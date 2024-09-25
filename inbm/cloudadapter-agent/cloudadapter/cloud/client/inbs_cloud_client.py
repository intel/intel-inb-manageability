"""
Modification of Cloud Client class that works for INBS.
INBS is different because it is using gRPC instead of MQTT.
"""

from collections.abc import Generator
import json
import queue
import random
import threading
from google.protobuf.timestamp_pb2 import Timestamp
from typing import Callable, Optional
from datetime import datetime

from cloudadapter.cloud.adapters.inbs.operation import (
    convert_updated_scheduled_operations_to_dispatcher_xml,
)
from cloudadapter.constants import METHOD, DEAD
from cloudadapter.exceptions import AuthenticationError
from cloudadapter.pb.inbs.v1 import inbs_sb_pb2_grpc, inbs_sb_pb2
from cloudadapter.pb.common.v1 import common_pb2
import logging

import grpc
from .cloud_client import CloudClient

logger = logging.getLogger(__name__)


class InbsCloudClient(CloudClient):
    def __init__(
        self,
        hostname: str,
        port: str,
        node_id: str,
        tls_enabled: bool,
        tls_cert: bytes | None,
        token: str | None,
    ):
        """Constructor for InbsCloudClient

        @param hostname: The hostname of the gRPC server
        @param port: The port number of the gRPC server
        @param node_id: The ID of the client node
        @param tls_enabled: Boolean to enable TLS
        @param tls_cert: (optional, only if tls_enabled) TLS cert contents
        @param token: (optional, only if tls_enabled) The authentication token
        """
        self._callbacks: dict[
            str, Callable
        ] = {}  # Used to send messages to Dispatcher Agent

        self._grpc_hostname = hostname
        self._grpc_port = port
        self._client_id = node_id
        self._token = token
        self._tls_enabled = tls_enabled
        self._tls_cert = tls_cert
        self._dispatcher_state = DEAD
        self._disp_state_lock = threading.Lock()

        self._metadata: list[tuple[str, str]] = [("node-id", node_id)]
        if tls_enabled:
            if token is None:
                raise AuthenticationError("Token is required when TLS is enabled.")
            else:
                self._metadata.append(("token", token))
            if tls_cert is None:
                raise AuthenticationError(
                    "TLS certificate path is required when TLS is enabled."
                )
        self._stop_event = threading.Event()

        self._stub = self._make_grpc_channel()  # assumption: this doesn't actually connect until first gRPC command

    def get_client_id(self) -> Optional[str]:
        """A readonly property

        @return: Client ID
        """

        return self._client_id

    def set_dispatcher_state(self, state) -> None:
        """Set the dispatcher state: running or dead

        @param state: State of dispatcher agent to be set
        """
        try:
            self._disp_state_lock.acquire()
            self._dispatcher_state = state
        finally:
            self._disp_state_lock.release()

    def get_dispatcher_state(self) -> str:
        """Get the dispatcher state

        @return: State of dispatcher agent
        """
        try:
            self._disp_state_lock.acquire()
            return self._dispatcher_state
        finally:
            self._disp_state_lock.release()

    def publish_telemetry(self, key: str, value: str, time: datetime) -> None:
        """Publishes telemetry to the cloud

        @param key: telemetry's key to publish
        @param value: data to publish to the telemetry
        @param time: timestamp for this telemetry publish
        @exception PublishError: If publish fails
        """

        pass  # INBS is not yet ready to receive telemetry

    def publish_update(self, key: str, value: str) -> None:
        """Publishes an update to the cloud

        @param message: node update message to publish
        @exception PublishError: If publish fails
        """
        # Turn the message into a dict
        logger.debug(f"Received node update: key={key}, value={value}")
        try:
            message_dict = json.loads(value)
        except json.JSONDecodeError as e:
            logger.error(f"Cannot convert formatted message to dict: {value}. Error: {e}")
            return
        
        timestamp = Timestamp()
        timestamp.GetCurrentTime()

        request = inbs_sb_pb2.SendNodeUpdateRequest(
            request_id=message_dict.get("request_id", ""),
            job_update=common_pb2.Job(
                job_id=message_dict.get("job_id", ""),
                node_id=self._client_id,
                status_code=message_dict.get("status", ""),
                result_msgs=message_dict.get("message", ""),
                actual_end_time=timestamp,
            )
        )
        logger.debug(f"Sending node update to INBS: request={request}")
            
        try:
            response = self._stub.SendNodeUpdate(request)
            logger.info(f"Received response from gRPC server: {response}")
        except grpc.RpcError as e:
            logger.error(f"Failed to send node update via gRPC: {e}")
    
    def publish_event(self, key: str, value: str) -> None:
        """Publishes an event to the cloud

        @param key: telemetry's key to publish
        @param value: event to publish
        @exception PublishError: If publish fails
        """

        pass  # INBS is not yet ready to receive events

    def publish_attribute(self, key: str, value: str) -> None:
        """Publishes a device attribute to the cloud

        @param key: attribute's key
        @param value: value to set for the attribute
        @exception PublishError: If publish fails
        """

        pass  # INBS is not yet ready to receive attributes

    def bind_callback(self, name: str, callback: Callable) -> None:
        """Bind a callback to be triggered by a method called on the cloud
        The callback has the signature: (**kwargs) -> (str)
            (**kwargs): Keys/types are documented per action function
            (str): The success status and an accompanying message

        @param name: name of the method to which to bind the callback
        @param callback: callback to trigger
        """

        # for now ignore all callbacks; only Ping is supported
        self._callbacks[name] = callback
    
    def _handle_inbm_command_request(
        self, request_queue: queue.Queue[inbs_sb_pb2.HandleINBMCommandRequest | None]
    ) -> Generator[inbs_sb_pb2.HandleINBMCommandResponse, None, None]:
        """Generator function to respond to HandleINBMCommandRequests with HandleINBMCommandResponses

        @param request_queue: Queue with HandleINBMCommandRequests that will be supplied from another thread

        When a HandleINBMCommandResponse is ready, yield it. Quit when gRPC error is seen or signaled to stop on self._stop_event.
        """
        while not self._stop_event.is_set():
            try:
                item = request_queue.get()
                if item is None:
                    break

                request_id = item.request_id
                logger.debug(f"Processing gRPC request: request_id {request_id}")
                command_type = item.command.WhichOneof("inbm_command")

                if self.get_dispatcher_state() == DEAD and command_type != "ping":
                    logger.error(
                        f"Dispatcher not in running state. Unable to process request - {request_id}"
                    )
                    yield inbs_sb_pb2.HandleINBMCommandResponse(
                        request_id=request_id,
                        error=common_pb2.Error(
                            message="INBM Cloudadapter: Unable to process request. Please try again"
                        ),
                    )
                    continue


                if command_type:
                    if command_type == "update_scheduled_operations":
                        # Convert operations to Dispatcher's ScheduleRequest
                        try:
                            dispatcher_xml = (
                                convert_updated_scheduled_operations_to_dispatcher_xml(
                                    request_id, item.command.update_scheduled_operations
                                )
                            )
                        except ValueError as ve:
                            logger.error(
                                f"Error converting operations to Dispatcher XML: {ve}"
                            )
                            yield inbs_sb_pb2.HandleINBMCommandResponse(
                                request_id=request_id,
                                error=common_pb2.Error(message=f"cloudadapter: {ve}"),
                            )
                            continue

                        try:
                            # Send the converted operations to Dispatcher; wait up to 3 seconds
                            # for reply
                            error = self._callbacks[METHOD.SCHEDULE](dispatcher_xml, request_id, 3)

                            # Expect the callback to return an error message if there was an error
                            # or None or "" if there was no error
                            if error is None or error == "":
                                pb_error = None
                            else:
                                pb_error = common_pb2.Error(message=error)

                            yield inbs_sb_pb2.HandleINBMCommandResponse(
                                request_id=request_id,
                                error=pb_error
                            )
                        except TimeoutError:
                            logger.error(
                                f"Timed out waiting for response from Dispatcher for request_id {request_id}"
                            )
                            yield inbs_sb_pb2.HandleINBMCommandResponse(
                                request_id=request_id,
                                error=common_pb2.Error(
                                    message="INBM Cloudadapter: timed out waiting for INBM Dispatcher response"
                                ),
                            )
                    elif command_type == "ping":
                        logger.debug(
                            f"Received ping command for request_id {request_id}"
                        )
                        yield inbs_sb_pb2.HandleINBMCommandResponse(
                            request_id=request_id
                        )
                    else:
                        logger.error(
                            f"Received unknown command {command_type} for request_id {request_id}"
                        )
                        yield inbs_sb_pb2.HandleINBMCommandResponse(
                            request_id=request_id,
                            error=common_pb2.Error(
                                message=f"cloudadapter: unknown command {command_type}"
                            ),
                        )
                else:
                    logger.error(
                        f"Received unknown command for request_id {request_id}"
                    )
                    yield inbs_sb_pb2.HandleINBMCommandResponse(
                        request_id=request_id,
                        error=common_pb2.Error(message="cloudadapter: unknown command"),
                    )

            except queue.Empty:
                continue  # No available item in the queue, continue to the next iteration
            except grpc.RpcError as e:
                logger.error(f"gRPC error in _handle_inbm_command_request: {e}")
                break
        logger.debug("Exiting _handle_inbm_command_request")

    def _make_grpc_channel(self) -> grpc.Channel:
        """Handle the socket/TLS/HTTP connection to the gRPC server.
        Assumption: should not connect until first gRPC command."""
        if self._tls_enabled:
            # Create a secure channel with SSL credentials
            logger.debug("Setting up connection to INBS cloud with TLS enabled")
            credentials = grpc.ssl_channel_credentials(root_certificates=self._tls_cert)
            self.channel = grpc.secure_channel(
                f"{self._grpc_hostname}:{self._grpc_port}", credentials
            )
        else:
            logger.debug("Setting up connection to INBS cloud with TLS disabled")
            # Create an insecure channel
            self.channel = grpc.insecure_channel(
                f"{self._grpc_hostname}:{self._grpc_port}"
            )
        
        logger.info(
            f"Connection set up for {self._grpc_hostname}:{self._grpc_port}; will attempt TCP connection on first request."
        )
        return inbs_sb_pb2_grpc.INBSSBServiceStub(self.channel)

    def connect(self):
        # Start the background thread
        self.background_thread = threading.Thread(target=self._run)
        self.background_thread.start()

    def _run(self):  # pragma: no cover  # multithreaded operation not unit testable
        """INBS cloud loop. Intended to be used inside a background thread."""
        backoff = 0.1  # Initial fixed backoff delay in seconds
        max_backoff = 4.0  # Maximum backoff delay in seconds

        while not self._stop_event.is_set():
            logger.debug("InbsCloudClient _run loop")
            try:
                request_queue: queue.Queue[
                    inbs_sb_pb2.HandleINBMCommandRequest | None
                ] = queue.Queue()
                stream = self._stub.HandleINBMCommand(
                    self._handle_inbm_command_request(request_queue),
                    metadata=self._metadata,
                )
                for command in stream:
                    if self._stop_event.is_set():
                        break
                    if command is None:
                        break
                    logger.debug(f"Received command over gRPC")
                    request_queue.put(command)
                    # If the code reaches this point without an exception,
                    # reset the backoff delay.
                    backoff = 1.0
            except grpc.RpcError as e:
                if not self._stop_event.is_set():
                    logger.error(
                        f"gRPC stream closed with error: {e}. Reconnecting in {backoff} seconds..."
                    )
                    self._stop_event.wait(backoff)
                    # Increase the backoff for the next attempt, up to a maximum.
                    backoff = min(backoff * 2.0 + random.uniform(0, 0.1), max_backoff)
                else:
                    logger.debug("gRPC Stream closed by stop event.")
                    break

        logger.debug("Exiting gRPC _run thread")

    def disconnect(
        self,
    ):  # pragma: no cover  # multithreaded operation not unit testable
        """Signal all background INBS threads to stop. Wait for them to terminate."""

        logger.debug("InbsCloudClient.disconnect: signaling background thread to stop")
        self._stop_event.set()
        if self.background_thread is not None:
            logger.debug("InbsCloudClient.disconnect: Waiting for background thread to terminate...")
            self.background_thread.join()
        logger.debug("InbsCloudClient.disconnect: Disconnected from the INBS gRPC server.")
