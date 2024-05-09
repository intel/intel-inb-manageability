"""
Modification of Cloud Client class that works for INBS.
INBS is different because it is using gRPC instead of MQTT.
"""

from collections.abc import Generator
import queue
import random
import threading
import time
from typing import Callable, Optional, Any
from datetime import datetime
import xml.etree.ElementTree as ET  # only using this to generate XML, not parse it

from cloudadapter.cloud.client.inbs_xml_conversion import convert_update_scheduled_tasks_request_to_xml
from cloudadapter.exceptions import AuthenticationError
from cloudadapter.constants import METHOD
from ..adapters.proto import inbs_sb_pb2_grpc, inbs_sb_pb2
import logging

import grpc
from .cloud_client import CloudClient

logger = logging.getLogger(__name__)


class InbsCloudClient(CloudClient):
    def __init__(self,
                 hostname: str,
                 port: str,
                 node_id: str,
                 tls_enabled: bool,
                 tls_cert: bytes | None,
                 token: str | None):
        """Constructor for InbsCloudClient

        @param hostname: The hostname of the gRPC server
        @param port: The port number of the gRPC server
        @param node_id: The ID of the client node
        @param tls_enabled: Boolean to enable TLS
        @param tls_cert: (optional, only if tls_enabled) TLS cert contents
        @param token: (optional, only if tls_enabled) The authentication token
        """
        self._grpc_hostname = hostname
        self._grpc_port = port
        self._client_id = node_id
        self._token = token
        self._tls_enabled = tls_enabled
        self._tls_cert = tls_cert

        self._callbacks: dict[str, Callable] = {}

        self._metadata: list[tuple[str, str]] = [("node-id", node_id)]
        if tls_enabled:
            if token is None:
                raise AuthenticationError("Token is required when TLS is enabled.")
            else:
                self._metadata.append(("token", token))
            if tls_cert is None:
                raise AuthenticationError("TLS certificate path is required when TLS is enabled.")

        self._stop_event = threading.Event()

    def get_client_id(self) -> Optional[str]:
        """A readonly property

        @return: Client ID
        """

        return self._client_id

    def publish_telemetry(self, key: str, value: str, time: datetime) -> None:
        """Publishes telemetry to the cloud

        @param key: telemetry's key to publish
        @param value: data to publish to the telemetry
        @param time: timestamp for this telemetry publish
        @exception PublishError: If publish fails
        """

        pass  # INBS is not yet ready to receive telemetry

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

        self._callbacks[name] = callback

    def _handle_update_scheduled_tasks_request(self,
                                     request: inbs_sb_pb2.UpdateScheduledTasksRequest,
                                     request_id: str
                                     ) -> inbs_sb_pb2.UpdateScheduledTasksResponse:        
        request_data_xml: str = ET.tostring(convert_update_scheduled_tasks_request_to_xml(request, request_id),
                                            encoding='unicode')
        # discard result 'Manifest Update Triggered'; not needed for reply
        self._callbacks[METHOD.MANIFEST](request_data_xml)
        # TODO: do we need a response from dispatcher? cloudadapter is not currently set up to do this; it just sends blindly

        return inbs_sb_pb2.UpdateScheduledTasksResponse()

    def _handle_inbm_command(self,
                             request_queue: queue.Queue[inbs_sb_pb2.HandleINBMCommandRequest | None]
                             ) -> Generator[inbs_sb_pb2.HandleINBMCommandResponse, None, None]:
        """Generator function to respond to INBMRequests with INBMResponses

        @param request_queue: Queue with HandleINBMCommandRequests that will be supplied from another thread

        When a HandleINBMCommandResponse is ready, yield it. Quit when gRPC error is seen or signaled to stop on self._stop_event."""
        while not self._stop_event.is_set():
            try:
                item = request_queue.get()
                if item is None:
                    break

                request_id = item.request_id
                logger.debug(f"Processing gRPC request: request_id {request_id}")

                request_data_type = item.WhichOneof('request')
                if request_data_type:
                    if request_data_type == 'ping_request':
                        yield inbs_sb_pb2.HandleINBMCommandResponse(request_id=request_id,
                                                                    ping_response=inbs_sb_pb2.PingResponse())
                    elif request_data_type == 'update_scheduled_tasks_request':
                        yield inbs_sb_pb2.HandleINBMCommandResponse(request_id=request_id,
                                                                    update_scheduled_tasks_response=
                                                                    self._handle_update_scheduled_tasks_request(
                                                                        request_id=request_id,
                                                                        request=item.update_scheduled_tasks_request))
                    else:
                        # Log an error if the payload is not recognized
                        logger.error(
                            f"Received unexpected payload type: {request_data_type} for request_id {request_id}")
                        break
                else:
                    logger.error(f"No payload found for request_id {request_id}")

            except queue.Empty:
                continue  # No available item in the queue, continue to the next iteration
            except grpc.RpcError as e:
                logger.error(f"gRPC error in _handle_inbm_command: {e}")
                break

    def _do_socket_connect(self):
        """Handle the socket/TLS/HTTP connection to the gRPC server."""
        if self._tls_enabled:
            # Create a secure channel with SSL credentials
            logger.debug("Connecting to INBS cloud with TLS enabled...")
            credentials = grpc.ssl_channel_credentials(root_certificates=self._tls_cert)
            self.channel = grpc.secure_channel(
                f'{self._grpc_hostname}:{self._grpc_port}', credentials)
        else:
            logger.debug("Connecting to INBS cloud with TLS disabled...")
            # Create an insecure channel
            self.channel = grpc.insecure_channel(f'{self._grpc_hostname}:{self._grpc_port}')

        self.stub = inbs_sb_pb2_grpc.INBSSBServiceStub(self.channel)
        logger.info(
            f"Successfully connected to INBS service at {self._grpc_hostname}:{self._grpc_port}")

    def connect(self):
        # Start the background thread
        self.background_thread = threading.Thread(target=self._run)
        self.background_thread.start()

    def _run(self):  # pragma: no cover  # multithreaded operation not unit testable
        """INBS cloud loop. Intended to be used inside a background thread."""
        backoff = 1.0  # Initial backoff delay in seconds
        max_backoff = 32.0  # Maximum backoff delay in seconds

        while not self._stop_event.is_set():
            try:
                self._do_socket_connect()
                request_queue: queue.Queue[inbs_sb_pb2.HandleINBMCommandRequest |
                                           None] = queue.Queue()
                stream = self.stub.HandleINBMCommand(self._handle_inbm_command(
                    request_queue), metadata=self._metadata)
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
                        f"gRPC stream closed with error: {e}. Reconnecting in {backoff} seconds...")
                    time.sleep(backoff)
                    # Increase the backoff for the next attempt, up to a maximum.
                    backoff = min(backoff * 2.0 + random.uniform(0, 1), max_backoff)
                else:
                    logger.debug("gRPC Stream closed by stop event.")
                    break

        logger.debug("Exiting gRPC _run thread")

    def disconnect(self):  # pragma: no cover  # multithreaded operation not unit testable
        """Signal all background INBS threads to stop. Wait for them to terminate."""

        self._stop_event.set()
        if self.background_thread is not None:
            self.background_thread.join()
        logger.debug("Disconnected from the INBS gRPC server.")
