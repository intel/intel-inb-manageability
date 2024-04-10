"""
Modification of Cloud Client class that works for INBS.
INBS is different because it is using gRPC instead of MQTT.
"""

import queue
import threading
import time
from typing import Callable, Optional, Any
from datetime import datetime
from ..adapters.proto import inbs_sb_pb2_grpc, inbs_sb_pb2
import logging

import grpc
from .cloud_client import CloudClient

logger = logging.getLogger(__name__)

class InbsCloudClient(CloudClient):

    def __init__(self, grpc_hostname: str, grpc_port: str) -> None:
        """Constructor for InbsCloudClient
        """
        
        self._grpc_hostname = grpc_hostname
        self._grpc_port = grpc_port
        self._stop_event = threading.Event()

    def get_client_id(self) -> Optional[str]:
        """A readonly property

        @return: Client ID
        """

        raise NotImplementedError("get_client_id not yet implemented")

    def publish_telemetry(self, key: str, value: str, time: datetime) -> None:
        """Publishes telemetry to the cloud

        @param key: telemetry's key to publish
        @param value: data to publish to the telemetry
        @param time: timestamp for this telemetry publish
        @exception PublishError: If publish fails
        """
        
        raise NotImplementedError("publish_telemetry not yet implemented")

    def publish_event(self, key: str, value: str) -> None:
        """Publishes an event to the cloud

        @param key: telemetry's key to publish
        @param value: event to publish
        @exception PublishError: If publish fails
        """
        
        raise NotImplementedError("publish_event not yet implemented")

    def publish_attribute(self, key: str, value: str) -> None:
        """Publishes a device attribute to the cloud

        @param key: attribute's key
        @param value: value to set for the attribute
        @exception PublishError: If publish fails
        """
        
        raise NotImplementedError("publish_attribute not yet implemented")

    def bind_callback(self, name: str, callback: Callable) -> None:
        """Bind a callback to be triggered by a method called on the cloud
        The callback has the signature: (**kwargs) -> (str)
            (**kwargs): Keys/types are documented per action function
            (str): The success status and an accompanying message

        @param name: name of the method to which to bind the callback
        @param callback: callback to trigger
        """

        # for now ignore all callbacks; only Ping is supported
        pass

    def _ping_pong(self, request_queue: queue.Queue):
        """Generator function to respond to PingRequests with PingResponses

        @param request_queue: Queue with PingRequests that will be supplied from another thread

        When a PingResponse is ready, yield it. Quit when gRPC error is seen or signaled to stop on self._stop_event."""
        while not self._stop_event.is_set():
            try:
                item = request_queue.get()
                if item is None:
                    break
                
                logger.debug("Responding to ping over gRPC")
                yield inbs_sb_pb2.PingResponse()
            except queue.Empty:
                continue
            except grpc.RpcError as e:
                logger.error(f"gRPC error in _ping_pong: {e}")
                break

    def connect(self):
        """Connect to cloud."""
        self.channel = grpc.insecure_channel(f'{self._grpc_hostname}:{self._grpc_port}')
        self.stub = inbs_sb_pb2_grpc.INBSServiceStub(self.channel)

        # Start the background thread
        self.background_thread = threading.Thread(target=self._run)
        self.background_thread.start()

    def _run(self):
        """INBS cloud loop. Intended to be used inside a background thread."""       
        backoff = 1  # Initial backoff delay in seconds        
        max_backoff = 32  # Maximum backoff delay in seconds

        while not self._stop_event.is_set():
            try:                  
                request_queue: queue.Queue = queue.Queue()              
                self.channel = grpc.insecure_channel(f'{self._grpc_hostname}:{self._grpc_port}')
                self.stub = inbs_sb_pb2_grpc.INBSServiceStub(self.channel)
                stream = self.stub.Ping(self._ping_pong(request_queue))
                for ping in stream:
                    if self._stop_event.is_set():
                        break
                    if ping is None:
                        break
                    logger.debug(f"Received ping over gRPC")
                    request_queue.put(ping)
                    # If the code reaches this point without an exception,
                    # reset the backoff delay.
                    backoff = 1
            except grpc.RpcError as e:
                if not self._stop_event.is_set():
                    logger.error(f"gRPC stream closed with error: {e}. Reconnecting in {backoff} seconds...")
                    time.sleep(backoff)
                    # Increase the backoff for the next attempt, up to a maximum.
                    backoff = min(backoff * 2, max_backoff)
                else:
                    logger.debug("gRPC Stream closed by stop event.")
                    break
            except Exception as e:
                logger.error(f"Unexpected error: {e}. Reconnecting in {backoff} seconds...")
                time.sleep(backoff)
                # Increase the backoff for the next attempt, up to a maximum.
                backoff = min(backoff * 2, max_backoff)

        logger.debug("Exiting gRPC _run thread")

    def disconnect(self):
        """Signal all background INBS threads to stop. Wait for them to terminate."""

        self._stop_event.set()
        if self.background_thread is not None:
            self.background_thread.join()
        logger.debug("Disconnected from the INBS gRPC server.")