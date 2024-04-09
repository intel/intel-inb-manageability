"""
Modification of Cloud Client class that works for INBS.
INBS is different because it is using gRPC instead of MQTT.
"""

from typing import Callable, Optional
from datetime import datetime
from .cloud_client import CloudClient


class InbsCloudClient(CloudClient):

    def __init__(self) -> None:
        """Constructor for InbsCloudClient
        """

        # FIXME implement
        pass

    def get_client_id(self) -> Optional[str]:
        """A readonly property

        @return: Client ID
        """

        # FIXME return actual client ID
        pass

    def publish_telemetry(self, key: str, value: str, time: datetime) -> None:
        """Publishes telemetry to the cloud

        @param key: telemetry's key to publish
        @param value: data to publish to the telemetry
        @param time: timestamp for this telemetry publish
        @exception PublishError: If publish fails
        """
        
        # FIXME implement
        pass

    def publish_event(self, key: str, value: str) -> None:
        """Publishes an event to the cloud

        @param key: telemetry's key to publish
        @param value: event to publish
        @exception PublishError: If publish fails
        """
        
        # FIXME implement
        pass

    def publish_attribute(self, key: str, value: str) -> None:
        """Publishes a device attribute to the cloud

        @param key: attribute's key
        @param value: value to set for the attribute
        @exception PublishError: If publish fails
        """
        
        # FIXME implement
        pass

    def bind_callback(self, name: str, callback: Callable) -> None:
        """Bind a callback to be triggered by a method called on the cloud
        The callback has the signature: (**kwargs) -> (str)
            (**kwargs): Keys/types are documented per action function
            (str): The success status and an accompanying message

        @param name: name of the method to which to bind the callback
        @param callback: callback to trigger
        """

        # FIXME implement
        pass

    def connect(self) -> None:
        """Establish a connection to the cloud service"""
        
        # FIXME implement
        pass

    def disconnect(self) -> None:
        """Disconnect from the cloud service"""
        
        # FIXME implement
        pass
