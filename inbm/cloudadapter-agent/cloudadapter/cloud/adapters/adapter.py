"""
Abstract base class used by all cloud adapters

Copyright (C) 2017-2023 Intel Corporation
SPDX-License-Identifier: Apache-2.0
"""


import abc

from datetime import datetime
from typing import Callable
from ..client.cloud_client import CloudClient


class Adapter(metaclass=abc.ABCMeta):  # pragma: no cover
    def __init__(self, config: dict):
        self._client = self.configure(config)

    @abc.abstractmethod
    def configure(self, config: dict) -> CloudClient:
        """Configure the adapter with the given keyword arguments
        Specific parameters and value types are documented per adapter

        @param config: The keyword arguments to pass into the function
        @exception AdapterConfigureError: If adapter configuration fails
        """
        pass

    @abc.abstractmethod
    def bind_callback(self, name: str, callback: Callable) -> None:
        """Bind a callback to be triggered by a method called on the cloud
        The callback has the signature: (**kwargs) -> (str)
            (**kwargs): Keys/types are documented per action function
            (str): The success status and an accompanying message

        @param name:     (str) The name of the method to bind the callback to
        @param callback: (Callable) The callback to trigger
        """
        pass

    def publish_event(self, message: str) -> None:
        """Publishes an event to the cloud

        @param message: (str) The event's message to send
        @exception PublishError: If publish fails
        """
        self._client.publish_event("event", message)

    def publish_attribute(self, attribute: str, value: str) -> None:
        """Publishes a device attribute to the cloud

        @param attribute: (str) The attribute's key
        @param value:     (str) The value to set for the attribute
        @exception PublishError: If publish fails
        """
        self._client.publish_attribute(attribute, value)

    def publish_telemetry(self, key: str, value: str, timestamp: datetime) -> None:
        """Publishes telemetry to the cloud

        @param key: telemetry's key to publish
        @param value: data to publish to the telemetry
        @param timestamp: timestamp for this telemetry publish
        @exception PublishError: If publish fails
        """
        self._client.publish_telemetry(key, value, timestamp)

    def connect(self) -> None:
        """Establish a connection to the cloud service

        @exception ConnectError: If connect fails
        """
        self._client.connect()

    def disconnect(self) -> None:
        """Disconnect from the cloud service

        @exception DisconnectError: If disconnect fails
        """
        self._client.disconnect()
