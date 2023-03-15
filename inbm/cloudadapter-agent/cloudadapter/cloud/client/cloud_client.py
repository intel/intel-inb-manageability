"""
Cloud Client class that provides all cloud interactions


"""
from .connections.mqtt_connection import MQTTConnection
from .messengers.one_way_messenger import OneWayMessenger
from .handlers.recieve_respond_handler import ReceiveResponseHandler
from typing import Callable
from datetime import datetime


class CloudClient:

    def __init__(self, connection: MQTTConnection, telemetry: OneWayMessenger, event: OneWayMessenger,
                 attribute: OneWayMessenger, handler: ReceiveResponseHandler) -> None:
        """Constructor for CloudClient

        @param connection: Connection associated with this CloudClient
        @param telemetry: Messenger to send telemetry
        @param event: Messenger to send events
        @param attribute: Messenger to send attributes
        @param handler: Handler to deal with cloud method calls
        """
        self._connection = connection
        self._telemetry = telemetry
        self._event = event
        self._attribute = attribute
        self._handler = handler

    def publish_telemetry(self, key: str, value: str, time: datetime) -> None:
        """Publishes telemetry to the cloud

        @param key: telemetry's key to publish
        @param value: data to publish to the telemetry
        @param time: timestamp for this telemetry publish
        @exception PublishError: If publish fails
        """
        return self._telemetry.publish(key, value, time)

    def publish_event(self, key: str, value: str) -> None:
        """Publishes an event to the cloud

        @param key: telemetry's key to publish
        @param value: event to publish
        @exception PublishError: If publish fails
        """
        return self._event.publish(key, value)

    def publish_attribute(self, key: str, value: str) -> None:
        """Publishes a device attribute to the cloud

        @param key: attribute's key
        @param value: value to set for the attribute
        @exception PublishError: If publish fails
        """
        return self._attribute.publish(key, value)

    def bind_callback(self, name: str, callback: Callable) -> None:
        """Bind a callback to be triggered by a method called on the cloud
        The callback has the signature: (**kwargs) -> (str)
            (**kwargs): Keys/types are documented per action function
            (str): The success status and an accompanying message

        @param name: name of the method to bind the callback to
        @param callback: callback to trigger
        """
        return self._handler.bind(name, callback)

    def connect(self) -> None:
        """Establish a connection to the cloud service"""
        return self._connection.start()

    def disconnect(self) -> None:
        """Disconnect from the cloud service"""
        return self._connection.stop()
