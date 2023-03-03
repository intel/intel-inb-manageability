"""
Messenger responsible for publishing events.
Publishes are one way, purely based on the MQTT protocol.

Copyright (C) 2017-2023 Intel Corporation
SPDX-License-Identifier: Apache-2.0
"""


from ._messenger import Messenger
from .. utilities import Formatter
from ..connections.mqtt_connection import MQTTConnection
from datetime import datetime
from typing import Optional
from threading import Thread, Lock

class OneWayMessenger(Messenger):

    def __init__(self, topic_formatter: Formatter, payload_formatter: Formatter, connection: MQTTConnection) -> None:
        """Construct a Messenger that performs message formatting

        @param topic_formatter:   (Formatter) Formatter for publish topic
        @param payload_formatter: (Formatter) Formatter for messages
        @param connection:       (Connection) Connection to use for publishing
        """
        self._topic_formatter = topic_formatter
        self._payload_formatter = payload_formatter
        self._connection = connection
        self.lock = Lock()

    def publish(self, key: str, value: str, time: Optional[datetime] = None) -> None:
        self.lock.acquire()
        topic = self._topic_formatter.format(request_id=self._connection.request_id)
        payload = self._payload_formatter.format(time, key=key, value=value)
        self._connection.publish(topic, payload)
        self.lock.release()
