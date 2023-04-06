"""
Handler that echoes a message when a message is received.


"""


from typing import Callable, Optional, Dict
from ._handler import Handler
from ..connections.mqtt_connection import MQTTConnection
from ..utilities import Formatter
from ....utilities import make_threaded

import logging
logger = logging.getLogger(__name__)


class EchoHandler(Handler):

    def __init__(self, topic_formatter: Formatter, payload_formatter: Formatter, subscribe_topic: Optional[str],
                 connection: MQTTConnection) -> None:
        """Construct a generic handler

        @param topic_formatter:   (Formatter) Formatter for response publish topic
        @param payload_formatter: (Formatter) Formatter for response payload
        @param subscribe_topic:   (str) Topic to subscribe for incoming messages
        @param connection: (Connection) Connection to use
        """
        self._topic_formatter = topic_formatter
        self._payload_formatter = payload_formatter

        self._connection = connection
        self._connection.subscribe(subscribe_topic, make_threaded(self._on_message))
        self._methods: Dict = {}

    def bind(self, key: str, callback: Callable):
        """This is currently unused, but would be useful to allow side effects on messages
        @exception NotImplementedError: If called
        """
        self._methods[key] = callback

    def _on_message(self, topic: str, payload: str):
        """Callback for subscribed messages

        @param topic:   (str) Specific topic
        @param payload: (str) Raw UTF-8 payload
        """

        # Log the message
        logger.info("Received message on %s: %s", topic, payload)

        # Acknowledge the command
        rid = self._connection.request_id
        payload = self._payload_formatter.format(request_id=rid)
        topic = self._topic_formatter.format(request_id=rid)
        self._connection.publish(topic, payload)
