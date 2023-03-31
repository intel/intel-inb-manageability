"""
Receive/respond handler parses incoming topic/payload and sends
a formatted message as a response.


"""


from typing import Dict

from typing import Callable
from ._handler import Handler
from ..utilities import Formatter
from ..utilities import MethodParser
from ..connections.mqtt_connection import MQTTConnection
from ....utilities import make_threaded

import logging
logger = logging.getLogger(__name__)


class ReceiveResponseHandler(Handler):

    def __init__(self, topic_formatter: Formatter, payload_formatter: Formatter, subscribe_topic: str,
                 parser: MethodParser, connection: MQTTConnection) -> None:
        """Construct a generic handler

        @param topic_formatter:   (Formatter) Formatter for response publish topic
        @param payload_formatter: (Formatter) Formatter for response payload
        @param subscribe_topic:   (str) Topic to subscribe for incoming messages
        @param parser:   (MethodParser) Parser to use for incoming messages
        @param connection: (Connection) Connection to use
        """
        self._topic_formatter = topic_formatter
        self._payload_formatter = payload_formatter

        self._method_parser = parser

        self._connection = connection
        self._connection.subscribe(subscribe_topic, make_threaded(self._on_method))

        self._methods: Dict = {}

    def bind(self, name: str, callback: Callable):
        self._methods[name] = callback

    def _on_method(self, topic: str, payload: str) -> None:
        """Callback for subscribed cloud messages

        @param topic:   (str) Specific topic
        @param payload: (str) Raw UTF-8 payload
        """

        # Parse the message
        try:
            parsed = self._method_parser.parse(topic, payload)
        except ValueError as e:
            logger.error("Received malformed message: see debug log")
            logger.debug(f"message contents: {payload} error: {str(e)}")
            return

        if not parsed:
            logger.info("Received non-RPC message: see debug log")
            logger.debug(f"message contents: {payload}")
            return

        # Loop through all parsed methods
        for p in parsed:

            method, args, symbols = p.method, p.args, p.symbols
            logger.debug(f"method={method} args={args} symbols={symbols}")

            # Check if method is valid
            if not method:
                logger.info("Received non-RPC message on %s: %s", topic, payload)
                return

            # Supply request_id if not parsed
            if "request_id" not in symbols:
                symbols.update(request_id=self._connection.request_id)

            logger.info(
                "Received parsed method: '%s' Request ID: '%s'",
                method, symbols.get("request_id"))

            # Run the applicable bound callback
            response = f"\"Unknown method: '{method}'\""
            if method in self._methods:
                response = self._methods[method](**args)

            # Acknowledge the command
            topic = self._topic_formatter.format(**symbols)
            payload = self._payload_formatter.format(message=response, **symbols)
            self._connection.publish(topic, payload)
