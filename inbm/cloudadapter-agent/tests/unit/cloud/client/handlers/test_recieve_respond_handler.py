"""
Unit tests for the ReceiveResponseHandler


"""


from cloudadapter.cloud.client.handlers.receive_response_handler import ReceiveResponseHandler
from cloudadapter.cloud.client.connections._connection import Connection
from cloudadapter.cloud.client.utilities import Formatter, MethodParser, MethodParsed
from cloudadapter.constants import METHOD

import unittest
import mock
import logging
import sys

logging.basicConfig(level=logging.DEBUG) # set log level for root logger

logger = logging.getLogger()
logger.level = logging.DEBUG
stream_handler = logging.StreamHandler(sys.stdout)
logger.addHandler(stream_handler)

class TestReceiveResponseHandler(unittest.TestCase):

    def setUp(self):
        self.mock_connection = mock.create_autospec(Connection)
        self.mock_topic = mock.create_autospec(Formatter)
        self.mock_payload = mock.create_autospec(Formatter)
        self.mock_parser = mock.create_autospec(MethodParser)

        self.receive_respond_handler = ReceiveResponseHandler(
            self.mock_topic,
            self.mock_payload,
            "subscribe_topic",
            self.mock_parser,
            self.mock_connection)

    def test_bind_succeeds(self):
        self.mock_topic.format.return_value = "topic"
        self.mock_payload.format.return_value = b"payload"
        self.mock_parser.parse.return_value = [MethodParsed(method="method")]
        mock_callback = mock.Mock()

        self.receive_respond_handler.bind("method", mock_callback)

        self.receive_respond_handler._on_method("topic", b"payload")
        assert mock_callback.call_count == 1

    def test_bind_succeeds_no_parser(self):
        receive_respond_handler = ReceiveResponseHandler(
            self.mock_topic,
            self.mock_payload,
            "subscribe_topic",
            None,
            self.mock_connection)
        
        self.mock_topic.format.return_value = "topic"
        self.mock_payload.format.return_value = b"payload"
        mock_callback = mock.Mock()

        receive_respond_handler.bind(METHOD.RAW, mock_callback)

        receive_respond_handler._on_method("topic", b"payload")        
        
        self.assertEqual(mock_callback.call_count, 1)

    def test_on_method_exits_on_no_methods_succeeds(self):
        self.mock_topic.format.return_value = "topic"
        self.mock_payload.format.return_value = b"payload"
        self.mock_parser.parse.return_value = []

        self.receive_respond_handler._on_method("topic", b"payload")
        assert self.mock_connection.publish.call_count == 0

    def test_on_method_exits_on_invalid_method_succeeds(self):
        self.mock_topic.format.return_value = "topic"
        self.mock_payload.format.return_value = b"payload"
        self.mock_parser.parse.return_value = [MethodParsed(method="")]

        self.receive_respond_handler._on_method("topic", b"payload")
        assert self.mock_connection.publish.call_count == 0
