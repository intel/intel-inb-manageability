"""
Unit tests for the RecieveRespondHandler


"""


from cloudadapter.cloud.client.handlers.recieve_respond_handler import RecieveRespondHandler
from cloudadapter.cloud.client.connections._connection import Connection
from cloudadapter.cloud.client.utilities import Formatter, MethodParser, MethodParsed

import unittest
import mock


class TestRecieveRespondHandler(unittest.TestCase):

    def setUp(self):
        self.mock_connection = mock.create_autospec(Connection)
        self.mock_topic = mock.create_autospec(Formatter)
        self.mock_payload = mock.create_autospec(Formatter)
        self.mock_parser = mock.create_autospec(MethodParser)

        self.recieve_respond_handler = RecieveRespondHandler(
            self.mock_topic,
            self.mock_payload,
            "subscribe_topic",
            self.mock_parser,
            self.mock_connection)

    def test_bind_succeeds(self):
        self.mock_topic.format.return_value = "topic"
        self.mock_payload.format.return_value = "payload"
        self.mock_parser.parse.return_value = [MethodParsed(method="method")]
        mock_callback = mock.Mock()

        self.recieve_respond_handler.bind("method", mock_callback)

        self.recieve_respond_handler._on_method("topic", "payload")
        assert mock_callback.call_count == 1

    def test_on_method_exits_on_no_methods_succeeds(self):
        self.mock_topic.format.return_value = "topic"
        self.mock_payload.format.return_value = "payload"
        self.mock_parser.parse.return_value = []

        self.recieve_respond_handler._on_method("topic", "payload")
        assert self.mock_connection.publish.call_count == 0

    def test_on_method_exits_on_invalid_method_succeeds(self):
        self.mock_topic.format.return_value = "topic"
        self.mock_payload.format.return_value = "payload"
        self.mock_parser.parse.return_value = [MethodParsed(method="")]

        self.recieve_respond_handler._on_method("topic", "payload")
        assert self.mock_connection.publish.call_count == 0
