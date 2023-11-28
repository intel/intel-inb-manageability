"""
Unit tests for the EchoHandler


"""


from cloudadapter.cloud.client.handlers.echo_handler import EchoHandler
from cloudadapter.cloud.client.connections._connection import Connection
from cloudadapter.cloud.client.utilities import Formatter

import unittest
import mock


class TestEchoHandler(unittest.TestCase):

    def setUp(self) -> None:
        self.mock_connection = mock.create_autospec(Connection)
        self.mock_topic = mock.create_autospec(Formatter)
        self.mock_payload = mock.create_autospec(Formatter)

        self.echo_handler = EchoHandler(
            self.mock_topic,
            self.mock_payload,
            "subscribe_topic",
            self.mock_connection)

    def test_echo_succeeds(self) -> None:
        self.mock_topic.format.return_value = "topic"
        self.mock_payload.format.return_value = "payload"

        self.echo_handler._on_message("topic", "payload")
        assert self.mock_connection.publish.call_count == 1
        args, _ = self.mock_connection.publish.call_args
        assert args == ("topic", "payload")

    def test_bind_fails(self) -> None:
        failed = False
        try:
            self.echo_handler.bind("name", lambda: None)
        except NotImplementedError:
            failed = True
        assert failed
