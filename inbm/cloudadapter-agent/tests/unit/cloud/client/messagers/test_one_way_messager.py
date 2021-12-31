"""
Unit tests for the OneWayMessenger


"""


from cloudadapter.cloud.client.messengers.one_way_messenger import OneWayMessenger
from cloudadapter.cloud.client.connections._connection import Connection
from cloudadapter.cloud.client.utilities import Formatter
from cloudadapter.exceptions import PublishError

import unittest
import mock


class TestOneWayMessenger(unittest.TestCase):

    def setUp(self):
        self.mock_connection = mock.create_autospec(Connection)
        self.mock_topic = mock.create_autospec(Formatter)
        self.mock_payload = mock.create_autospec(Formatter)
        self.one_way_messenger = OneWayMessenger(
            self.mock_topic,
            self.mock_payload,
            self.mock_connection)

    def test_publish_suceeds(self):
        self.mock_topic.format.return_value = "topic"
        self.mock_payload.format.return_value = "payload"

        self.one_way_messenger.publish("key", "value")

        assert self.mock_topic.format.call_count == 1
        assert self.mock_payload.format.call_count == 1
        assert self.mock_connection.publish.call_count == 1

        args, _ = self.mock_connection.publish.call_args
        assert args == ("topic", "payload")

    def test_publish_with_connection_error_fails(self):
        self.mock_connection.publish.side_effect = PublishError("Error!")
        failed = False
        try:
            self.one_way_messenger.publish("key", "value")
        except PublishError:
            failed = True
        assert failed
