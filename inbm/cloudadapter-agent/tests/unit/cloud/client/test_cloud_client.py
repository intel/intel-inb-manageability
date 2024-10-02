"""
Unit tests for the CloudClient


"""


from cloudadapter.cloud.client.connections._connection import Connection
from cloudadapter.cloud.client.messengers._messenger import Messenger
from cloudadapter.cloud.client.handlers._handler import Handler
from cloudadapter.cloud.client.cloud_client import CloudClient
from cloudadapter.constants import RUNNING

import datetime

import unittest
import mock


class TestCloudClient(unittest.TestCase):

    def setUp(self) -> None:
        self.mock_connection = mock.create_autospec(Connection)
        self.mock_connection.set_dispatcher_state = mock.MagicMock()
        self.mock_telemetry = mock.create_autospec(Messenger)
        self.mock_attribute = mock.create_autospec(Messenger)
        self.mock_event = mock.create_autospec(Messenger)
        self.mock_update = mock.create_autospec(Messenger)
        self.mock_handler = mock.create_autospec(Handler)

        self.cloud_client = CloudClient(
            connection=self.mock_connection,
            telemetry=self.mock_telemetry,
            event=self.mock_event,
            update=self.mock_update,
            attribute=self.mock_attribute,
            handler=self.mock_handler
        )

    def test_publish_telemetry_succeeds(self) -> None:
        args = ("key", "value", datetime.datetime.utcnow())
        self.cloud_client.publish_telemetry(*args)
        assert self.mock_telemetry.publish.call_count == 1

    def test_publish_attribute_succeeds(self) -> None:
        args = ("key", "value")
        self.cloud_client.publish_attribute(*args)
        assert self.mock_attribute.publish.call_count == 1

    def test_publish_node_update_succeeds(self) -> None:
        args = ("key", "value")
        self.cloud_client.publish_node_update(*args)
        assert self.mock_update.publish.call_count == 1
        
    def test_publish_event_succeeds(self) -> None:
        args = ("key", "value")
        self.cloud_client.publish_event(*args)
        assert self.mock_event.publish.call_count == 1

    def test_bind_callback_succeeds(self) -> None:
        args = ("name", lambda **_: None)
        self.cloud_client.bind_callback(*args)
        assert self.mock_handler.bind.call_count == 1

    def test_connect_succeeds(self) -> None:
        self.cloud_client.connect()
        assert self.mock_connection.start.call_count == 1

    def test_disconnect_succeeds(self) -> None:
        self.cloud_client.disconnect()
        assert self.mock_connection.stop.call_count == 1

    def test_set_dispatcher_state_succeeds(self) -> None:
        self.cloud_client.set_dispatcher_state(RUNNING)
        assert self.mock_connection.set_dispatcher_state.call_count == 1