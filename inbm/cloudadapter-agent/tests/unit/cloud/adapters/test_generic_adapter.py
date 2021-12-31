"""
Unit tests for the GenericAdapter class


"""


import unittest
import mock

from cloudadapter.exceptions import (PublishError,
                                     ConnectError,
                                     DisconnectError,
                                     AdapterConfigureError,
                                     ClientBuildError)
from cloudadapter.cloud.adapters.generic_adapter import GenericAdapter
import datetime


class TestGenericAdapter(unittest.TestCase):

    @mock.patch('cloudadapter.cloud.client.cloud_client.CloudClient', autospec=True)
    @mock.patch(
        'cloudadapter.cloud.adapters.generic_adapter.build_client_with_config', autospec=True)
    def setUp(self, mock_build_client_with_config, MockCloudClient):
        self.MockCloudClient = MockCloudClient
        self.mocked_client = self.MockCloudClient.return_value
        mock_build_client_with_config.return_value = self.mocked_client

        self.config = {
            "sample": "config"
        }
        self.generic_adapter = GenericAdapter(self.config)
        self.generic_adapter.configure(self.config)

    @mock.patch('cloudadapter.cloud.client.cloud_client.CloudClient', autospec=True)
    @mock.patch(
        'cloudadapter.cloud.adapters.generic_adapter.build_client_with_config', autospec=True)
    def test_configure_succeeds(self, mock_build_client_with_config, MockCloudClient):
        mock_build_client_with_config.return_value = self.mocked_client
        self.generic_adapter.configure(self.config)
        assert mock_build_client_with_config.call_count == 1

    @mock.patch('cloudadapter.cloud.client.cloud_client.CloudClient', autospec=True)
    @mock.patch(
        'cloudadapter.cloud.adapters.generic_adapter.build_client_with_config', autospec=True)
    def test_configure_with_build_fail_fails(self, mock_build_client_with_config, MockCloudClient):
        mock_build_client_with_config.return_value = self.mocked_client
        mock_build_client_with_config.side_effect = ClientBuildError("Error!")
        with self.assertRaises(AdapterConfigureError):
            self.generic_adapter.configure(self.config)

    def test_bind_callback_succeeds(self):
        topic = "topic"

        self.generic_adapter.bind_callback(topic, lambda: None)

        assert self.mocked_client.bind_callback.call_count == 1
        args, _ = self.mocked_client.bind_callback.call_args
        assert topic in args

    def test_publish_event_succeeds(self):
        message = "message"
        self.mocked_client.publish_event.return_value = None

        self.generic_adapter.publish_event(message)

        assert self.mocked_client.publish_event.call_count == 1
        args, _ = self.mocked_client.publish_event.call_args
        assert message in args

    def test_publish_event_with_client_fail_fails(self):
        self.mocked_client.publish_event.side_effect = PublishError("Error!")
        with self.assertRaises(PublishError):
            self.generic_adapter.publish_event("message")

    def test_publish_attribute_succeeds(self):
        attribute, value = "attribute", "value"
        self.mocked_client.publish_attribute.return_value = None
        self.generic_adapter.publish_attribute(attribute, value)
        self.mocked_client.publish_attribute.assert_called_once_with(attribute, value)

    def test_publish_attribute_with_client_fail_fails(self):
        self.mocked_client.publish_attribute.side_effect = PublishError("Error!")
        with self.assertRaises(PublishError):
            self.generic_adapter.publish_attribute("attribute", "value")

    def test_publish_telemetry_succeeds(self):
        telemetry, value, time = "telemetry", "value", datetime.datetime.utcnow()
        self.mocked_client.publish_telemetry.return_value = None
        self.generic_adapter.publish_telemetry(telemetry, value, time)
        self.mocked_client.publish_telemetry.assert_called_once_with(telemetry, value, time)

    def test_publish_telemetry_with_client_fail_fails(self):
        self.mocked_client.publish_telemetry.side_effect = PublishError("Error!")
        with self.assertRaises(PublishError):
            self.generic_adapter.publish_telemetry("key", "value", datetime.datetime.utcnow())

    def test_connect_succeeds(self):
        self.mocked_client.connect.return_value = None
        self.generic_adapter.connect()
        self.mocked_client.connect.assert_called_once_with()

    def test_connect_with_client_fail_fails(self):
        self.mocked_client.connect.side_effect = ConnectError("Error!")
        with self.assertRaises(ConnectError):
            self.generic_adapter.connect()

    def test_disconnect_succeeds(self):
        self.mocked_client.disconnect.return_value = None
        self.generic_adapter.disconnect()
        self.mocked_client.disconnect.assert_called_once_with()

    def test_disconnect_with_client_fail_fails(self):
        self.mocked_client.disconnect.side_effect = DisconnectError("Error!")
        with self.assertRaises(DisconnectError):
            self.generic_adapter.disconnect()
