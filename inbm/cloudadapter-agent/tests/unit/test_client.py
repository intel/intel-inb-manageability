"""
Unit tests for the Client class


"""


import unittest
import mock

from cloudadapter.client import Client
from cloudadapter.exceptions import DisconnectError


class TestClient(unittest.TestCase):

    @mock.patch('cloudadapter.client.Broker', autospec=True)
    @mock.patch('cloudadapter.cloud.adapters.adapter.Adapter', autospec=True)
    @mock.patch('cloudadapter.client.adapter_factory', autospec=True)
    def setUp(self, mock_adapter_factory, MockAdapter, MockBroker):
        self.mock_adapter = MockAdapter("config")
        self.mock_adapter_factory = mock_adapter_factory
        self.mock_adapter_factory.get_adapter.return_value = self.mock_adapter

        self.MockBroker = MockBroker

        self.client = Client()

    def test_start_broker_succeed(self):
        self.client.start()

        self.MockBroker.assert_called_once_with()
        assert self.MockBroker.return_value.ota_formback.call_count > 0
        self.MockBroker.return_value.start.assert_called_once_with()

    def test_start_adapter_succeed(self):
        self.client.start()

        self.mock_adapter_factory.get_adapter.assert_called_once_with()
        assert self.mock_adapter.bind_callback.call_count > 0
        self.mock_adapter.connect.assert_called_once_with()

    def test_stop_succeed(self):
        self.client.stop()

        self.MockBroker.return_value.stop.assert_called_once_with()
        self.mock_adapter.disconnect.assert_called_once_with()

    @mock.patch('cloudadapter.client.logger', autospec=True)
    def test_stop_logs_failure_succeeds(self, mock_logger):
        self.mock_adapter.disconnect.side_effect = DisconnectError
        self.client.stop()
        assert mock_logger.error.call_count == 1
