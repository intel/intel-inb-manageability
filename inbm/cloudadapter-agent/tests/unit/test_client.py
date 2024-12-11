"""
Unit tests for the Client class


"""


import unittest
import mock

from cloudadapter.client import Client
from cloudadapter.exceptions import DisconnectError
from cloudadapter.constants import RUNNING, DEAD


class TestClient(unittest.TestCase):

    @mock.patch('cloudadapter.client.Broker', autospec=True)
    @mock.patch('cloudadapter.cloud.adapters.adapter.Adapter', autospec=True)
    @mock.patch('cloudadapter.client.adapter_factory', autospec=True)
    def setUp(self, mock_adapter_factory, MockAdapter, MockBroker) -> None:
        self.mock_adapter = MockAdapter("config")
        self.mock_adapter.set_dispatcher_state = mock.MagicMock()
        self.mock_adapter_factory = mock_adapter_factory
        self.mock_adapter_factory.get_adapter.return_value = self.mock_adapter

        self.MockBroker = MockBroker

        self.client = Client()

    def test_start_broker_succeed(self) -> None:
        self.client.start()

        self.MockBroker.assert_called_once_with()
        assert self.MockBroker.return_value.bind_callback.call_count > 0
        self.MockBroker.return_value.start.assert_called_once_with()

    def test_start_adapter_succeed(self) -> None:
        self.client.start()

        self.mock_adapter_factory.get_adapter.assert_called_once_with()
        assert self.mock_adapter.bind_callback.call_count > 0
        self.mock_adapter.connect.assert_called_once_with()

    def test_stop_succeed(self) -> None:
        self.client.stop()

        self.MockBroker.return_value.stop.assert_called_once_with()
        self.mock_adapter.disconnect.assert_called_once_with()

    @mock.patch('cloudadapter.client.logger', autospec=True)
    def test_stop_logs_failure_succeeds(self, mock_logger) -> None:
        self.mock_adapter.disconnect.side_effect = DisconnectError
        self.client.stop()
        assert mock_logger.error.call_count == 1

    @mock.patch('cloudadapter.cloud.adapters.adapter.Adapter.get_client_id', return_value="abc123")
    def test_bind_ucc_to_agent(self, mock_get_client) -> None:
        self.client._bind_ucc_to_agent()
        self.MockBroker.assert_called_once_with()
        assert self.mock_adapter.bind_callback.call_count > 0

    @mock.patch('cloudadapter.client.isinstance',  return_value=True)
    def test_handle_state_running(self, mock_instance) -> None:
        self.client._handle_state("dispatcher/state", RUNNING)
        assert self.mock_adapter.set_dispatcher_state.call_count == 1

    @mock.patch('cloudadapter.client.isinstance', return_value=True)
    def test_handle_state_dead(self, mock_instance) -> None:
        self.client._handle_state("dispatcher/state", DEAD)
        assert self.mock_adapter.set_dispatcher_state.call_count == 1
