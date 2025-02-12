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

    @mock.patch("cloudadapter.client.make_threaded", lambda logger: logger)
    def test_with_log_success(self):
        """
        Test that a function decorated with _with_log returns its result and 
        the logger is invoked with that result.
        """
        # Dummy function that returns a computed message.
        def dummy_func(x):
            return f"success-{x}"
        
        # Create a MagicMock to simulate a logger.
        dummy_logger = mock.MagicMock()
        
        # Decorate the dummy function.
        decorated = self.client._with_log(dummy_func, dummy_logger)
        
        # Call the decorated function.
        result = decorated("test")
        
        # Verify the original function's return value is propagated.
        self.assertEqual(result, "success-test")
        # Verify that the logger was called exactly once with the same message.
        dummy_logger.assert_called_once_with("success-test")

    @mock.patch("cloudadapter.client.make_threaded", lambda logger: logger)
    def test_with_log_exception(self):
        """
        Test that if the decorated function raises an exception (ValueError,
        KeyError, or TypeError), _with_log catches it, returns a formatted error 
        message, and logs that error message.
        """
        # Dummy function that always raises a ValueError.
        def failing_func(x):
            raise ValueError("oops")
        
        # Create a MagicMock to simulate a logger.
        dummy_logger = mock.MagicMock()
        
        # Decorate the failing function.
        decorated = self.client._with_log(failing_func, dummy_logger)
        
        # Call the decorated function.
        result = decorated("bad input")
        
        expected_message = "Command failing_func failed: oops"
        # Verify the return value is the formatted error message.
        self.assertEqual(result, expected_message)
        # Verify that the logger was invoked exactly once with the error message.
        dummy_logger.assert_called_once_with(expected_message)

    def test_start_broker_succeed(self) -> None:
        self.client.start()

        self.MockBroker.assert_called_once_with(tls=True)
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
        self.MockBroker.assert_called_once_with(tls=True)
        assert self.mock_adapter.bind_callback.call_count > 0

    @mock.patch('cloudadapter.client.isinstance',  return_value=True)
    def test_handle_state_running(self, mock_instance) -> None:
        self.client._handle_state("dispatcher/state", RUNNING)
        assert self.mock_adapter.set_dispatcher_state.call_count == 1

    @mock.patch('cloudadapter.client.isinstance', return_value=True)
    def test_handle_state_dead(self, mock_instance) -> None:
        self.client._handle_state("dispatcher/state", DEAD)
        assert self.mock_adapter.set_dispatcher_state.call_count == 1
