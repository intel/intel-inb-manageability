"""
Unit tests for the Device Manager class


"""


import unittest
import mock

from cloudadapter.constants import MESSAGE
from cloudadapter.agent.device_manager import DeviceManager


class TestDeviceManager(unittest.TestCase):

    @mock.patch('cloudadapter.agent.broker.Broker', autospec=True)
    def setUp(self, MockBroker):
        self.MockBroker = MockBroker
        self.device_manager = DeviceManager(self.MockBroker())

    def test_shutdown_device_succeed(self):
        message = self.device_manager.shutdown_device()

        assert message == MESSAGE.SHUTDOWN
        mocked = self.MockBroker.return_value
        mocked.publish_shutdown.assert_called_once_with()

    def test_reboot_device_succeed(self):
        message = self.device_manager.reboot_device()

        assert message == MESSAGE.REBOOT
        mocked = self.MockBroker.return_value
        mocked.publish_reboot.assert_called_once_with()

    @mock.patch(
        'cloudadapter.agent.device_manager.get_adapter_config_filepaths',
        return_value=[])
    @mock.patch('cloudadapter.agent.device_manager.os')
    def test_decommission_device_no_configs_succeed(
            self, mock_os, mock_get_adapter_config_filepaths):
        message = self.device_manager.decommission_device()

        assert message == MESSAGE.DECOMMISSION
        mock_get_adapter_config_filepaths.assert_called_once_with()
        assert mock_os.remove.call_count == 0

    @mock.patch(
        'cloudadapter.agent.device_manager.get_adapter_config_filepaths',
        return_value=['F', 'I', 'L', 'E', 'S'])
    @mock.patch('cloudadapter.agent.device_manager.remove_file')
    def test_decommission_device_with_configs_succeed(
            self, mock_remove, mock_get_adapter_config_filepaths):
        message = self.device_manager.decommission_device()

        assert message == MESSAGE.DECOMMISSION
        mock_get_adapter_config_filepaths.assert_called_once_with()
        assert mock_remove.call_count == 5

    @mock.patch('os.path.exists', return_value=True)
    @mock.patch('os.path.isfile', side_effect=OSError())
    @mock.patch(
        'cloudadapter.agent.device_manager.get_adapter_config_filepaths',
        return_value=['FILE'])
    @mock.patch('cloudadapter.agent.device_manager.logger')
    def test_decommission_device_logs_warning_succeed(
            self, mock_logger, mock_get_adapter_config_filepaths, mock_remove, mock_exists):
        self.device_manager.decommission_device()
        assert mock_logger.warn.call_count > 0
