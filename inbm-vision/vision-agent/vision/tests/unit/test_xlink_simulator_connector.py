from unittest import TestCase
from mock import patch, Mock, MagicMock

from vision.node_communicator.ixlink_channel_connector import XlinkSimulatorConnector
from vision.data_handler.data_handler import DataHandler


class TestXlinkSimulatorConnector(TestCase):

    @patch('inbm_vision_lib.xlink.xlink_simulator_wrapper.XlinkSimulatorWrapper.__init__', return_value=None)
    @patch('vision.data_handler.data_handler.DataHandler.load_config_file')
    @patch('inbm_vision_lib.invoker.Invoker.__init__', return_value=None)
    @patch('vision.registry_manager.RegistryManager.__init__', return_value=None)
    def setUp(self, mock_reg, mock_invoker, mock_load_file, mock_sim_wrapper):
        new_data_handler = DataHandler(Mock(), Mock())

        channel_list = list(range(1530, 1730))
        self.xlink_sim_connector = XlinkSimulatorConnector(new_data_handler, channel_list, False)
        mock_reg.assert_called_once()
        mock_invoker.assert_called_once()
        mock_load_file.assert_called_once()

    @patch('inbm_vision_lib.xlink.xlink_simulator_wrapper.XlinkSimulatorWrapper.send')
    def test_send(self, mock_send):
        self.xlink_sim_connector.send('mock_message', '389C0A')
        mock_send.assert_called_once()

    @patch('inbm_vision_lib.xlink.xlink_simulator_wrapper.XlinkSimulatorWrapper.boot_device')
    def test_boot_device(self, mock_boot_device):
        self.xlink_sim_connector.boot_device('389C0A')
        mock_boot_device.assert_called_once()

    @patch('inbm_vision_lib.xlink.xlink_simulator_wrapper.XlinkSimulatorWrapper.reset_device')
    def test_reset_device(self, mock_reset_device):
        self.xlink_sim_connector.reset_device('389C0A')
