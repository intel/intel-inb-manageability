from unittest import TestCase
from mock import patch, Mock, MagicMock

from inbm_vision_lib.xlink.ixlink_wrapper import XlinkWrapperException
from inbm_common_lib.pms.pms_helper import PmsException

from vision.data_handler.data_handler import DataHandler
from vision.node_communicator.node_connector import NodeConnector


class TestNodeConnector(TestCase):

    @patch('inbm_vision_lib.xlink.xlink_library.XLinkLibrary.__init__', return_value=None)
    @patch('vision.data_handler.data_handler.DataHandler.load_config_file')
    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.invoker.Invoker.__init__', return_value=None)
    @patch('vision.registry_manager.RegistryManager.__init__', return_value=None)
    def setUp(self, mock_reg, mock_invoker, mock_start_thread, mock_load_file, mock_xlink_lib):
        new_data_handler = DataHandler(Mock(), Mock())
        new_config_mgr = Mock()
        new_config_mgr.get_element = MagicMock(return_value=[1, "SUCCESS"])
        self.node_connector = NodeConnector(new_data_handler, new_config_mgr)
        mock_reg.assert_called_once()
        mock_invoker.assert_called_once()
        mock_start_thread.assert_called_once()
        mock_load_file.assert_called_once()

    @patch('vision.node_communicator.node_connector.logger')
    @patch('vision.node_communicator.xlink_connector.XlinkConnector.send')
    def test_send_message(self, mock_send, mock_logger):
        self.node_connector.send('mock_message', '389COA')
        mock_send.assert_called_once()
        assert mock_logger.error.call_count == 0

    @patch('vision.node_communicator.node_connector.logger')
    @patch('vision.node_communicator.xlink_connector.XlinkConnector.send',
           side_effect=XlinkWrapperException("Failed to send message"))
    def test_raises_when_send_message_fails(self, mock_send, mock_logger):
        self.node_connector.send('mock_message', '389COA')
        assert mock_logger.error.call_count == 1

    @patch('vision.node_communicator.node_connector.logger')
    @patch('vision.node_communicator.xlink_connector.XlinkConnector.send_file')
    def test_send_file(self, mock_send, mock_logger):
        self.node_connector.send_file('389COA', 'mock_filepath')
        mock_send.assert_called_once()
        assert mock_logger.error.call_count == 0

    @patch('vision.node_communicator.node_connector.logger')
    @patch('vision.node_communicator.xlink_connector.XlinkConnector.send_file',
           side_effect=XlinkWrapperException("Failed to send message"))
    def test_raises_when_send_file_fails(self, mock_send, mock_logger):
        self.node_connector.send_file('389COA', 'mock_filepath')
        assert mock_logger.error.call_count == 1

    @patch('vision.node_communicator.node_connector.logger')
    @patch('vision.node_communicator.xlink_connector.XlinkConnector.boot_device')
    def test_boot_device(self, mock_boot, mock_logger):
        self.node_connector.boot_device('389COA')
        mock_boot.assert_called_once()
        assert mock_logger.error.call_count == 0

    @patch('vision.node_communicator.node_connector.logger')
    @patch('vision.node_communicator.xlink_connector.XlinkConnector.boot_device',
           side_effect=XlinkWrapperException("Failed to send message"))
    def test_raises_when_boot_device_fails(self, mock_boot, mock_logger):
        self.node_connector.boot_device('389COA')
        assert mock_logger.error.call_count == 1

    @patch('inbm_common_lib.pms.pms_helper.PMSHelper.reset_device')
    def test_reset_device_via_pms(self, pms_reset):
        self.node_connector.reset_device('007f5a2-12345')
        pms_reset.assert_called_once()

    @patch('vision.node_communicator.node_connector.logger')
    @patch('vision.node_communicator.xlink_connector.XlinkConnector.reset_device')
    @patch('inbm_common_lib.pms.pms_helper.PMSHelper.reset_device', side_effect=PmsException)
    def test_reset_device_via_xlink(self, pms_reset, mock_reset, mock_logger):
        self.node_connector.reset_device('007f5a2-12345')
        mock_reset.assert_called_once()
        assert mock_logger.error.call_count == 1

    @patch('vision.node_communicator.node_connector.logger')
    @patch('vision.node_communicator.xlink_connector.XlinkConnector.reset_device',
           side_effect=XlinkWrapperException("Failed to send message"))
    @patch('inbm_common_lib.pms.pms_helper.PMSHelper.reset_device', side_effect=PmsException)
    def test_raises_when_reset_device_fails(self, pms_reset, mock_reset, mock_logger):
        self.node_connector.reset_device('007f5a2-12345')
        assert mock_logger.error.call_count == 2

    @patch('vision.node_communicator.xlink_connector.XlinkConnector.get_guid')
    def test_get_guid_is_called(self, get_guid):
        self.node_connector.get_guid(12345)
        get_guid.assert_called_once()

    @patch('vision.node_communicator.xlink_connector.XlinkConnector.is_provisioned')
    def test_is_provisioned_is_called(self, mock_is_provisioned):
        self.node_connector.is_provisioned(12345)
        mock_is_provisioned.assert_called_once()

    @patch('vision.node_communicator.xlink_connector.XlinkConnector.get_all_guid')
    def test_get_all_guid_is_called(self, get_all_guid):
        self.node_connector.get_all_guid()
        get_all_guid.assert_called_once()
