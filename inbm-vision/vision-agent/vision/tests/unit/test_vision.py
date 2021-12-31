import os
import signal
import threading
from time import sleep
from unittest import TestCase

from vision.vision import Vision, get_log_config_path
from vision.vision import main as main_method
from vision.constant import VisionException
from vision.node_communicator.node_connector import NodeConnector
from mock import patch, Mock, MagicMock


class TestVision(TestCase):

    def setUp(self):
        self._vision = Vision()

    def test_init(self):
        mock_broker = Mock()
        mock_node_connector = Mock()
        mock_data_handler = Mock()
        self._vision.initialize(mock_broker, mock_node_connector, mock_data_handler)
        self.assertEquals(self._vision._broker, mock_broker)
        self.assertEquals(self._vision._node_connector, mock_node_connector)
        self.assertEquals(self._vision._data_handler, mock_data_handler)

    @patch('vision.node_communicator.xlink_connector.filter_first_slice_from_list', return_value=[1702351])
    @patch('vision.node_communicator.xlink_connector.get_all_xlink_pcie_device_ids', return_value=[1702351])
    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.__init__', return_value=None)
    def test_start_xlink_channel(self, init_wrapper, get_id, filter):
        new_config_mgr = Mock()
        new_config_mgr.get_element = MagicMock(return_value=[1, "SUCCESS"])
        self._vision.initialize(None, NodeConnector(None, new_config_mgr), None)  # type: ignore
        init_wrapper.assert_called_once()

    def test_stop_vision_no_data_handler(self):
        self.assertRaises(VisionException, self._vision.stop)

    def test_stop_vision_no_xlink_manager(self):
        mock_data_handler = Mock()
        self._vision.initialize(None, None, mock_data_handler)   # type: ignore
        self.assertRaises(VisionException, self._vision.stop)

    @patch('vision.broker.Broker.stop_broker')
    def test_stop_vision_no_broker(self, broker_stop):
        mock_data_handler = Mock()
        mock_data_handler.stop
        mock_node_connector = Mock()
        mock_node_connector.stop
        self._vision.initialize(None, mock_node_connector, mock_data_handler)   # type: ignore
        self._vision.stop()
        mock_data_handler.stop.assert_called_once()
        mock_node_connector.stop.assert_called_once()
        broker_stop.assert_not_called()

    def test_stop_vision(self):
        mock_broker = Mock()
        mock_broker.stop_broker
        mock_data_handler = Mock()
        mock_data_handler.stop
        mock_node_connector = Mock()
        mock_node_connector.stop
        self._vision.initialize(mock_broker, mock_node_connector, mock_data_handler)
        self._vision.stop()
        mock_data_handler.stop.assert_called_once()
        mock_node_connector.stop.assert_called_once()
        mock_broker.stop_broker.assert_called_once()

    def test_get_log_config_path_throw_exception(self):
        log_config_path = get_log_config_path()
        self.assertEqual(
            log_config_path, "/etc/intel-manageability/public/vision-agent/logging.ini")

    @patch('vision.vision.Vision.stop', side_effect=VisionException)
    @patch('vision.node_communicator.node_connector.NodeConnector.__init__', return_value=None)
    @patch('vision.broker.Broker.__init__', return_value=None)
    @patch('vision.data_handler.data_handler.DataHandler.__init__', return_value=None)
    @patch('inbm_vision_lib.configuration_manager.ConfigurationManager.__init__', return_value=None)
    @patch('vision.vision.fileConfig', autospec=True)
    def test_main_throw_exception_fail_to_stop_vision(self, file_config, config_init, dh_init, broker_init, xlink_init, m_stop):
        pid = os.getpid()

        def terminate_signal():
            sleep(1)
            os.kill(pid, signal.SIGINT)

        thread = threading.Thread(target=terminate_signal)
        thread.daemon = True
        thread.start()
        self.assertRaises(SystemExit, main_method)
