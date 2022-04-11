import os
import threading
import signal
from time import sleep
from unittest import TestCase
from mock import patch, Mock, MagicMock
from node.node import Node, purge_cache, get_log_config_path
from node.node import main as main_method
from node.inode import INode
from node.xlink_manager import XlinkManager
from node.node_exception import NodeException


class TestBitCreekNode(TestCase):

    def setUp(self):
        self.node: INode = Node()

    @patch('os.listdir', return_value=['file.tar'])
    @patch('os.path.join', return_value='file.tar')
    @patch('os.remove')
    @patch('os.path.exists', return_value=True)
    def test_purge_cache(self, mock_path, mock_remove, mock_join, mock_list):
        purge_cache()

    def test_init(self):
        mock_broker = Mock()
        mock_xlink = Mock()
        mock_data_handler = Mock()
        self.node.initialize(mock_broker, mock_xlink, mock_data_handler)
        self.assertEquals(self.node.get_broker(), mock_broker)
        self.assertEquals(self.node.get_xlink(), mock_xlink)
        self.assertEquals(self.node.get_data_handler(), mock_data_handler)

    @patch('inbm_vision_lib.xlink.xlink_library.XLinkLibrary.__init__', return_value=None)
    @patch('node.xlink_manager.XlinkManager._query_channel')
    @patch('node.xlink_manager.XlinkManager.start')
    def test_start_xlink_channel_pass(self, listen_channel, query_channel, mock_xlink_lib):
        new_config_mgr = Mock()
        new_config_mgr.get_element = MagicMock(return_value=[1, "SUCCESS"])
        self.node.initialize(None, XlinkManager(None, new_config_mgr), None)  # type: ignore
        self.node.start()
        listen_channel.assert_called_once()
        query_channel.query_channel()

    def test_start_fail_without_xlink_manager(self):
        self.node.initialize(None, None, None)  # type: ignore
        with self.assertRaises(NodeException):
            self.node.start()

    def test_get_log_config_path_throw_exception(self):
        log_config_path = get_log_config_path()
        self.assertEqual(log_config_path, "/etc/intel-manageability/public/node-agent/logging.ini")

    @patch('node.node.Node.start', side_effect=NodeException)
    @patch('node.xlink_manager.XlinkManager.get_init_status', return_value=True)
    @patch('node.xlink_manager.XlinkManager.start')
    @patch('node.xlink_manager.XlinkManager.__init__', return_value=None)
    @patch('node.broker.Broker.__init__', return_value=None)
    @patch('node.data_handler.DataHandler.__init__', return_value=None)
    @patch('inbm_vision_lib.configuration_manager.ConfigurationManager.__init__', return_value=None)
    @patch('node.node.fileConfig', autospec=True)
    def test_main_throw_exception_fail_to_start_node(self, file_config, config_init, dh_init, broker_init, xlink_init, x_start, get_status, m_start):
        self.assertRaises(SystemExit, main_method)

    @patch('node.node.Node.stop', side_effect=NodeException)
    @patch('node.data_handler.DataHandler.register')
    @patch('node.node.purge_cache')
    @patch('node.node.Node.start')
    @patch('node.xlink_manager.XlinkManager.get_init_status', return_value=True)
    @patch('node.xlink_manager.XlinkManager.start')
    @patch('node.xlink_manager.XlinkManager.__init__', return_value=None)
    @patch('node.broker.Broker.__init__', return_value=None)
    @patch('node.data_handler.DataHandler.__init__', return_value=None)
    @patch('inbm_vision_lib.configuration_manager.ConfigurationManager.__init__', return_value=None)
    @patch('node.node.fileConfig', autospec=True)
    def test_main_throw_exception_fail_to_stop_node(self, file_config, config_init, dh_init, broker_init, xlink_init, x_start, get_status, m_start, purge_cache, register, stop_node):
        pid = os.getpid()

        def terminate_signal():
            sleep(1)
            os.kill(pid, signal.SIGINT)

        thread = threading.Thread(target=terminate_signal)
        thread.daemon = True
        thread.start()
        self.assertRaises(SystemExit, main_method)
