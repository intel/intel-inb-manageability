import os
import threading
from time import sleep
from unittest import TestCase

from mock import patch, Mock, MagicMock
from node.data_handler import DataHandler
from node.xlink_manager import XlinkManager


class TestXlinkManager(TestCase):

    @patch('threading.Thread.start')
    @patch('node.data_handler.DataHandler.load_config_file')
    def setUp(self, load_config, t_start):
        new_data_handler = DataHandler(Mock(), Mock())
        new_config_mgr = Mock()
        new_config_mgr.get_element = MagicMock(return_value=[20, "SUCCESS"])
        self.xlink_manager = XlinkManager(new_data_handler, new_config_mgr)
        load_config.assert_called_once()

    @patch('node.data_handler.DataHandler.receive_xlink_message')
    def test_receive(self, receive_msg):
        self.xlink_manager.receive('mock_message')
        receive_msg.assert_called_once()

    @patch('node.xlink_manager.sleep')
    @patch('node.xlink_manager.XlinkManager._start_public_thread')
    @patch('node.data_handler.DataHandler.reset_heartbeat')
    def test_receive_reconnection_message(self, reset, start_pub, patch_sleep):
        self.xlink_manager.receive('RECONNECT')
        reset.assert_called_once()
        start_pub.assert_called_once()

    @patch('node.data_handler.DataHandler.downloaded_file')
    def test_receive_file_message(self, download_file):
        self.xlink_manager.xlink_wrapper = Mock()
        self.xlink_manager.xlink_wrapper.receive_file  # type: ignore
        self.xlink_manager.receive('FILE')
        self.xlink_manager.xlink_wrapper.receive_file.assert_called_once()  # type: ignore
        download_file.assert_called_once()

    @patch('node.data_handler.DataHandler.downloaded_file')
    def test_receive_fail_no_xlink_wrapper(self, download_file):
        self.xlink_manager.receive("FILE")
        download_file.assert_called_once()

    @patch('node.xlink_manager.XlinkManager.send')
    def test_send_message(self, send_message):
        self.xlink_manager.send('mock_message')
        send_message.assert_called_once()

    def test_stop_listen_to_channel(self):
        self.xlink_manager.xlink_public_channel = Mock()
        self.xlink_manager.xlink_wrapper = Mock()
        self.xlink_manager.stop()

    @patch('inbm_vision_lib.checksum_validator.hash_message')
    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.send')
    def test_send_message_with_hash(self, send_message, hash_message):
        self.xlink_manager.send('mock_message')
        hash_message.assert_called_once()

    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.send')
    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.start')
    @patch('node.xlink_manager.get_all_xlink_pcie_device_ids', return_value=[1702351])
    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.get_init_status', return_value=True)
    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.__init__', return_value=None)
    def test_query_channel(self, init, get_status, get_id, start, send):
        def set_running():
            sleep(2)
            self.xlink_manager.running = False

        thread = threading.Thread(target=set_running)
        thread.daemon = True
        thread.start()

        self.xlink_manager._query_channel()
        init.assert_called_once()
        get_status.assert_called_once()
        start.assert_called_once()
        send.assert_called_once()

    @patch('node.data_handler.DataHandler.register')
    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.start')
    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.get_init_status', return_value=True)
    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.__init__', return_value=None)
    def test_receive_channel_non_secure_xlink(self, init, get_status, start, register):
        self.xlink_manager._is_secure_xlink = False
        self.xlink_manager.xlink_public_channel = Mock()
        self.xlink_manager._receive_channel("1282/01ff9982-1679820")
        init.assert_called_once()
        get_status.assert_called_once()
        start.assert_called_once()

    @patch('node.data_handler.DataHandler.register')
    @patch('inbm_vision_lib.xlink.xlink_secure_wrapper.XlinkSecureWrapper.start')
    @patch('inbm_vision_lib.xlink.xlink_secure_wrapper.XlinkSecureWrapper.get_init_status', return_value=True)
    @patch('inbm_vision_lib.xlink.xlink_secure_wrapper.XlinkSecureWrapper.__init__', return_value=None)
    def test_receive_channel_secure_xlink(self, init, get_status, start, register):
        self.xlink_manager._is_secure_xlink = True
        self.xlink_manager.xlink_public_channel = Mock()
        self.xlink_manager._receive_channel("1282/01ff9982-1679820")
        init.assert_called_once()
        get_status.assert_called_once()
        start.assert_called_once()

    def test_get_init_status_true(self):
        mock_xlink = Mock()
        mock_xlink.get_init_status = MagicMock(return_value=True)
        self.xlink_manager.xlink_wrapper = mock_xlink
        status = self.xlink_manager.get_init_status()
        self.assertEqual(status, True)

    def test_get_init_status_false(self):
        status = self.xlink_manager.get_init_status()
        self.assertEqual(status, False)

    @patch('node.data_handler.DataHandler.register')
    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.stop')
    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.send')
    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.start')
    @patch('node.xlink_manager.get_all_xlink_pcie_device_ids', return_value=[1702351])
    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.get_init_status', return_value=True)
    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.__init__', return_value=None)
    def test_node_not_send_query_message_after_receive_message_from_vision_agent_pass(self, init, get_status, get_id,
                                                                                      start, send, stop, register):
        def receive_response_from_vision_agent():
            sleep(2)
            self.xlink_manager._receive_channel("1282/01ff9982-1679820")

        def set_running():
            sleep(8)
            self.xlink_manager.running = False

        thread = threading.Thread(target=receive_response_from_vision_agent)
        thread.daemon = True
        thread.start()

        thread = threading.Thread(target=set_running)
        thread.daemon = True
        thread.start()

        self.xlink_manager.xlink_retry_sec = 5
        self.xlink_manager._query_channel()
        stop.assert_called_once()
        send.assert_called_once()
        register.assert_called_once()
        assert start.call_count == 2
        assert init.call_count == 2
        assert get_status.call_count == 2

    @patch('node.data_handler.DataHandler.register')
    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.stop', side_effect=Exception)
    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.send', side_effect=[True, AttributeError])
    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.start')
    @patch('node.xlink_manager.get_all_xlink_pcie_device_ids', return_value=[1702351])
    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.get_init_status', return_value=True)
    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.__init__', return_value=None)
    def test_node_not_send_query_message_after_receive_message_from_vision_agent_fail(self, init, get_status, get_id,
                                                                                      start, send, stop, register):
        def receive_response_from_vision_agent():
            sleep(2)
            self.xlink_manager._receive_channel("1282/01ff9982-1679820")

        def set_running():
            sleep(15)
            self.xlink_manager.running = False

        thread = threading.Thread(target=receive_response_from_vision_agent)
        thread.daemon = True
        thread.start()

        thread = threading.Thread(target=set_running)
        thread.daemon = True
        thread.start()

        self.xlink_manager.xlink_retry_sec = 5
        self.assertRaises(AttributeError, self.xlink_manager._query_channel)
        get_status.assert_called_once()
        start.assert_called_once()
        register.assert_not_called()
        assert init.call_count == 2
        assert send.call_count == 2
