import threading
from time import sleep
from unittest import TestCase
from mock import patch, MagicMock
from ctypes import *
from inbm_vision_lib.xlink.xlink_wrapper import XlinkWrapper
from inbm_vision_lib.xlink.ixlink_wrapper import XlinkWrapperException, receive_file_progress, check_platform_type
from inbm_vision_lib.constants import *
from inbm_vision_lib.xlink.ixlink_wrapper import X_LINK_SUCCESS, X_LINK_ERROR


class MockXlinkLib(CDLL):

    def __init__(self):
        pass

    def xlink_initialize(self):
        return X_LINK_SUCCESS

    def xlink_connect(self, handler):
        return X_LINK_SUCCESS

    def xlink_open_channel(self, handler, channel_id, operation_type, data_size, timeout):
        return X_LINK_SUCCESS

    def xlink_close_channel(self, handler, channel_id):
        return X_LINK_SUCCESS

    def xlink_disconnect(self, handler):
        return X_LINK_SUCCESS

    def xlink_read_data(self, handler, channel_id, message, size):
        message._obj.contents = c_char(b'\x01')
        size._obj.value = 1
        return X_LINK_SUCCESS

    def xlink_write_data(self):
        return X_LINK_SUCCESS

    def xlink_release_data(self, handler, channel_id, data_addr):
        return X_LINK_SUCCESS

    def xlink_boot_device(self, handler, file_path):
        return X_LINK_SUCCESS

    def xlink_reset_device(self):
        return X_LINK_SUCCESS

    def xlink_get_device_list(self, dev_id_list, num_dev):
        dev_id_list._obj[0] = 1
        dev_id_list._obj[1] = 2
        return X_LINK_SUCCESS

    def xlink_data_available_event(self, handler, channel_id, callback):
        return X_LINK_SUCCESS

    def xlink_data_consumed_event(self, handler, channel_id, callback):
        return X_LINK_SUCCESS

    def xlink_get_device_status(self, handler, device_status):
        return X_LINK_SUCCESS


class TestXlinkWrapper(TestCase):

    @patch('ctypes.CDLL.__init__', return_value=None)
    @patch('threading.Thread.start')
    def setUp(self, t_start, lib_init) -> None:
        self.receive = MagicMock()
        self.xlink_wrapper = XlinkWrapper(self.receive, UNSECURED_XLINK_CHANNEL, 0, True)
        # assign mock xlink library
        self.xlink_wrapper._xlink_library = MockXlinkLib()

    @patch.object(MockXlinkLib, 'xlink_open_channel', return_value=X_LINK_SUCCESS)
    @patch.object(MockXlinkLib, 'xlink_connect', return_value=X_LINK_SUCCESS)
    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.boot_device', return_value=X_LINK_SUCCESS)
    @patch.object(MockXlinkLib, 'xlink_initialize', return_value=X_LINK_SUCCESS)
    @patch('time.sleep', return_value=None)
    def test_init_channel(self, sleep, init, boot_dev, connect, open_channel):
        self.xlink_wrapper._init_channel()
        init.assert_called_once()
        boot_dev.assert_called_once()
        connect.assert_called_once()
        open_channel.assert_called_once()

    @patch.object(MockXlinkLib, 'xlink_data_consumed_event', return_value=X_LINK_SUCCESS)
    @patch.object(MockXlinkLib, 'xlink_data_available_event', return_value=X_LINK_SUCCESS)
    def test_register_callback(self, data_ready, data_consumed):
        self.xlink_wrapper._register_callback()
        data_ready.assert_called_once()
        data_consumed.assert_called_once()

    def test_get_init_status(self):
        self.xlink_wrapper.xlink_init_status_success = True
        self.assertEqual(self.xlink_wrapper.get_init_status(), True)

    def test_get_device_id(self):
        self.xlink_wrapper._xlink_handler.sw_device_id = 1234567
        self.assertEqual(self.xlink_wrapper.get_device_id(), 1234567)

    @patch('threading.Thread.start')
    def test_start(self, start_listen):
        self.xlink_wrapper.start()
        start_listen.assert_called_once()

    @patch('inbm_vision_lib.xlink.ixlink_wrapper.IXlinkWrapper._check_status')
    @patch.object(MockXlinkLib, 'xlink_write_data', return_value=X_LINK_SUCCESS)
    def test_send(self, write, check_status):
        self.xlink_wrapper.xlink_init_status_success = True
        self.xlink_wrapper.send("123")
        write.assert_called_once()
        check_status.assert_called_once()

    def test_check_status_pass(self):
        self.xlink_wrapper._check_status(X_LINK_SUCCESS, "")

    def test_check_status_fail(self):
        self.assertRaises(XlinkWrapperException,
                          self.xlink_wrapper._check_status, X_LINK_ERROR, "Error")

    @patch('os.path.islink', return_value=False)
    @patch('os.path.exists', return_value=True)
    @patch('builtins.open')
    @patch('os.path.getsize', return_value=100)
    @patch('inbm_vision_lib.xlink.ixlink_wrapper.IXlinkWrapper._check_status')
    @patch.object(MockXlinkLib, 'xlink_write_data', return_value=X_LINK_SUCCESS)
    @patch('time.sleep', return_value=None)
    def test_send_file_single_chunk(self, sleep, write, check_status, get_size, open_file, mock_exists, mock_islink):
        self.xlink_wrapper.xlink_init_status_success = True
        self.xlink_wrapper.send_file("123")
        assert write.call_count == 4
        assert check_status.call_count == 4

    @patch('os.path.islink', return_value=False)
    @patch('os.path.exists', return_value=True)
    @patch('builtins.open')
    @patch('os.path.getsize', return_value=10000000)
    @patch('inbm_vision_lib.xlink.ixlink_wrapper.IXlinkWrapper._check_status')
    @patch.object(MockXlinkLib, 'xlink_write_data', return_value=X_LINK_SUCCESS)
    @patch('time.sleep', return_value=None)
    def test_send_file_multiple_chunk(self, sleep, write, check_status, get_size, open_file, mock_exists, mock_islink):
        self.xlink_wrapper.xlink_init_status_success = True
        self.xlink_wrapper.send_file("123")
        assert write.call_count == 8
        assert check_status.call_count == 3

    @patch('inbm_vision_lib.xlink.ixlink_wrapper.IXlinkWrapper._check_status')
    @patch.object(MockXlinkLib, 'xlink_release_data', return_value=X_LINK_SUCCESS)
    def test_xlink_release_data(self, release, check_status):
        self.xlink_wrapper._xlink_release_data()
        release.assert_called_once()
        check_status.assert_called_once()

    @patch.object(MockXlinkLib, 'xlink_boot_device', return_value=X_LINK_SUCCESS)
    @patch('time.sleep', return_value=None)
    def test_boot_device(self, sleep, boot_dev):
        self.xlink_wrapper._agent = VISION
        self.xlink_wrapper.boot_device()
        assert boot_dev.call_count == 2

    @patch.object(MockXlinkLib, 'xlink_reset_device', return_value=X_LINK_SUCCESS)
    def test_reset_device(self, reset_dev):
        self.xlink_wrapper._agent = VISION
        self.xlink_wrapper.reset_device()
        reset_dev.assert_called_once()

    @patch.object(MockXlinkLib, 'xlink_disconnect', return_value=X_LINK_SUCCESS)
    @patch.object(MockXlinkLib, 'xlink_close_channel', return_value=X_LINK_SUCCESS)
    @patch('time.sleep', return_value=None)
    def test_stop_xlink(self, sleep, close, disconnect):
        self.xlink_wrapper.stop(disconnect=True)
        close.assert_called_once()
        disconnect.assert_called_once()

    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper._xlink_release_data')
    def test_xlink_listen_to_channel(self, release_data):
        def stop_listen():
            sleep(0.1)
            self.xlink_wrapper._running = False
        thread = threading.Thread(target=stop_listen)
        thread.daemon = True
        thread.start()
        self.xlink_wrapper.xlink_init_status_success = True
        self.xlink_wrapper._listen_to_channel()
        release_data.assert_called()
        self.receive.assert_called()

    def test_xlink_get_device_status(self):
        self.assertEqual(self.xlink_wrapper.get_xlink_device_status(), 0)

    def test_receive_file_progress(self):
        self.assertEqual(receive_file_progress(20, 100), 20)
        self.assertEqual(receive_file_progress(40, 100), 40)
        self.assertEqual(receive_file_progress(60, 100), 60)
        self.assertEqual(receive_file_progress(80, 100), 80)
        self.assertEqual(receive_file_progress(99, 100), 99)
        self.assertEqual(receive_file_progress(101, 100), None)

    def test_check_platform_type_KMB(self):
        self.assertEqual(check_platform_type(17629184), KMB)

    def test_check_platform_type_KMB_second_node_id(self):
        self.assertEqual(check_platform_type(16780544), KMB)

    def test_check_platform_type_TBH(self):
        self.assertEqual(check_platform_type(17104928), TBH)
