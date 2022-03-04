from unittest import TestCase
from mock import patch, Mock, MagicMock

from inbm_vision_lib.xlink.ixlink_wrapper import XlinkWrapperException, X_LINK_SUCCESS
from inbm_vision_lib.constants import TBH, KMB

from vision.data_handler.data_handler import DataHandler
from vision.node_communicator.xlink_connector import XlinkConnector
from vision.node_communicator.xlink import Xlink, XlinkPublic


class TestXlinkConnector(TestCase):

    @patch('vision.data_handler.data_handler.DataHandler.load_config_file')
    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.invoker.Invoker.__init__', return_value=None)
    @patch('vision.registry_manager.RegistryManager.__init__', return_value=None)
    def setUp(self, mock_reg, mock_invoker, mock_start_thread, mock_load_file):
        new_data_handler = DataHandler(Mock(), Mock())

        channel_list = list(range(1530, 1730))
        self.xlink_connector = XlinkConnector(new_data_handler, channel_list, False)
        self.xlink_connector.initialize()
        mock_reg.assert_called_once()
        mock_invoker.assert_called_once()
        mock_start_thread.assert_called_once()
        mock_load_file.assert_called_once()

    @patch('vision.node_communicator.xlink_connector.get_mac_address', return_value='02:e1:87:54:8c:80')
    def test_create_node_id_with_valid_mac(self, mock_get_mac):
        self.assertEqual(XlinkConnector._create_node_id("1"), '02e187548c80-1')

    @patch('vision.node_communicator.xlink_connector.get_mac_address', return_value='02-e1-87-54-8c-80')
    def test_create_node_id_with_valid_mac_windows(self, mock_get_mac):
        self.assertEqual(XlinkConnector._create_node_id("1"), '02e187548c80-1')

    @patch('vision.node_communicator.xlink_connector.get_mac_address', return_value=None)
    def test_create_node_id_with_no_mac(self, mock_get_mac):
        self.assertEqual(XlinkConnector._create_node_id("1"), '000-1')

    @patch('vision.data_handler.data_handler.DataHandler.receive_xlink_message')
    def test_receive(self, receive_msg):
        self.xlink_connector.receive('mock_message')
        receive_msg.assert_called_once()

    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.send')
    def test_send_message(self, send_message):
        mock_xlink_wrapper = Mock()
        mock_xlink_wrapper.send
        mock_xlink = Mock()
        mock_xlink.xlink_wrapper = mock_xlink_wrapper
        mock_xlink.node_id = '389C0A'
        self.xlink_connector._xlink_list.append(mock_xlink)
        self.xlink_connector.send('mock_message', '389C0A')
        mock_xlink_wrapper.send.assert_called_once()

    @patch('inbm_vision_lib.checksum_validator.hash_message')
    def test_send_message_with_hash(self, hash_message):
        self.xlink_connector.send('mock_message', '389C0A')
        hash_message.assert_called_once()

    def test_send_message_fail(self):
        mock_xlink_wrapper = Mock()
        mock_xlink_wrapper.send = MagicMock(
            side_effect=XlinkWrapperException("Failed to send message"))
        mock_xlink = Mock()
        mock_xlink.xlink_wrapper = mock_xlink_wrapper
        mock_xlink.node_id = '389C0A'
        self.xlink_connector._xlink_list.append(mock_xlink)
        with self.assertRaises(XlinkWrapperException):
            self.xlink_connector.send('mock_message', '389C0A')
        mock_xlink_wrapper.send.assert_called_once()

    def test_send_file(self):
        mock_xlink_wrapper = Mock()
        mock_xlink_wrapper.send_file
        mock_xlink = Mock()
        mock_xlink.xlink_wrapper = mock_xlink_wrapper
        mock_xlink.node_id = '123ABC'
        self.xlink_connector._xlink_list.append(mock_xlink)
        self.xlink_connector.send_file('123ABC', 'mock_filepath')
        mock_xlink_wrapper.send_file.assert_called_once()

    def test_raise_exception_when_unable_to_send_file(self):
        mock_xlink_wrapper = Mock()
        mock_xlink_wrapper.send_file = MagicMock(
            side_effect=XlinkWrapperException("Failed to send file"))
        mock_xlink = Mock()
        mock_xlink.xlink_wrapper = mock_xlink_wrapper
        mock_xlink.node_id = '123ABC'
        self.xlink_connector._xlink_list.append(mock_xlink)
        with self.assertRaises(XlinkWrapperException):
            self.xlink_connector.send_file('123ABC', 'mock_filepath')
        mock_xlink_wrapper.send_file.assert_called_once()

    def test_stop_listen_to_channel(self):
        mock_xlink_public = Mock()
        mock_xlink_public.xlink_wrapper.stop
        self.xlink_connector._xlink_wrapper_public.append(mock_xlink_public)
        self.xlink_connector.stop()
        mock_xlink_public.xlink_wrapper.stop.assert_called_once()

    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.start')
    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.get_init_status', return_value=True)
    @patch('vision.node_communicator.xlink_connector.XlinkConnector._create_node_id', return_value='123ABC')
    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.get_device_id', return_value=16084061002)
    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.__init__', return_value=None)
    def test_add_xlink_wrapper_non_secure_xlink(self, init_wrapper, get_id, create_id, get_status, t_start):
        self.xlink_connector._add_xlink_wrapper(0x501, False, 1702321)
        self.assertEquals(len(self.xlink_connector._xlink_list), 1)
        init_wrapper.assert_called_once()
        get_id.assert_called_once()
        create_id.assert_called_once()
        get_status.assert_called_once()
        t_start.assert_called_once()

    @patch('inbm_vision_lib.xlink.xlink_secure_wrapper.XlinkSecureWrapper.start')
    @patch('inbm_vision_lib.xlink.xlink_secure_wrapper.XlinkSecureWrapper.get_init_status', return_value=True)
    @patch('vision.node_communicator.xlink_connector.XlinkConnector._create_node_id', return_value='123ABC')
    @patch('inbm_vision_lib.xlink.xlink_secure_wrapper.XlinkSecureWrapper.get_device_id',
           return_value=16084061002)
    @patch('inbm_vision_lib.xlink.xlink_secure_wrapper.XlinkSecureWrapper.__init__', return_value=None)
    @patch('os.path.exists', return_value=True)
    def test_add_xlink_wrapper_secure_xlink(self, is_secure, init_wrapper, get_id, create_id, get_status, t_start):
        self.xlink_connector._add_xlink_wrapper(0x501, True, 1702321)
        self.assertEquals(len(self.xlink_connector._xlink_list), 1)
        is_secure.assert_called_once()
        init_wrapper.assert_called_once()
        get_id.assert_called_once()
        create_id.assert_called_once()
        get_status.assert_called_once()
        t_start.assert_called_once()

    def test_reset_device_pass(self):
        mock_xlink_wrapper_pub = Mock()
        mock_xlink_wrapper_pub.get_platform_type = MagicMock(return_value=KMB)
        mock_xlink_pub = XlinkPublic(mock_xlink_wrapper_pub, 0x501, "123ABC")
        self.xlink_connector._xlink_wrapper_public.append(mock_xlink_pub)

        mock_xlink_wrapper = Mock()
        mock_xlink_wrapper.reset_device
        mock_xlink = Xlink(mock_xlink_wrapper, 0x501, "123ABC")
        self.xlink_connector._xlink_list.append(mock_xlink)
        self.xlink_connector.reset_device("123ABC")
        mock_xlink_wrapper.reset_device.assert_called_once()

    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.reset_device')
    def test_reset_device_fail(self, boot_device):
        mock_xlink = Xlink(Mock(), 0x501, "123ABC")
        self.xlink_connector._xlink_list.append(mock_xlink)
        self.xlink_connector.reset_device("456DEF")
        boot_device.assert_not_called()

    def test_raise_exception_when_reset_device_fails(self):
        mock_xlink_wrapper_pub = Mock()
        mock_xlink_wrapper_pub.get_platform_type = MagicMock(return_value=KMB)
        mock_xlink_pub = XlinkPublic(mock_xlink_wrapper_pub, 0x501, "456DEF")
        self.xlink_connector._xlink_wrapper_public.append(mock_xlink_pub)

        mock_xlink_wrapper = Mock()
        mock_xlink_wrapper.reset_device = MagicMock(
            side_effect=XlinkWrapperException("Failed to boot device"))
        mock_xlink = Xlink(mock_xlink_wrapper, 0x501, "456DEF")
        self.xlink_connector._xlink_list.append(mock_xlink)
        with self.assertRaises(XlinkWrapperException):
            self.xlink_connector.reset_device("456DEF")
        mock_xlink_wrapper.reset_device.assert_called_once()

    @patch('os.path.exists', return_value=False)
    def test_add_xlink_wrapper_secure_xlink_error(self, is_secure):
        self.xlink_connector._add_xlink_wrapper(0x501, True, 1702321)
        self.assertEquals(len(self.xlink_connector._xlink_list), 0)
        is_secure.assert_called_once()

    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.start')
    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.__init__', return_value=None)
    def test_disconnect_channel(self, init_xlink, start_listen):
        mock_xlink_wrapper = Mock()
        mock_xlink_wrapper.stop
        mock_xlink = Xlink(mock_xlink_wrapper, 0x501, "123ABC")
        self.xlink_connector._xlink_list.append(mock_xlink)
        mock_xlink_public = XlinkPublic(mock_xlink_wrapper, 0x501, "123ABC")
        self.xlink_connector._xlink_wrapper_public.append(mock_xlink_public)
        self.xlink_connector._disconnect_channel("123ABC")
        assert mock_xlink_wrapper.stop.call_count == 2
        self.assertEqual(len(self.xlink_connector._xlink_list), 0)

    @patch('threading.Thread.start')
    def test_check_xlink_device_status(self, thread_start):
        mock_xlink_public = Mock()
        mock_xlink_public.xlink_wrapper
        mock_xlink_public.xlink_pcie_dev_id
        mock_xlink_public.node_id
        self.xlink_connector._xlink_wrapper_public.append(mock_xlink_public)
        self.xlink_connector._check_xlink_device_status()

    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.start')
    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.__init__', return_value=None)
    def test_reconnect_public_with_node_xlink_dev_id(self, init_wrapper, listen_start):
        mock_xlink_public = Mock()
        mock_xlink_public.xlink_wrapper
        mock_xlink_public.xlink_wrapper.stop
        mock_xlink_public.xlink_pcie_dev_id = 1709876
        mock_xlink_public.node_id = None
        self.xlink_connector._xlink_wrapper_public.append(mock_xlink_public)
        self.xlink_connector._reconnect_public(node_xlink_dev_id=1709876)
        mock_xlink_public.xlink_wrapper.start.assert_called_once()
        init_wrapper.assert_called_once()
        listen_start.assert_called_once()

    @patch('vision.node_communicator.xlink_connector.XlinkConnector._restore_channel')
    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.start')
    @patch('inbm_vision_lib.xlink.xlink_wrapper.XlinkWrapper.__init__', return_value=None)
    def test_reconnect_public_with_node_id(self, init_wrapper, listen_start, restore_chl):
        mock_xlink_public = Mock()
        mock_xlink_public.xlink_wrapper
        mock_xlink_public.xlink_wrapper.stop
        mock_xlink_public.xlink_pcie_dev_id = 1709876
        mock_xlink_public.node_id = "1709876-14112"
        self.xlink_connector._xlink_wrapper_public.append(mock_xlink_public)
        mock_xlink_wrapper = Mock()
        mock_xlink_wrapper.stop
        mock_xlink = Xlink(mock_xlink_wrapper, 0x501, "1709876-14112")
        self.xlink_connector._xlink_list.append(mock_xlink)
        self.xlink_connector._reconnect_public(None, sw_dev_id="14112")
        restore_chl.assert_called_once()
        mock_xlink_public.xlink_wrapper.start.assert_called_once()
        init_wrapper.assert_called_once()
        listen_start.assert_called_once()
        mock_xlink_wrapper.stop.assert_called_once()
        self.assertEqual(self.xlink_connector._xlink_list, [])

    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_check_single_xlink(self, mock_add):
        mock_xlink_public = Mock()
        mock_xlink_public.xlink_wrapper
        mock_xlink_public.xlink_wrapper.get_xlink_device_status = MagicMock(return_value=0)
        mock_xlink_public.xlink_pcie_dev_id = 1709876
        mock_xlink_public.node_id = "1709876-14112"
        self.xlink_connector._check_single_xlink(mock_xlink_public)
        mock_xlink_public.xlink_wrapper.get_xlink_device_status.assert_called_once()

    def test_get_free_channel(self):
        self.assertIsNotNone(self.xlink_connector._get_free_channel())

    def test_raises_when_no_free_channel(self):
        self.xlink_connector._channel_list.clear()
        with self.assertRaises(XlinkWrapperException):
            self.xlink_connector._get_free_channel()

    def test_get_platform_type_pass(self):
        mock_xlink_wrapper = Mock()
        mock_xlink_wrapper.get_platform_type = MagicMock(return_value=TBH)
        mock_xlink = XlinkPublic(mock_xlink_wrapper, 0x501, "123ABC")
        self.xlink_connector._xlink_wrapper_public.append(mock_xlink)
        self.assertEqual(self.xlink_connector.get_platform_type("123ABC"), TBH)

    def test_get_platform_type_invalid_node(self):
        mock_xlink_wrapper = Mock()
        mock_xlink_wrapper.get_platform_type = MagicMock(return_value=TBH)
        mock_xlink = Xlink(mock_xlink_wrapper, 0x501, "123ABC")
        self.xlink_connector._xlink_list.append(mock_xlink)
        self.assertEqual(self.xlink_connector.get_platform_type("456DEF"), None)

    @patch('vision.node_communicator.xlink_connector.XlinkConnector._reconnect_public')
    def test_xlink_async_callback(self, reconnect_pub):
        sw_dev_id = 17036856
        event_id = 0
        self.assertEqual(self.xlink_connector._xlink_async_callback(
            sw_dev_id, event_id), X_LINK_SUCCESS)
        reconnect_pub.assert_called_once()

    def test_get_guid_when_no_node(self):
        self.assertEqual(self.xlink_connector.get_guid(17036856), ("0", "0"))

    @patch('vision.node_communicator.xlink_connector.filter_first_slice_from_list', return_value=[])
    @patch('vision.node_communicator.xlink_connector.get_all_xlink_pcie_device_ids', return_value=[])
    def test_get_all_guid_when_no_node(self, get_all, filter_first):
        self.assertEqual(self.xlink_connector.get_all_guid(), [])

    def test_is_provisioned_when_no_node(self):
        self.assertEqual(self.xlink_connector.is_provisioned(17036856), False)

    @patch('inbm_vision_lib.xlink.xlink_secure_wrapper.XlinkSecureWrapper.get_guid', side_effect=AttributeError("Error"))
    @patch('vision.node_communicator.xlink_connector.filter_first_slice_from_list', return_value=[12345])
    @patch('vision.node_communicator.xlink_connector.get_all_xlink_pcie_device_ids', return_value=[12345])
    def test_get_all_guid_raise_exception(self, get_all, filter_first, get_guid):
        self.assertEqual(self.xlink_connector.get_all_guid(), [])
