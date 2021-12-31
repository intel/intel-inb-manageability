from datetime import datetime
from unittest import TestCase

from mock import Mock, MagicMock
from mock import patch, mock_open
from inbm_vision_lib.configuration_manager import ConfigurationException
from inbm_common_lib.platform_info import PlatformInformation
from node.command.command import *
from node.command.configuration_command import ConfigValuesCommand, LoadConfigCommand, SendConfigResponseCommand
from inbm_vision_lib.constants import NODE
from node.node_exception import NodeException
from node.constant import *

Manifest = '<?xml version="1.0" encoding="utf-8"?><message>    <otaUpdate id="123AB">        ' \
           '<items>            <manifest>                <type>ota</type>                <ota>   ' \
           '' \
           '                 <header>                        <id>sampleId</id>                   ' \
           '' \
           '     <name>Sample FOTA</name>                        <description>Sample FOTA ' \
           'manifest file</description>                        <type>fota</type>                 ' \
           '' \
           '       <repo>local</repo>                    </header>                    <type>     ' \
           '' \
           '                   <fota name="sample">                            ' \
           '<fetch>/var/cache/manageability/X041_BIOS.tar</fetch>                            ' \
           '<biosversion>5.12</biosversion>                            <vendor>American ' \
           'Megatrends Inc.</vendor>                            <manufacturer>Default ' \
           'string</manufacturer>                            <product>Default string</product>   ' \
           '' \
           '                         <releasedate>2018-03-30</releasedate>                       ' \
           '' \
           '     <tooloptions>/p /b</tooloptions>                        </fota>                 ' \
           '' \
           '   </type>                </ota>            </manifest>        </items>    ' \
           '</otaUpdate></message>'

Message = 'Rebooting in 2sec ...'

GET_ELEMENT_MESSAGE = ['registrationRetryTimerSecs']

SET_ELEMENT_MESSAGE = ['registrationRetryTimerSecs:50']

OTA_ELEMENT_MESSAGE = 'registrationRetryTimerSecs:50'

GET_CMD = 'getConfigValues'

SET_CMD = 'setConfigValues'

INVALID_CONFIG_CMD = 'resetConfigValues'

Expected_manifest = ''


class TestRequestToDownloadCommand(TestCase):

    def setUp(self):
        self.mock_xlink = Mock()
        self.mock_xlink.send
        self.Command = RequestToDownloadCommand("123ABC", self.mock_xlink, "1600")

    def test_execute(self):
        self.Command.execute()
        self.mock_xlink.send.assert_called_once()

    def test_SendDownloadFalse(self):
        self.Command = RequestToDownloadCommand("123ABC", self.mock_xlink, "9160000000000")
        self.Command.execute()
        self.mock_xlink.send.assert_called_once()


class TestRegisterCommand(TestCase):

    def setUp(self):
        self.mock_xlink = Mock()
        self.mock_xlink.send
        self.Command = RegisterCommand(self.mock_xlink)

    @patch('node.command.command.get_version', return_value='bit-creek-2.13.2-r1.aarch64')
    @patch('node.command.command.RegisterCommand._get_fw_data', return_value=(PlatformInformation(
        datetime(2018, 6, 22, 0, 0, 0), u'American Megatrends Inc.', u'5.12', u'Uzelinfo', u'intel')))
    def test_execute(self, mock_fw_data, get_version):
        self.Command.execute()
        mock_fw_data.assert_called_once()
        get_version.assert_called_once()
        self.mock_xlink.send.assert_called_once()

    @patch('node.command.command.RegisterCommand._get_fw_data', return_value=(
        u'American Megatrends Inc.', u'5.12', datetime(2018, 6, 22, 0, 0, 0), u'Uzelinfo'))
    @patch('platform.version', return_value="#74~18.04.2-Ubuntu SMP Fri Feb 5 11:17:31 UTC 2021")
    def test_get_os_data_ubuntu(self, mock_platform, mock_fw_data):
        os_version, os_type, os_release_date = self.Command._get_os_data()
        self.assertEquals(os_type, "Ubuntu")
        self.assertEquals(os_version, "18.04.2")

    @patch('platform.platform', return_value='Linux-5.4.45-intel-standard-aarch64-with-glibc2.17')
    @patch('node.command.command.read_current_mender_version', return_value='Release-20210209021447')
    @patch('platform.version', return_value='#1 SMP PREEMPT Tue Feb 9 02:22:13 UTC 2021')
    def test_get_os_data_arm(self, mock_version, mock_mender, mock_platform):
        os_version, os_type, os_release_date = self.Command._get_os_data()
        self.assertEqual(os_type, 'Yocto')
        self.assertEquals(os_version, '1')
        self.assertEquals(os_release_date, '2-9-2021-2-14-47')

    @patch('platform.platform', return_value='Linux-5.4.45-intel-standard-aarch64-with-glibc2.17')
    @patch('node.command.command.RegisterCommand._get_os_release_date_from_version_file', return_value='20210207025149')
    @patch('platform.version', return_value='#1 SMP PREEMPT Tue Feb 9 02:22:13 UTC 2021')
    def test_get_os_data_arm_no_mender(self, mock_version, mock_release_date, mock_platform):
        os_version, os_type, os_release_date = self.Command._get_os_data()
        self.assertEqual(os_type, 'Yocto')
        self.assertEquals(os_version, '1')
        self.assertEquals(os_release_date, '20210207025149')

    def test_get_os_release_date_from_version_file(self):
        with patch("builtins.open", mock_open(read_data="20201209083327")) as mock_file:
            self.assertEqual(self.Command._get_os_release_date_from_version_file(),
                             "12-9-2020-8-33-27")

    def test_get_os_release_date_from_version_file_with_error(self):
        with patch("builtins.open", side_effect=FileNotFoundError):
            self.assertIsNone(self.Command._get_os_release_date_from_version_file())

    def test_get_board_info_with_non_existent_path(self):
        stepping, sku, model, serial_num = self.Command._get_board_info()
        self.assertIsNone(stepping)
        self.assertIsNone(sku)
        self.assertIsNone(model)
        self.assertIsNone(serial_num)

    @patch('os.path.exists')
    def test_get_board_info(self, path_exist):
        with patch("builtins.open", mock_open(read_data="A0")) as mock_file:
            stepping, sku, model, serial_num = self.Command._get_board_info()
        self.assertEqual(stepping, "A0")
        assert path_exist.call_count == 4


class TestSendHeartbeatCommand(TestCase):

    def setUp(self):
        self.mock_xlink = Mock()
        self.mock_xlink.send
        self.Command = SendHeartbeatCommand("123ABC", self.mock_xlink)

    def test_execute(self):
        self.Command.execute()
        self.mock_xlink.send.assert_called_once()


class TestSendDownloadStatusCommand(TestCase):

    def setUp(self):
        self.mock_xlink = Mock()
        self.mock_xlink.send
        self.Command = SendDownloadStatusCommand("123ABC", self.mock_xlink, "True")

    def test_execute(self):
        self.Command.execute()
        self.mock_xlink.send.assert_called_once()


class TestSendManifestCommand(TestCase):

    def setUp(self):
        self.mock_xlink = Mock()
        self.mock_xlink.send
        self.mock_broker = Mock()
        self.mock_broker.push_ota
        self.Command = SendManifestCommand("123ABC", self.mock_broker, Manifest)

    def test_execute(self):
        self.Command.execute()
        self.mock_broker.push_ota.assert_called_once()


class TestSendTelemetryEventCommand(TestCase):

    def setUp(self):
        self.mock_xlink = Mock()
        self.mock_xlink.send
        self.Command = SendTelemetryEventCommand("123ABC", self.mock_xlink, Message)

    def test_execute(self):
        self.Command.execute()
        self.mock_xlink.send.assert_called_once()

    def test_execute_throw_exception(self):
        self.Command.xlink_manager = None
        self.assertRaises(NodeException, self.Command.execute)


class TestSendOtaResultCommand(TestCase):

    def setUp(self):
        self.mock_xlink = Mock()
        self.mock_xlink.send
        self.Command = SendOtaResultCommand("123ABC", self.mock_xlink, Message)

    def test_execute(self):
        self.Command.execute()
        self.mock_xlink.send.assert_called_once()

    def test_execute_throw_exception(self):
        self.Command.xlink_manager = None
        self.assertRaises(NodeException, self.Command.execute)


class TestGetConfigValuesCommand(TestCase):
    """Test GetConfigValuesCommand."""

    def setUp(self):
        """Setup test GetConfigValues."""
        self.mock_xlink = Mock()
        self.mock_xlink.send
        self.mock_config_mgr = Mock()
        self.mock_config_mgr.get_element = MagicMock(return_value='20')
        self.Command = ConfigValuesCommand(
            "123ABC", self.mock_xlink, self.mock_config_mgr, GET_ELEMENT_MESSAGE, GET_CMD, NODE)
        self.invalid_command = ConfigValuesCommand(
            "123ABC", self.mock_xlink, self.mock_config_mgr, GET_ELEMENT_MESSAGE, INVALID_CONFIG_CMD, NODE)

    def test_execute(self):
        """Execute GetConfigvalue."""
        self.Command.execute()
        self.assertEqual(self.mock_xlink.send.call_count, 1)

    def test_execute_throw_exception(self):
        self.Command.xlink_manager = None
        self.assertRaises(NodeException, self.Command.execute)

    def test_execute_get_element_error_throw_exception(self):
        self.Command.xlink_manager = None
        self.mock_config_mgr.get_element = MagicMock(
            side_effect=ConfigurationException("Failed to get element"))
        self.assertRaises(NodeException, self.Command.execute)

    def test_execute_invalid_command_throw_exception(self):
        self.assertRaises(NodeException, self.invalid_command.execute)


class TestSetConfigValuesCommand(TestCase):
    """Test SetConfigValuesCommand."""

    @patch('inbm_vision_lib.configuration_manager.ConfigurationManager')
    def setUp(self, config_mngr):
        """Setup test SetConfigValues."""
        self.mock_xlink = Mock()
        self.mock_xlink.send
        self.Command = ConfigValuesCommand(
            "123ABC", self.mock_xlink, config_mngr, SET_ELEMENT_MESSAGE, SET_CMD, NODE)

    def test_execute(self):
        """Execute SetConfigvalue."""
        self.Command.execute()
        self.assertEqual(self.mock_xlink.send.call_count, 1)


class TestLoadConfigCommand(TestCase):
    """Test SetConfigValuesCommand."""

    def setUp(self):
        """Setup test loadConfig."""
        self.mock_xlink = Mock()
        self.mock_xlink.send
        self.mock_path = Mock()
        self.config_mgr = Mock()
        self.config_mgr.load
        self.Command = LoadConfigCommand(
            "123ABC", self.mock_xlink, self.config_mgr, self.mock_path, NODE)

    @patch('os.path.isfile', return_value=True)
    @patch('os.path.exists', return_value=True)
    @patch('os.remove')
    def test_execute(self, mock_remove, mock_exists, mock_is_file):
        """Execute SetConfigvalue."""
        self.Command.execute()
        self.assertEqual(self.mock_xlink.send.call_count, 1)
        mock_remove.assert_called_once()

    @patch('os.path.isfile', return_value=True)
    @patch('os.path.exists', return_value=True)
    @patch('os.remove')
    @patch('logging.Logger.error')
    def test_execute_throw_configuration_exception(self, mock_logger, mock_remove, mock_exists, mock_is_file):
        self.mock_xlink = Mock()
        self.mock_xlink.send
        self.mock_path = Mock()
        self.config_mgr = Mock()
        self.config_mgr.load = MagicMock(side_effect=ConfigurationException)
        self.Command = LoadConfigCommand(
            "123ABC", self.mock_xlink, self.config_mgr, self.mock_path, NODE)
        self.Command.execute()
        self.config_mgr.load.assert_called_once()
        mock_logger.assert_called_once()
        mock_remove.assert_called_once()

    @patch('os.path.isfile', return_value=True)
    @patch('os.path.exists', return_value=True)
    @patch('os.remove')
    def test_execute_throw_node_exception(self, mock_remove, mock_exists, mock_is_file):
        self.Command.xlink_manager = None
        self.assertRaises(NodeException, self.Command.execute)
        mock_remove.assert_called_once()


class SendOtaClientCommandTest(TestCase):
    """Test SetConfigValuesCommand."""

    @patch('inbm_vision_lib.configuration_manager.ConfigurationManager')
    def setUp(self, config_mngr):
        self.mock_broker = Mock()
        self.mock_broker.push_ota
        self.Command = SendOtaClientConfigurationCommand(
            self.mock_broker, OTA_ELEMENT_MESSAGE, "set")

    def test_execute(self):
        """Execute SetConfigvalue."""
        self.Command.execute()
        self.assertEqual(self.mock_broker.push_ota.call_count, 1)


class SendConfigResponseCommandTest(TestCase):
    def setUp(self):
        self.mock_xlink = Mock()
        self.mock_xlink.send
        self.Command = SendConfigResponseCommand('123', self.mock_xlink, "success")

    def test_execute(self):
        self.Command.execute()
        self.assertEqual(self.mock_xlink.send.call_count, 1)
