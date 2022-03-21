from unittest import TestCase

from typing import Dict, Any
from inbm_vision_lib.invoker import Invoker
from mock import Mock, patch
from node.command.command import RegisterCommand
from node.data_handler import DataHandler
from node.heartbeat_timer import HeartbeatTimer
from node.node import Node
from inbm_vision_lib.configuration_manager import ConfigurationManager
from node.node_exception import NodeException
from node.command.configuration_command import ConfigValuesCommand, LoadConfigCommand, SendConfigResponseCommand
from node.command.command import SendOtaClientConfigurationCommand

import os

mock_node = Mock()
queue_size = 10

TEST_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                    '../../../fpm-template/usr/share/node-agent/' +
                                    'intel_manageability_node_schema.xsd')

CONFIG_LOCATION = os.path.join(os.path.dirname(__file__),
                               '../../../fpm-template/etc/intel-manageability/public/node-agent/intel_manageability_node.conf')

RequestToDownload_message = '<?xml version="1.0" encoding="utf-8"?><message>    ' \
                            '<requestToDownload id="389C0A">        ' \
                            '<items>            <size_kb>16385</size_kb>        </items>    ' \
                            '</requestToDownload></message>::123 '

registerResponse_message = '<?xml version="1.0" encoding="utf-8"?><message>    <registerResponse ' \
                           '' \
                           'id="389C0A">        <heartbeatIntervalSecs>5</heartbeatIntervalSecs>  ' \
                           '' \
                           '  </registerResponse></message>::123'

isAlive_message = '<?xml version="1.0" encoding="utf-8"?><message>    <isAlive ' \
                  'id="389C0A"/></message>::123'

otaUpdate_message = '<?xml version="1.0" encoding="utf-8"?><message>    <otaUpdate id="389C0A">   ' \
                    '' \
                    '     <items>            <manifest>                <type>ota</type>          ' \
                    '' \
                    '      <ota>                    <header>                        ' \
                    '<id>sampleId</id>                        <name>Sample FOTA</name>           ' \
                    '' \
                    '             <description>Sample FOTA manifest file</description>           ' \
                    '' \
                    '             <type>fota</type>                        <repo>local</repo>    ' \
                    '' \
                    '                </header>                    <type>                        ' \
                    '<fota name="sample">                            ' \
                    '<fetch>/var/cache/manageability/X041_BIOS.tar</fetch>                       ' \
                    '' \
                    '     <biosversion>5.12</biosversion>                            ' \
                    '<vendor>American Megatrends Inc.</vendor>                            ' \
                    '<manufacturer>Default string</manufacturer>                            ' \
                    '<product>Default string</product>                            ' \
                    '<releasedate>2018-03-30</releasedate>                            ' \
                    '<tooloptions>/p /b</tooloptions>                        </fota>             ' \
                    '' \
                    '       </type>                </ota>            </manifest>        </items> ' \
                    '' \
                    '   </otaUpdate></message>::123'

failed_message = '<?xml version="1.0" encoding="utf-8"?><message>    <isAlive ' \
                 'id="None"/></message>::123'

message = 'Rebooting in 2sec'

HEARTBEAT_RESPONSE = '<?xml version="1.0" encoding="utf-8"?><message><registerResponse id="389C0A"><heartbeatIntervalSecs>60</heartbeatIntervalSecs></registerResponse></message>'


class TestDataHandler(TestCase):

    @patch('threading.Thread.start')
    def setUp(self, t_start):
        self._node = Node()
        self._invoker = Invoker(queue_size)
        self._schema_location = TEST_SCHEMA_LOCATION
        is_file = True
        self._config = ConfigurationManager(CONFIG_LOCATION, is_file, self._schema_location)
        self._config.get_root()
        self.data_handler = DataHandler(self._node, self._config)
        self.data_handler._nid = "389C0A"
        mock_xlink = Mock()
        mock_xlink.node_data_handler = self.data_handler
        self.registry_cmd = RegisterCommand(mock_xlink)
        self.registry_cmd._get_hddl_data()
        self.assertEqual(t_start.call_count, 2)

    def test_validate_key_successful(self):
        try:
            self.data_handler._validate_key('registrationRetryTimerSecs')
        except NodeException:
            self.fail("Raised exception when not expected.")

    def test_validate_key_raises_invalid_key(self):
        with self.assertRaises(NodeException):
            self.data_handler._validate_key('invalid')

    @patch('threading.Thread.start')
    def test_downloaded_file_false(self, t_start):
        self.data_handler.downloaded_file("X041_BIOS.tar", False)

    @patch('node.xlink_parser.XLinkParser.parse', return_value=['requestToDownload', '389C0A', None,
                                                                otaUpdate_message, None])
    @patch('node.data_handler.DataHandler._validate_xlink_message')
    @patch('inbm_vision_lib.checksum_validator.validate_message',
           return_value=True)
    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_otaUpdate_command(self, add_cmd, t_start, validate_hash, validate_xlink, mock_parse):
        self.data_handler.receive_xlink_message(otaUpdate_message)
        add_cmd.assert_called_once()

    @patch('node.xlink_parser.XLinkParser.parse', return_value=['requestToDownload', '389C0A', '16385',
                                                                RequestToDownload_message, None])
    @patch('node.data_handler.DataHandler._validate_xlink_message')
    @patch('inbm_vision_lib.checksum_validator.validate_message',
           return_value=True)
    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_request_to_download_command(self, add_cmd, t_start, validate_hash, validate_xlink, mock_xml):
        self.data_handler.receive_xlink_message(RequestToDownload_message)
        add_cmd.assert_called_once()

    @patch('node.xlink_parser.XLinkParser.parse', return_value=['isAlive', '389C0A', '5',
                                                                isAlive_message, None])
    @patch('node.data_handler.DataHandler._validate_xlink_message')
    @patch('inbm_vision_lib.checksum_validator.validate_message',
           return_value=True)
    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_isAlive_command(self, add_cmd, t_start, validate_hash, validate_xlink, mock_parse):
        self.data_handler.receive_xlink_message(isAlive_message)
        add_cmd.assert_called_once()

    @patch('node.xlink_parser.XLinkParser.parse', return_value=['registerResponse', '389C0A', '5',
                                                                registerResponse_message, None])
    @patch('node.data_handler.DataHandler._validate_xlink_message')
    @patch('inbm_vision_lib.checksum_validator.validate_message')
    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_register_response_command(self, add_cmd, t_start, cksum, mock_validate, mock_parse):
        self.data_handler.receive_xlink_message(registerResponse_message)
        add_cmd.assert_not_called()
        cksum.assert_called_once()

    @patch('node.xlink_parser.XLinkParser.parse', return_value=['registerResponse', '389C0A', '5',
                                                                registerResponse_message, None])
    @patch('node.data_handler.DataHandler._validate_xlink_message')
    @patch('node.heartbeat_timer.HeartbeatTimer.stop')
    @patch('inbm_vision_lib.checksum_validator.validate_message')
    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_register_response_command_new_value(self, add_cmd, t_start, cksum, t_stop, validate_xlink, mock_parse):
        self.data_handler._heartbeat = HeartbeatTimer(Mock(), Mock())
        self.data_handler.receive_xlink_message(registerResponse_message)
        cksum.assert_called_once()
        t_stop.assert_called_once()
        add_cmd.assert_not_called()

    @patch('node.xlink_parser.XLinkParser._check_nid', return_value=None)
    @patch('node.xlink_parser.XLinkParser.parse', return_value=['isAlive', None, None,
                                                                failed_message, None])
    @patch('node.data_handler.DataHandler._validate_xlink_message')
    @patch('inbm_vision_lib.checksum_validator.validate_message')
    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_command_fail(self, add_cmd, t_start, cksum, mock_validate, mock_parse, mock_get):
        self.data_handler.receive_xlink_message(failed_message)
        add_cmd.assert_not_called()
        cksum.assert_called_once()

    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_register(self, add_cmd, t_start):
        self.data_handler.register()
        add_cmd.assert_called_once()

    @patch('threading.Thread.start')
    @patch('node.heartbeat_timer.HeartbeatTimer.__init__', return_value=None)
    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_send_heartbeat(self, add_cmd, start_heartbeat, t_start):
        self.data_handler.send_heartbeat()
        add_cmd.assert_called_once()
        start_heartbeat.call_count == 2

    @patch('os.remove')
    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_receive_mqtt_message(self, add_cmd, t_start, mock_remove):
        self.data_handler.receive_mqtt_message(message)
        add_cmd.assert_called()

    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_receive_mqtt_result(self, add_cmd, t_start):
        self.data_handler.receive_mqtt_result(message)
        add_cmd.assert_called()

    @patch('node.xlink_parser.XLinkParser.parse', return_value=['isAlive', '389C0A', '389C0A',
                                                                isAlive_message, None])
    @patch('node.data_handler.DataHandler._validate_xlink_message')
    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.checksum_validator.validate_message')
    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_receive_xlink_message_validate_hash_called(self, add_cmd, validate_msg, t_start, validate_xlink, mock_parse):
        self.data_handler.receive_xlink_message(isAlive_message)
        validate_msg.assert_called_once()
        add_cmd.assert_called_once()

    @patch('node.xlink_parser.XLinkParser.parse', return_value=['isAlive', '389C0A', '389C0A',
                                                                isAlive_message, None])
    @patch('node.data_handler.DataHandler._validate_xlink_message')
    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.checksum_validator.hash_message',
           return_value="123")
    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_receive_xlink_message_validate_hash_success(self, add_cmd, hash_msg, t_start, validate_xlink, mock_parse):
        self.data_handler.receive_xlink_message(isAlive_message)
        add_cmd.assert_called_once()

    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.checksum_validator.hash_message',
           return_value="1234")
    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_receive_xlink_message_validate_hash_fail(self, add_cmd, hash_msg, t_start):
        self.data_handler.receive_xlink_message(isAlive_message)
        add_cmd.assert_called_once()

    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.invoker.Invoker.stop')
    @patch('node.heartbeat_timer.HeartbeatTimer.stop')
    def test_stop(self, hb_stop, invoker_stop, t_start):
        self.data_handler._timer = HeartbeatTimer(5, Mock())
        self.data_handler._invoker = self._invoker
        self.data_handler._heartbeat = HeartbeatTimer(5, Mock())
        self.data_handler.stop()
        self.assertEqual(hb_stop.call_count, 2)
        invoker_stop.assert_called_once()

    def test_validate_xlink_message_fail(self):
        self.assertRaises(NodeException,
                          self.data_handler._validate_xlink_message, "invalid manifest")

    @patch('node.heartbeat_timer.HeartbeatTimer.stop')
    def test_reset_heartbeat(self, hb_stop):
        def mock_callback():
            pass

        self.data_handler._heartbeat_interval = 100
        self.data_handler._retry_count = 100
        self.data_handler._heartbeat = HeartbeatTimer(
            self.data_handler._heartbeat_interval, mock_callback)
        self.data_handler._timer = HeartbeatTimer(
            self.data_handler._heartbeat_interval, mock_callback)
        self.data_handler.reset_heartbeat()
        self.assertIsNone(self.data_handler._heartbeat_interval)
        assert hb_stop.call_count == 2
        self.assertEqual(self.data_handler._retry_count, 0)

    def test_successfully_process_get_config_node_command(self):
        cmd = self.data_handler._process_configuration_command(
            "getConfigValues", "node", ['registrationRetryTimerSecs'])
        assert type(cmd is ConfigValuesCommand)

    def test_successfully_process_get_config_node_client_command(self):
        cmd = self.data_handler._process_configuration_command(
            "getConfigValues", "node_client", ['registrationRetryTimerSecs'])
        assert type(cmd is ConfigValuesCommand)

    def test_successfully_process_set_config_node_command(self):
        cmd = self.data_handler._process_configuration_command(
            "setConfigValues", "node", ['registrationRetryTimerSecs:30'])
        assert type(cmd is SendOtaClientConfigurationCommand)

    def test_successfully_process_set_config_node_client_command(self):
        cmd = self.data_handler._process_configuration_command(
            "setConfigValues", "node_client", ['registrationRetryTimerSecs:30'])
        assert type(cmd is SendOtaClientConfigurationCommand)

    def test_successfully_process_append_config_node_client_command(self):
        cmd = self.data_handler._process_configuration_command("appendConfigValues", "node_client",
                                                               ['registrationRetryTimerSecs:30'])
        assert type(cmd is SendOtaClientConfigurationCommand)

    def test_return_none_append_config_node_command(self):
        cmd = self.data_handler._process_configuration_command("appendConfigValues", "node",
                                                               ['registrationRetryTimerSecs:30'])
        self.assertEqual(cmd, None)

    def test_successfully_process_remove_config_node_client_command(self):
        cmd = self.data_handler._process_configuration_command("removeConfigValues", "node_client",
                                                               ['registrationRetryTimerSecs'])
        assert type(cmd is SendOtaClientConfigurationCommand)

    def test_return_none_remove_config_node_command(self):
        cmd = self.data_handler._process_configuration_command("removeConfigValues", "node",
                                                               ['registrationRetryTimerSecs'])
        self.assertEqual(cmd, None)

    def test_successfully_process_load_config_node_command(self):
        cmd = self.data_handler._process_configuration_command("load", "node",
                                                               '/var/cache/manageability/intel_manageability_node.conf')
        assert type(cmd is LoadConfigCommand)

    def test_successfully_process_load_config_node_client_command(self):
        cmd = self.data_handler._process_configuration_command("load", "node_client",
                                                               '/var/cache/manageability/intel_manageability_node.conf')
        assert type(cmd is SendOtaClientConfigurationCommand)

    def test_successfully_set_heartbeat_response_value(self):
        children: Dict[str, Any] = {"heartbeatResponseTimerSecs": '450'}
        self.data_handler.publish_config_value(children)
        self.assertEqual(450, self.data_handler._heartbeat_response)

    def test_set_default_value_when_heartbeat_response_value_out_of_bounds(self):
        children: Dict[str, Any] = {"heartbeatResponseTimerSecs": '30'}
        self.data_handler.publish_config_value(children)
        self.assertEqual(300, self.data_handler._heartbeat_response)

    def test_successfully_set_registration_retry_timer_secs(self):
        children: Dict[str, Any] = {"registrationRetryTimerSecs": '30'}
        self.data_handler.publish_config_value(children)
        self.assertEqual(30, self.data_handler._retry_timer)

    def test_set_default_value_when_registration_retry_timer_out_of_bounds(self):
        children: Dict[str, Any] = {"registrationRetryTimerSecs": '61'}
        self.data_handler.publish_config_value(children)
        self.assertEqual(20, self.data_handler._retry_timer)

    def test_successfully_set_registration_retry_limit(self):
        children: Dict[str, Any] = {"registrationRetryLimit": '6'}
        self.data_handler.publish_config_value(children)
        self.assertEqual(6, self.data_handler._retry_limit)

    def test_set_default_value_when_registration_retry_limit_out_of_bounds(self):
        children: Dict[str, Any] = {"registrationRetryLimit": '16'}
        self.data_handler.publish_config_value(children)
        self.assertEqual(8, self.data_handler._retry_limit)
