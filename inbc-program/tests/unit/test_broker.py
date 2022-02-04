from unittest import TestCase
from mock import patch, Mock
from inbc.broker import Broker
from inbc.parser import ArgsParser
from inbm_common_lib.request_message_constants import *


class TestINBC(TestCase):
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    def setUp(self, mock_subscribe, mock_publish, mock_connect):
        self.arg_parser = ArgsParser()
        self._fota_args = self.arg_parser.parse_args(
            ['fota', '-p', '/var/cache/manageability/repository-tool/BIOS.img', '--target', '123ABC', '456DEF'])
        self._sota_args = self.arg_parser.parse_args(
            ['sota', '-p', '/var/cache/manageability/repository-tool/BIOS.img', '-t', '123ABC', '456DEF'])
        self._pota_args = self.arg_parser.parse_args(
            ['pota', '-fp', './fip.bin', '-sp', './temp/test.mender', '--target', '123ABC', '456DEF'])
        self._get_vision_args = self.arg_parser.parse_args(
            ['get', '-p', '/var/cache/manageability/repository-tool/BIOS.img', '--targettype', 'vision'])
        self._get_inbm_args = self.arg_parser.parse_args(
            ['get', '--nohddl', '-p', 'maxCacheSize'])
        self._set_vision_args = self.arg_parser.parse_args(
            ['set', '-p', '/var/cache/manageability/repository-tool/BIOS.img', '-tt', 'node-client'])
        self._set_inbm_args = self.arg_parser.parse_args(
                ['set', '--nohddl', '-p', 'maxCacheSize:100'])
        self._load_args = self.arg_parser.parse_args(
            ['load', '-p', '/var/cach&e/manageability/repository-tool/BIOS.img', '-tt', 'node'])
        self._restart_args = self.arg_parser.parse_args(['restart'])

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.ota_command.SotaCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_on_vision_event_sota_failure(self, mock_agent, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('sota', self._sota_args, Mock(), False)
        b._on_vision_event('manageability/event', SOTA_COMMAND_FAILURE, 1)
        mock_terminate.assert_called_once()

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.ota_command.FotaCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_on_vision_event(self, mocak_agent, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('fota', self._fota_args, Mock(), False)
        b._on_vision_event('manageability/event', 'Overall FOTA status : SUCCESS', 1)

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.ota_command.FotaCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_on_message_response(self, mock_agent, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('fota', self._fota_args, Mock(), False)
        b._on_vision_event('manageability/response', 'Overall FOTA status : SUCCESS', 1)

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.ota_command.FotaCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_on_message_response_fota_success(self, mock_agent, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('fota', self._fota_args, Mock(), False)
        b._on_response('manageability/response', SUCCESSFUL_INSTALL, 1)
        mock_terminate.assert_called_once()

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.ota_command.FotaCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_on_message_response_fota_failed(self, mock_agent, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('fota', self._fota_args, Mock(), False)
        b._on_response('manageability/response', FAILED_TO_INSTALL, 1)
        mock_terminate.assert_called_once()

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.ota_command.PotaCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_on_message_response_pota_failed(self, mock_agent, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('pota', self._pota_args, Mock(), False)
        b._on_response('manageability/response', FAILED_TO_INSTALL, 1)
        mock_terminate.assert_called_once()

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.ota_command.SotaCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_on_message_response_sota_success(self, mock_agent, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('sota', self._sota_args, Mock(), False)
        b._on_response('manageability/response', SOTA_COMMAND_STATUS_SUCCESS, 1)
        mock_terminate.assert_called_once()

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.ota_command.SotaCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_on_message_response_sota_failed(self, mock_agent, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('sota', self._sota_args, Mock(), False)
        b._on_response('manageability/response', OTA_FAILURE, 1)
        mock_terminate.assert_called_once()

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.config_command.GetConfigCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_on_message_response_get_success(self, mock_agent, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('get', self._get_vision_args, Mock(), False)
        b._on_response('manageability/response', 'Configuration command: SUCCESSFUL', 1)
        mock_terminate.assert_called_once()

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.config_command.GetConfigCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_on_message_response_get_failed(self, mock_agent, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('get', self._get_vision_args, Mock(), False)
        b._on_response('manageability/response', 'Configuration command: FAILED', 1)
        mock_terminate.assert_called_once()

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.config_command.GetConfigCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=False)
    def test_on_message_response_get_inbm_success(self, mock_agent, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('get', self._get_inbm_args, Mock(), False)
        b._on_response('manageability/response', 'Configuration command: SUCCESSFUL', 1)
        mock_terminate.assert_called_once()

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.config_command.GetConfigCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=False)
    def test_on_message_response_get_inbm_failed(self, mock_agent, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('get', self._get_inbm_args, Mock(), False)
        b._on_response('manageability/response', 'Configuration command: FAILED', 1)
        mock_terminate.assert_called_once()

    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.config_command.GetConfigCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_on_message_response_set_success(self, mock_agent, mock_terminate, mock_trigger, mock_sub, mock_pub,
                                             mock_con, mock_thread):
        b = Broker('set', self._set_vision_args, Mock(), False)
        b._on_response('manageability/response', 'Configuration command: SUCCESSFUL', 1)
        mock_terminate.assert_called_once()

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.config_command.GetConfigCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_on_message_response_set_failed(self, mock_agent, mock_terminate, mock_trigger, mock_sub, mock_pub,
                                            mock_con, mock_reconnect):
        b = Broker('set', self._set_vision_args, Mock(), False)
        b._on_response('manageability/response', 'Configuration command: FAILED', 1)
        mock_terminate.assert_called_once()


    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.config_command.GetConfigCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=False)
    def test_on_message_response_set_inbm_success(self, mock_agent, mock_terminate, mock_trigger, mock_sub, mock_pub,
                                            mock_con, mock_reconnect):
        b = Broker('set', self._set_inbm_args, Mock(), False)
        b._on_response('manageability/response', 'Configuration command: SUCCESSFUL', 1)
        mock_terminate.assert_called_once()


    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.config_command.GetConfigCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=False)
    def test_on_message_response_seti_inbm_failed(self, mock_agent, mock_terminate, mock_trigger, mock_sub, mock_pub,
                                            mock_con, mock_reconnect):
        b = Broker('set', self._set_inbm_args, Mock(), False)
        b._on_response('manageability/response', 'Configuration command: FAILED', 1)
        mock_terminate.assert_called_once()


    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.config_command.LoadConfigCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_on_message_response_load_success(self, mock_agent, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('load', self._load_args, Mock(), False)
        b._on_response('manageability/response', 'Configuration command: SUCCESSFUL', 1)
        mock_terminate.assert_called_once()

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.config_command.LoadConfigCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_on_message_response_load_failed(self, mock_agnt, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('load', self._load_args, Mock(), False)
        b._on_response('manageability/response', 'Configuration command: FAILED', 1)
        mock_terminate.assert_called_once()

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.command.RestartCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_on_message_response_restart_success(self, mock_agent, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('restart', self._restart_args, Mock(), False)
        b._on_response('manageability/response', 'Restart Command Success', 1)
        mock_terminate.assert_called_once()

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.command.RestartCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_on_message_response_restart_failed(self, mock_agent, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('restart', self._restart_args, Mock(), False)
        b._on_response('manageability/response', 'Restart FAILED', 1)
        mock_terminate.assert_called_once()

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.ota_command.FotaCommand.trigger_manifest')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_on_message_response_num_of_targets(self, mock_agent, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('fota', self._fota_args, Mock(), False)
        payload = '{"status": "200", "message": "OTA_TARGETS:2"}'
        b._on_response('manageability/response', payload, 1)
        self.assertEquals(b._command._num_vision_targets, 2)

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.ota_command.FotaCommand.trigger_manifest')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_on_message_response_num_of_targets_ValueError(self, mock_agent, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('fota', self._fota_args, Mock(), False)
        payload = '{"status": "200", "message": "OTA_TARGETS:two"}'
        b._on_response('manageability/response', payload, 1)
        self.assertEquals(b._command._num_vision_targets, 1)


    @patch('inbc.command.command.Command.search_response')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.ota_command.FotaCommand.trigger_manifest')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_on_message_response(self, mock_agent, mock_trigger, mock_sub, mock_pub, mock_con, mock_search):
        b = Broker('fota', self._fota_args, Mock(), False)
        b._on_response('manageability/response', 'check', 1)
        mock_search.assert_called_once()

    @patch('inbc.utility.search_keyword', return_value= True)
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.ota_command.FotaCommand.trigger_manifest')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_on_status(self, mock_agent, mock_trigger, mock_sub, mock_pub, mock_con, mock_search):
        b = Broker('fota', self._fota_args, Mock(), False)
        b._on_status('manageability/response', 'check', 1)
                
                
                
