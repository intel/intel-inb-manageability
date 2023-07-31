from unittest import TestCase
from mock import patch, Mock
from inbc.broker import Broker
from inbc.parser import ArgsParser
from inbm_common_lib.request_message_constants import *


class TestINBC(TestCase):
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    def setUp(self, mock_subscribe, mock_publish, mock_connect):
        self.arg_parser = ArgsParser()
        self._aota_args = self.arg_parser.parse_args(
            ['aota', '-a', 'application', '-c', 'update', '-u', 'https://abc.com/test.deb'])
        self._fota_args = self.arg_parser.parse_args(
            ['fota', '-u', 'https://abc.com/BIOS.img'])
        self._sota_args = self.arg_parser.parse_args(
            ['sota', '-u', 'https://abc.com/test.mender'])
        self._pota_args = self.arg_parser.parse_args(
            ['pota', '-fu', 'https://abc.com/BIOS.img', '-su', 'https://abc.com/test.mender'])
        self._get_inbm_args = self.arg_parser.parse_args(
            ['get', '-p', 'maxCacheSize'])
        self._set_inbm_args = self.arg_parser.parse_args(
                ['set', '-p', 'maxCacheSize:100'])
        self._load_args = self.arg_parser.parse_args(
            ['load', '-u', 'https://abc.com/intel_configuration.xml'])
        self._restart_args = self.arg_parser.parse_args(['restart'])

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.ota_command.SotaCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    def test_on_event_sota_failure(self, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('sota', self._sota_args, False)
        b._on_event('manageability/event', SOTA_COMMAND_FAILURE, 1)
        mock_terminate.assert_called_once()

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.ota_command.FotaCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    def test_on_event(self, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('fota', self._fota_args, False)
        b._on_event('manageability/event', 'Overall FOTA status : SUCCESS', 1)

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.ota_command.FotaCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    def test_on_event(self, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('aota', self._aota_args, False)
        b._on_event('manageability/event', 'Overall AOTA status : SUCCESS', 1)

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.ota_command.AotaCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    def test_on_message_response_aota_success(self, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('aota', self._aota_args, False)
        b._on_response('manageability/response', SUCCESSFUL_INSTALL, 1)
        mock_terminate.assert_called_once()

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.ota_command.AotaCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    def test_on_message_response_aota_failed(self, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('aota', self._fota_args, False)
        b._on_response('manageability/response', FAILED_TO_INSTALL, 1)
        mock_terminate.assert_called_once()

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.ota_command.FotaCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    def test_on_message_response(self, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('fota', self._fota_args, False)
        b._on_event('manageability/event', 'Overall FOTA status : SUCCESS', 1)

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.ota_command.FotaCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    def test_on_message_response_fota_success(self, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('fota', self._fota_args, False)
        b._on_response('manageability/response', SUCCESSFUL_INSTALL, 1)
        mock_terminate.assert_called_once()

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.ota_command.FotaCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    def test_on_message_response_fota_failed(self, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('fota', self._fota_args, False)
        b._on_response('manageability/response', FAILED_TO_INSTALL, 1)
        mock_terminate.assert_called_once()

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.ota_command.PotaCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    def test_on_message_response_pota_failed(self, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('pota', self._pota_args, False)
        b._on_response('manageability/response', FAILED_TO_INSTALL, 1)
        #mock_terminate.assert_called_once()

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.ota_command.SotaCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    def test_on_message_response_sota_failed(self, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('sota', self._sota_args, False)
        b._on_response('manageability/response', OTA_FAILURE, 1)
        mock_terminate.assert_called_once()

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.config_command.GetConfigCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    def test_on_message_response_get_inbm_success(self, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('get', self._get_inbm_args, False)
        b._on_response('manageability/response', 'Configuration command: SUCCESSFUL', 1)
        mock_terminate.assert_called_once()

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.config_command.GetConfigCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    def test_on_message_response_get_inbm_failed(self, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('get', self._get_inbm_args, False)
        b._on_response('manageability/response', 'Configuration command: FAILED', 1)
        mock_terminate.assert_called_once()

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.config_command.GetConfigCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    def test_on_message_response_set_inbm_success(self, mock_terminate, mock_trigger,
                                                  mock_sub, mock_pub, mock_con, mock_reconnect):
        b = Broker('set', self._set_inbm_args, False)
        b._on_response('manageability/response', 'Configuration command: SUCCESSFUL', 1)
        mock_terminate.assert_called_once()

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.config_command.GetConfigCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    def test_on_message_response_set_inbm_failed(self, mock_terminate, mock_trigger, mock_sub, mock_pub,
                                            mock_con, mock_reconnect):
        b = Broker('set', self._set_inbm_args, False)
        b._on_response('manageability/response', 'Configuration command: FAILED', 1)
        mock_terminate.assert_called_once()

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.config_command.LoadConfigCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    def test_on_message_response_load_success(self, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('load', self._load_args, False)
        b._on_response('manageability/response', 'Configuration command: SUCCESSFUL', 1)
        mock_terminate.assert_called_once()

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.config_command.LoadConfigCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    def test_on_message_response_load_failed(self, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('load', self._load_args, False)
        b._on_response('manageability/response', 'Configuration command: FAILED', 1)
        mock_terminate.assert_called_once()

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.command.RestartCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    def test_on_message_response_restart_success(self, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('restart', self._restart_args, False)
        b._on_response('manageability/response', 'Restart Command Success', 1)
        mock_terminate.assert_called_once()

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.command.RestartCommand.trigger_manifest')
    @patch('inbc.command.command.Command.terminate_operation')
    def test_on_message_response_restart_failed(self, mock_terminate, mock_trigger, mock_sub, mock_pub, mock_con):
        b = Broker('restart', self._restart_args, False)
        b._on_response('manageability/response', 'Restart FAILED', 1)
        mock_terminate.assert_called_once()

    @patch('inbc.command.command.Command.search_response')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.ota_command.FotaCommand.trigger_manifest')
    def test_on_message_response(self, mock_trigger, mock_sub, mock_pub, mock_con, mock_search):
        b = Broker('fota', self._fota_args, False)
        b._on_response('manageability/response', 'check', 1)
        mock_search.assert_called_once()

    @patch('inbc.command.command.Command.stop_timer')
    @patch('inbm_lib.mqttclient.mqtt.mqtt')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.ota_command.FotaCommand.trigger_manifest')
    def test_on_stop_broker(self, mock_trigger, mock_sub, mock_pub, mock_con, mock_mqtt, mock_timer):
        b = Broker('fota', self._fota_args, False)
        b.stop_broker()
        mock_timer.assert_called_once()
