import datetime
from unittest import TestCase
from typing import Any

from vision.data_handler.data_handler import DataHandler
from vision.manifest_parser import ParsedManifest, TargetParsedManifest
from vision.constant import HEARTBEAT_ACTIVE_STATE, HEARTBEAT_IDLE_STATE, VisionException
from vision.constant import AGENT
from vision.configuration_constant import VISION_HB_CHECK_INTERVAL_SECS, NODE_HEARTBEAT_INTERVAL_SECS, \
    VISION_FOTA_TIMER, VISION_SOTA_TIMER, VISION_POTA_TIMER, IS_ALIVE_INTERVAL_SECS, VISION_HB_RETRY_LIMIT, \
    FLASHLESS_FILE_PATH
from inbm_common_lib.constants import CONFIG_LOAD
from inbm_vision_lib.constants import CONFIG_GET, CONFIG_SET
from inbm_vision_lib.configuration_manager import ConfigurationException
from mock import Mock, patch, MagicMock
from vision.ota_target import OtaTarget
from inbm_vision_lib.ota_parser import ParseException

RECEIVED_XML = '<manifest><type>cmd</type><cmd>provisionNode</cmd><provisionNode>' \
    '<blobPath>/var/cache/manageability/repository-tool/test.bin</blobPath>' \
               '<certPath>/var/cache/manageability/repository-tool/test.crt</certPath></provisionNode></manifest>'


class TestDataHandler(TestCase):

    @patch('inbm_vision_lib.xlink.xlink_library.XLinkLibrary.__init__', return_value=None)
    @patch('vision.data_handler.data_handler.DataHandler.load_config_file')
    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.timer.Timer.start')
    def setUp(self, timer_start, thread_start, load_file, mock_xlink_lib):
        mock_config_mgr = Mock()
        mock_config_mgr.get_children = MagicMock(return_value={'mock_key1': 10})
        mock_config_mgr.get_element = MagicMock(return_value=['Mock'])
        self.data_handler = DataHandler(Mock(), mock_config_mgr)
        self.assertEqual(timer_start.call_count, 2)
        thread_start.assert_called_once()
        load_file.assert_called_once()

    @patch('vision.manifest_parser.parse_manifest',
           return_value=ParsedManifest('provisionNode', {'blob_path': 'blob.bin', 'cert_path': 'path.crt'}, []))
    @patch('vision.data_handler.data_handler.move_file')
    def test_move_files_successfully(self, mock_move, mock_parse):
        self.data_handler.receive_provision_node_request(RECEIVED_XML)
        self.assertEqual(mock_move.call_count, 2)

    @patch('vision.manifest_parser.parse_manifest', side_effect=ParseException)
    @patch('inbm_common_lib.utility.move_file')
    def test_no_move_files_on_failure(self, mock_move, mock_parse):
        self.data_handler.receive_provision_node_request(RECEIVED_XML)
        self.assertEqual(mock_move.call_count, 0)

    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_send_node_register_response(self, add_cmd):
        self.data_handler.send_node_register_response("123ABC")
        add_cmd.assert_called_once()

    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_send_file(self, add_cmd):
        self.data_handler.send_file("123ABC", "mock_ota_file")
        assert add_cmd.call_count == 2

    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_send_ota_manifest(self, add_cmd):
        self.data_handler.send_ota_manifest("123ABC", "mock_manifest")
        add_cmd.assert_called_once()

    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_create_telemetry_event(self, add_cmd):
        self.data_handler.create_telemetry_event("123ABC", "Update success!")
        add_cmd.assert_called_once()

    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_send_heartbeat_response(self, add_cmd):
        self.data_handler.send_heartbeat_response("123ABC")
        add_cmd.assert_called_once()

    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_send_telemetry_response(self, add_cmd):
        self.data_handler.send_telemetry_response(
            "123ABC", {'status': '200', 'message': 'Update success!'})
        add_cmd.assert_called_once()

    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_create_download_request(self, add_cmd):
        file_size = 16000
        self.data_handler.create_download_request("123ABC", file_size)
        add_cmd.assert_called_once()

    node = Mock()
    node.heartbeat_status = HEARTBEAT_ACTIVE_STATE

    @patch("vision.data_handler.data_handler.validate_file_type")
    @patch('tarfile.open')
    @patch('os.remove')
    @patch('vision.data_handler.request_data_handler.FotaDataHandler.get_validated_node_ids', return_value=['123ABC'])
    @patch('vision.registry_manager.RegistryManager.get_device', return_value=(node, Mock()))
    @patch('inbm_vision_lib.invoker.Invoker.add')
    @patch('vision.updater.FotaUpdater.__init__', return_value=None)
    @patch('vision.manifest_parser.parse_manifest', return_value=ParsedManifest('fota', {'path': '/var/intel-manageability'}, ['123ABC']))
    def test_receive_mqtt_message_pass(self, parse_manifest, updater_init, add_cmd, get_dev, validate_node,
                                       mock_remove, mock_tar, validate_file):
        self.data_handler.receive_mqtt_message("mock_payload")
        parse_manifest.assert_called_once()
        updater_init.assert_called_once()
        assert add_cmd.call_count == 2
        get_dev.assert_called_once()
        validate_node.assert_called_once()
        validate_file.assert_called_once()

    @patch('vision.command.command.SendRestartNodeCommand.__init__', return_value=None)
    @patch('vision.status_watcher.StatusWatcher.__init__', return_value=None)
    @patch('inbm_vision_lib.invoker.Invoker.add')
    @patch('vision.manifest_parser.parse_manifest', return_value=ParsedManifest('restart', {}, ['123ABC']))
    def test_send_restart_request_one_node(self, mock_parse, mock_add, mock_status_watcher, mock_restart_cmd):
        mock_node = Mock()
        mock_node.device_id = "123ABC"
        mock_node.hardware.is_flashless = False
        mock_node.status.heartbeat_status = HEARTBEAT_ACTIVE_STATE
        self.data_handler._registry_manager._registries.append(mock_node)

        self.data_handler.receive_restart_request("mock_payload")
        mock_parse.assert_called_once()
        mock_restart_cmd.assert_called_once()
        mock_add.assert_called_once()

    @patch('vision.command.command.SendRestartNodeCommand.__init__')
    @patch('vision.status_watcher.StatusWatcher.__init__', return_value=None)
    @patch('inbm_vision_lib.invoker.Invoker.add')
    @patch('vision.manifest_parser.parse_manifest', return_value=ParsedManifest('restart', {}, ['123ABC']))
    def test_not_send_restart_request_to_any_node(self, mock_parse, mock_add, mock_status_watcher, mock_restart_cmd):
        mock_node = Mock()
        mock_node.device_id = "456DEF"
        mock_node.is_flashless = False
        mock_node.heartbeat_status = HEARTBEAT_ACTIVE_STATE
        self.data_handler._registry_manager._registries.append(mock_node)

        self.data_handler.receive_restart_request("mock_payload")
        mock_parse.assert_called_once()
        mock_restart_cmd.assert_not_called()

    @patch('os.remove')
    @patch('vision.registry_manager.RegistryManager.get_device', return_value=(None, None))
    @patch('inbm_vision_lib.invoker.Invoker.add')
    @patch('inbm_vision_lib.timer.Timer.start')
    @patch('vision.updater.Updater.__init__', return_value=None)
    @patch('vision.manifest_parser.parse_manifest',
           return_value=ParsedManifest('fota', {'path': '/var/intel-manageability'}, ['123ABC']))
    def test_receive_mqtt_message_fail(self, parse_manifest, updater_init, t_start, add_cmd, get_dev, mock_remove):
        self.data_handler.receive_mqtt_message("mock_payload")
        parse_manifest.assert_called_once()
        updater_init.assert_not_called()
        t_start.assert_not_called()
        assert add_cmd.call_count == 2
        get_dev.assert_called_once()

    @patch('os.remove')
    @patch('inbm_vision_lib.invoker.Invoker.add')
    @patch('inbm_vision_lib.timer.Timer.start')
    @patch('vision.updater.Updater.__init__', return_value=None)
    @patch('vision.manifest_parser.parse_manifest',
           return_value=ParsedManifest('fota', {'path': '/var/intel-manageability'}, ['123ABC']))
    def test_receive_mqtt_message_update_in_progress(self, parse_manifest, updater_init, t_start,
                                                     add_cmd, mock_remove):
        self.data_handler._updater = Mock()  # type: ignore
        self.data_handler.receive_mqtt_message("mock_payload")
        parse_manifest.assert_called_once()
        updater_init.assert_not_called()
        t_start.assert_not_called()
        add_cmd.assert_called_once()

    @patch('inbm_vision_lib.invoker.Invoker.add')
    @patch('inbm_vision_lib.timer.Timer.start')
    @patch('vision.manifest_parser.parse_manifest',
           return_value=TargetParsedManifest('get_element', {'path': 'isAliveTimerSecs'}, [], 'vision'))
    def test_manage_configuration_request(self, mock_parse, mock_timer, mock_invoker):
        get_request = '<?xml version="1.0" ' \
            'encoding="utf-8"?><manifest><type>config</type><config><cmd>get_element</cmd> ' \
            '<agent>vision</agent>' \
            '<configtype><get><path>isAliveTimerSecs</path>' \
            '</get></configtype></config></manifest>'
        self.data_handler.manage_configuration_request(get_request)
        mock_invoker.assert_called_once()

    @patch('inbm_vision_lib.invoker.Invoker.add')
    @patch('inbm_vision_lib.timer.Timer.start')
    @patch('vision.data_handler.data_handler.logger')
    def test_manage_configuration_request_fail(self, mock_logger, mock_timer, mock_invoker):
        get_request = '<?xml version="1.0" ' \
            'encoding="utf-8"?><manifest><type>config</type><config><cmd>element</cmd> ' \
            '<agent>vision</agent>' \
            '<configtype><get><path>isAliveTimerSecs</path>' \
            '</get></configtype></config></manifest>'
        self.data_handler.manage_configuration_request(get_request)
        assert mock_logger.error.call_count == 1
        mock_invoker.assert_called_once()

    @patch('inbm_vision_lib.invoker.Invoker.add')
    @patch('vision.command.broker_command.SendTelemetryResponseCommand.__init__', return_value=None)
    @patch('vision.data_handler.data_handler.logger')
    def test_manage_configuration_request_fail_target_not_active(self, mock_logger, mock_tele_init, mock_invoker):
        get_request = '<?xml version="1.0" encoding="utf-8"?><manifest>' \
                      '<type>config</type><config><cmd>get_element</cmd>' \
                      '<targetType>node</targetType><configtype><targets>' \
                      '<target>389C0A</target></targets><get><path>' \
                      'registrationRetryTimerSecs;registrationRetryLimit</path>' \
                      '</get></configtype></config></manifest>'
        mock_node = Mock()
        mock_node.device_id = "389C0A"
        mock_node.heartbeat_status = HEARTBEAT_IDLE_STATE
        self.data_handler._registry_manager._registries.append(mock_node)
        self.data_handler.manage_configuration_request(get_request)
        mock_tele_init.assert_called_once()
        mock_invoker.assert_called_once()

    @patch('vision.validater.validate_xlink_message')
    @patch('inbm_vision_lib.checksum_validator.validate_message',
           return_value=True)
    @patch('inbm_vision_lib.invoker.Invoker.add')
    @patch('vision.parser.XLinkParser.parse', return_value=('register', '123ABC', {'is_xlink_secure': True}))
    def test_receive_xlink_message_register_command(self, parse_xlink, add_cmd, validate_msg, validate_xlink):
        self.data_handler.receive_xlink_message("mock_message::123")
        parse_xlink.assert_called_once()
        add_cmd.assert_called_once()

    @patch('vision.validater.validate_xlink_message')
    @patch('inbm_vision_lib.checksum_validator.validate_message')
    @patch('inbm_vision_lib.invoker.Invoker.add')
    @patch('vision.parser.XLinkParser.parse', return_value=('register', '123ABC', {'is_xlink_secure': True}))
    def test_receive_xlink_message_validate_hash_called(self, parse_xlink, add_cmd, validate_msg, validate_xlink):
        self.data_handler.receive_xlink_message("mock_message::123")
        validate_msg.assert_called_once()
        parse_xlink.assert_called_once()
        add_cmd.assert_called_once()

    @patch('vision.validater.validate_xlink_message')
    @patch('inbm_vision_lib.checksum_validator.hash_message',
           return_value="123")
    @patch('inbm_vision_lib.invoker.Invoker.add')
    @patch('vision.parser.XLinkParser.parse', return_value=('register', '123ABC', {'is_xlink_secure': True}))
    def test_receive_xlink_message_validate_hash_success(self, parse_xlink, add_cmd, hash_msg, validate_xlink):
        self.data_handler.receive_xlink_message("mock_message::123")
        parse_xlink.assert_called_once()
        add_cmd.assert_called_once()

    @patch('inbm_vision_lib.checksum_validator.hash_message',
           return_value="1234")
    @patch('inbm_vision_lib.invoker.Invoker.add')
    @patch('vision.parser.XLinkParser.parse', return_value=('register', '123ABC', 'mock_dict'))
    def test_receive_xlink_message_validate_hash_fail(self, parse_xlink, add_cmd, hash_msg):
        self.data_handler.receive_xlink_message("mock_message::123")
        parse_xlink.assert_not_called()
        add_cmd.assert_called_once()

    @patch('vision.validater.validate_xlink_message')
    @patch('inbm_vision_lib.checksum_validator.validate_message',
           return_value=True)
    @patch('inbm_vision_lib.invoker.Invoker.add')
    @patch('vision.parser.XLinkParser.parse', return_value=('heartbeat', '123ABC', 'mock_dict'))
    def test_receive_xlink_message_heartbeat_command(self, parse_xlink, add_cmd, validate_msg, validate_xlink):
        self.data_handler.receive_xlink_message("mock_message::123")
        parse_xlink.assert_called_once()
        add_cmd.assert_called_once()

    @patch('vision.validater.validate_xlink_message')
    @patch('inbm_vision_lib.checksum_validator.validate_message',
           return_value=True)
    @patch('inbm_vision_lib.invoker.Invoker.add')
    @patch('vision.parser.XLinkParser.parse',
           return_value=('downloadStatus', '123ABC', {'status': 'success'}))
    def test_receive_xlink_message_downloadStatus_command(self, parse_xlink, add_cmd, validate_msg, validate_xlink):
        self.data_handler.receive_xlink_message("mock_message::123")
        parse_xlink.assert_called_once()
        add_cmd.assert_called_once()

    @patch('vision.validater.validate_xlink_message')
    @patch('inbm_vision_lib.checksum_validator.validate_message',
           return_value=True)
    @patch('inbm_vision_lib.invoker.Invoker.add')
    @patch('vision.parser.XLinkParser.parse',
           return_value=('sendFileResponse', '123ABC', {'sendDownload': 'True'}))
    def test_receive_xlink_message_sendFileResponse_command(self, parse_xlink, add_cmd, validate_msg, validate_xlink):
        self.data_handler.receive_xlink_message("mock_message::123")
        parse_xlink.assert_called_once()
        add_cmd.assert_called_once()

    @patch('vision.updater.Updater.__init__', return_value=None)
    @patch('vision.validater.validate_xlink_message')
    @patch('inbm_vision_lib.checksum_validator.validate_message',
           return_value=True)
    @patch('inbm_vision_lib.invoker.Invoker.add')
    @patch('vision.parser.XLinkParser.parse', return_value=('otaResult', '123ABC',
                                                            {'result': '{"status": 400, "message": "FAILED"}'}))
    def test_receive_xlink_message_otaResult_command_failure(self, parse_xlink, add_cmd, validate_msg, validate_xlink,
                                                             mock_updater):
        self.data_handler._updater = mock_updater
        self.data_handler.receive_xlink_message("mock_message::123")
        parse_xlink.assert_called_once()
        add_cmd.assert_called_once()
        mock_updater.set_target_error.assert_called_once()

    @patch('vision.updater.Updater.__init__', return_value=None)
    @patch('vision.validater.validate_xlink_message')
    @patch('inbm_vision_lib.checksum_validator.validate_message',
           return_value=True)
    @patch('inbm_vision_lib.invoker.Invoker.add')
    @patch('vision.parser.XLinkParser.parse', return_value=('otaResult', '123ABC',
                                                            {'result': '{"status": 200, "message": "SUCCESSFUL"}'}))
    def test_receive_xlink_message_otaResult_command_success(self, parse_xlink, add_cmd, validate_msg, validate_xlink,
                                                             mock_updater):
        self.data_handler._updater = Mock()
        self.data_handler.receive_xlink_message("mock_message::123")
        parse_xlink.assert_called_once()
        add_cmd.assert_called_once()
        mock_updater.set_done.assert_not_called()

    @patch('vision.validater.validate_xlink_message')
    @patch('inbm_vision_lib.checksum_validator.validate_message',
           return_value=True)
    @patch('inbm_vision_lib.invoker.Invoker.add')
    @patch('vision.parser.XLinkParser.parse',
           return_value=('configResponse', '123ABC', {'item': "{'status': '200', 'message': 'NODE Configuration command: SUCCESSFUL'}))"}))
    def test_receive_xlink_message_config_response_command_success(self, parse_xlink, add_cmd, validate_msg, validate_xlink):
        mock_updater = Mock()
        mock_updater.set_done
        mock_updater.is_all_targets_done
        self.data_handler._updater = mock_updater
        self.data_handler.receive_xlink_message("mock_message::123")
        parse_xlink.assert_called_once()
        add_cmd.assert_called_once()
        mock_updater.set_done.assert_called_once()
        mock_updater.is_all_targets_done.assert_called_once()

    @patch('vision.validater.validate_xlink_message')
    @patch('inbm_vision_lib.checksum_validator.validate_message',
           return_value=True)
    @patch('inbm_vision_lib.invoker.Invoker.add')
    @patch('vision.parser.XLinkParser.parse',
           return_value=('configResponse', '123ABC', {'item': "{'status': '400', 'message': 'Configuration command: FAILED'}))"}))
    def test_receive_xlink_message_config_response_command_fail(self, parse_xlink, add_cmd, validate_msg, validate_xlink):
        mock_updater = Mock()
        mock_updater.set_target_error
        self.data_handler._updater = mock_updater
        self.data_handler.receive_xlink_message("mock_message::123")
        parse_xlink.assert_called_once()
        add_cmd.assert_called_once()
        mock_updater.set_target_error.assert_called_once()

    @patch('vision.validater.validate_xlink_message')
    @patch('inbm_vision_lib.checksum_validator.validate_message',
           return_value=True)
    @patch('inbm_vision_lib.invoker.Invoker.add')
    @patch('vision.parser.XLinkParser.parse',
           return_value=('telemetryEvent', '123ABC', {'result': 200, 'telemetryMessage': 'mock_msg'}))
    def test_receive_xlink_message_telemetryEvent_command(self, parse_xlink, add_cmd, validate_msg, validate_xlink):
        self.data_handler.receive_xlink_message("mock_message::123")
        parse_xlink.assert_called_once()
        add_cmd.assert_called_once()

    @patch('vision.validater.validate_xlink_message')
    @patch('inbm_vision_lib.checksum_validator.validate_message',
           return_value=True)
    @patch('inbm_vision_lib.invoker.Invoker.add')
    @patch('vision.parser.XLinkParser.parse',
           return_value=('unknown_command', '123ABC', 'mock_dict'))
    def test_receive_xlink_message_unsupported_command(self, parse_xlink, add_cmd, validate_msg, validate_xlink):
        self.data_handler.receive_xlink_message("mock_message::123")
        parse_xlink.assert_called_once()
        add_cmd.assert_not_called()

    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_send_is_alive(self, add_cmd):
        self.data_handler.send_is_alive('123ABC')
        add_cmd.assert_called_once()

    @patch('vision.registry_manager.RegistryManager.stop_heartbeat_timer')
    @patch('inbm_vision_lib.invoker.Invoker.stop')
    def test_stop_data_handler(self, invoker_stop, registry_manager_stop):
        self.data_handler.stop()
        invoker_stop.assert_called_once()
        registry_manager_stop.assert_called_once()

    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_send_reregister_request(self, add_cmd):
        self.data_handler.send_reregister_request('Mock_id')
        add_cmd.assert_called_once()

    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_send_config_load_manifest(self, add_cmd):
        self.data_handler.send_config_load_manifest('Mock_id', 'Mock_manifest', 'node')
        add_cmd.assert_called_once()

    @patch('vision.command.configuration_command.SendNodeConfigValueCommand.__init__', return_value=None)
    def test_handle_node_configuration_get_request(self, init_command):
        command = self.data_handler._handle_node_configuration_request(
            TargetParsedManifest(CONFIG_GET, {'path': 'heartbeatRetryLimit'}, ['123ABC'], 'node'))
        init_command.assert_called_once()
        self.assertIsNotNone(command)

    @patch('vision.command.configuration_command.SendNodeConfigValueCommand.__init__', return_value=None)
    def test_handle_node_configuration_set_request(self, init_command):
        command = self.data_handler._handle_node_configuration_request(
            TargetParsedManifest(CONFIG_GET, {'path': 'heartbeatRetryLimit'}, ['123ABC'], 'node'))
        init_command.assert_called_once()
        self.assertIsNotNone(command)

    @patch("vision.data_handler.data_handler.validate_file_type")
    @patch('vision.command.ota_command.UpdateNodeCommand.__init__', return_value=None)
    @patch('vision.updater.ConfigurationLoader.__init__', return_value=None)
    def test_handle_node_configuration_load_request(self, init_config, init_command, validate):
        command = self.data_handler._handle_node_configuration_request(
            TargetParsedManifest(CONFIG_LOAD, {'path': '/var/manageability/node.conf'}, ['123ABC'], 'node'))
        init_config.assert_called_once()
        init_command.assert_called_once()
        self.assertIsNotNone(command)

    def test_handle_node_configuration_load_request_fail_update_in_progress(self):
        self.data_handler._updater = Mock()
        self.assertRaises(VisionException, self.data_handler._handle_node_configuration_request,
                          TargetParsedManifest(CONFIG_LOAD, {'path': '/var/manageability/node.conf'},
                                               ['123ABC'], 'node'))

    @patch('vision.registry_manager.RegistryManager.update_heartbeat_check_interval')
    def test_manage_configuration_update_hb_check_interval(self, update_method):
        self.data_handler.manage_configuration_update(VISION_HB_CHECK_INTERVAL_SECS + ":10")
        update_method.assert_called_once()

    @patch('vision.data_handler.data_handler.DataHandler._update_heartbeat_transmission_interval')
    def test_manage_configuration_update_node_hb_interval(self, update_method):
        self.data_handler.manage_configuration_update(NODE_HEARTBEAT_INTERVAL_SECS + ":10")
        update_method.assert_called_once()

    def test_manage_configuration_update_fota_timer(self):
        self.data_handler.manage_configuration_update(VISION_FOTA_TIMER + ":121")
        self.assertEquals(getattr(self.data_handler, 'max_fota_update_wait_time'), 121)

    def test_manage_configuration_update_sota_timer(self):
        self.data_handler.manage_configuration_update(VISION_SOTA_TIMER + ":600")
        self.assertEquals(getattr(self.data_handler, 'max_sota_update_wait_time'), 600)

    def test_manage_configuration_update_pota_timer(self):
        self.data_handler.manage_configuration_update(VISION_POTA_TIMER + ":1680")
        self.assertEquals(getattr(self.data_handler, 'max_pota_update_wait_time'), 1680)

    @patch('vision.registry_manager.RegistryManager.update_is_alive_interval')
    def test_manage_configuration_update_is_alive_interval(self, update_method):
        self.data_handler.manage_configuration_update(IS_ALIVE_INTERVAL_SECS + ":10")
        update_method.assert_called_once()

    def test_manage_configuration_update_flashless_file_path(self):
        self.data_handler.manage_configuration_update(FLASHLESS_FILE_PATH + ":/etc")
        self.assertEquals(getattr(self.data_handler, 'flashless_filepath'), '/etc')

    @patch('vision.registry_manager.RegistryManager.update_heartbeat_retry_limit')
    def test_manage_configuration_update_retry_limit(self, update_method):
        self.data_handler.manage_configuration_update(VISION_HB_RETRY_LIMIT + ":10")
        update_method.assert_called_once()

    def test_raise_updating_non_integer_value(self):
        with self.assertRaises(VisionException):
            self.data_handler.manage_configuration_update(VISION_HB_RETRY_LIMIT + ":abc")

    def test_raise_update_invalid_key(self):
        with self.assertRaises(VisionException):
            self.data_handler.manage_configuration_update("InvalidKey:10")

    @patch('vision.data_handler.data_handler.DataHandler.manage_configuration_update')
    def test_load_config_file_startup_success(self, conf_update: Any):
        self.data_handler.load_config_file(True)
        conf_update.assert_called_once()

    @patch('vision.data_handler.data_handler.DataHandler.manage_configuration_update',
           side_effect=ConfigurationException("Key not found"))
    def test_load_config_file_startup_fail(self, conf_update: Any):
        self.data_handler.load_config_file(True)
        conf_update.assert_called_once()

    @patch('inbm_vision_lib.invoker.Invoker.add')
    @patch('vision.data_handler.data_handler.DataHandler.manage_configuration_update',
           side_effect=ConfigurationException("Key not found"))
    def test_load_config_file_not_startup_fail(self, conf_update: Any, add_cmd: Any):
        self.data_handler.load_config_file(False)
        conf_update.assert_called_once()
        add_cmd.assert_called_once()

    @patch('vision.command.configuration_command.GetVisionConfigValuesCommand.__init__', return_value=None)
    def test_handle_vision_configuration_get_request(self, init_command):
        command = self.data_handler._handle_vision_configuration_request(
            TargetParsedManifest(CONFIG_GET, {'path': "mock_keys"}, [], AGENT))
        init_command.assert_called_once()
        self.assertIsNotNone(command)

    @patch('vision.command.configuration_command.SetVisionConfigValuesCommand.__init__', return_value=None)
    def test_handle_vision_configuration_set_request(self, init_command):
        command = self.data_handler._handle_vision_configuration_request(
            TargetParsedManifest(CONFIG_SET, {'path': "mock_keys"}, [], AGENT))
        init_command.assert_called_once()
        self.assertIsNotNone(command)

    @patch("vision.data_handler.data_handler.validate_file_type")
    @patch('vision.command.configuration_command.LoadConfigFileCommand.__init__', return_value=None)
    def test_handle_vision_configuration_load_request(self, init_command, validate):
        command = self.data_handler._handle_vision_configuration_request(
            TargetParsedManifest(CONFIG_LOAD, {'path': "mock_path"}, [], AGENT))
        init_command.assert_called_once()
        self.assertIsNotNone(command)

    def test_handle_vision_configuration_invalid_request(self):
        self.assertRaises(VisionException, self.data_handler._handle_vision_configuration_request,
                          TargetParsedManifest("unknown request", {'path': "mock_path"}, [], AGENT))

    def test_update_request_status_with_updater_pass(self):
        mock_updater = Mock()
        mock_updater.set_done
        mock_updater.is_all_targets_done
        mock_ota_target = OtaTarget("123ABC")
        mock_updater._targets = [mock_ota_target]
        self.data_handler._updater = mock_updater
        self.data_handler._update_request_status("123ABC")
        mock_updater.set_done.assert_called_once()
        mock_updater.is_all_targets_done.assert_called_once()

    @patch('vision.data_handler.data_handler.DataHandler.send_telemetry_response')
    def test_update_request_status_with_status_watcher_pass(self, send_response):
        mock_status_watcher = Mock()
        mock_status_watcher.set_done
        mock_status_watcher.is_all_targets_done = MagicMock(return_value=True)
        self.data_handler._status_watcher = mock_status_watcher
        self.data_handler._update_request_status("123ABC")
        mock_status_watcher.set_done.assert_called_once()
        mock_status_watcher.is_all_targets_done.assert_called_once()
        send_response.assert_called_once()

    @patch('vision.manifest_parser.parse_manifest',
           return_value=TargetParsedManifest('query', {'option': 'all'}, [], 'node'))
    @patch('vision.data_handler.data_handler.DataHandler.create_telemetry_event')
    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_receive_command_query_request_node_all_info(self, add_cmd, tele, parsed_manifest):
        mock_node = Mock()
        mock_node.device_id = "389C0A"
        mock_node.status.heartbeat_status = HEARTBEAT_ACTIVE_STATE
        self.data_handler._registry_manager._registries.append(mock_node)
        self.data_handler.receive_command_request("Mock Payload")
        assert tele.call_count == 2

    @patch('vision.manifest_parser.parse_manifest',
           return_value=TargetParsedManifest('query', {'option': 'fw'}, [], 'node'))
    @patch('vision.data_handler.data_handler.DataHandler.create_telemetry_event')
    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_receive_command_query_request_node_fw_info(self, add_cmd, tele, parsed_manifest):
        mock_node = Mock()
        mock_node.device_id = "389C0A"
        mock_node.status.heartbeat_status = HEARTBEAT_ACTIVE_STATE
        mock_node.firmware.boot_fw_date = datetime.datetime(2021, 1, 12)
        mock_node.os.os_release_date = datetime.datetime(2021, 1, 12)
        self.data_handler._registry_manager._registries.append(mock_node)
        self.data_handler.receive_command_request("Mock Payload")
        assert tele.call_count == 2

    @patch('vision.manifest_parser.parse_manifest',
           return_value=TargetParsedManifest('query', {'option': 'os'}, [], 'node'))
    @patch('vision.data_handler.data_handler.DataHandler.create_telemetry_event')
    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_receive_command_query_request_node_os_info(self, add_cmd, tele, parsed_manifest):
        mock_node = Mock()
        mock_node.device_id = "389C0A"
        mock_node.status.heartbeat_status = HEARTBEAT_ACTIVE_STATE
        self.data_handler._registry_manager._registries.append(mock_node)
        self.data_handler.receive_command_request("Mock Payload")
        assert tele.call_count == 2

    @patch('vision.manifest_parser.parse_manifest',
           return_value=TargetParsedManifest('query', {'option': 'status'}, [], 'node'))
    @patch('vision.data_handler.data_handler.DataHandler.create_telemetry_event')
    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_receive_command_query_request_node_status_info(self, add_cmd, tele, parsed_manifest):
        mock_node = Mock()
        mock_node.device_id = "389C0A"
        mock_node.status.heartbeat_status = HEARTBEAT_ACTIVE_STATE
        self.data_handler._registry_manager._registries.append(mock_node)
        self.data_handler.receive_command_request("Mock Payload")
        assert tele.call_count == 2

    @patch('vision.manifest_parser.parse_manifest',
           return_value=TargetParsedManifest('query', {'option': 'status'}, [], 'node'))
    @patch('vision.data_handler.data_handler.DataHandler.create_telemetry_event')
    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_receive_command_query_request_node_no_node(self, add_cmd, tele, parsed_manifest):
        self.data_handler.receive_command_request("Mock Payload")
        assert tele.call_count == 1

    @patch("inbm_vision_lib.shell_runner.PseudoShellRunner.run", return_value=("vision-agent     1.7.1-1", '', 0))
    @patch('vision.manifest_parser.parse_manifest',
           return_value=TargetParsedManifest('query', {'option': 'version'}, [], 'vision'))
    @patch('vision.data_handler.data_handler.DataHandler.create_telemetry_event')
    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_receive_command_query_request_vision_version(self, add_cmd, tele, parsed_manifest, check_version):
        self.data_handler.receive_command_request("Mock Payload")
        assert tele.call_count == 1
        check_version.assert_called_once()

    @patch('vision.manifest_parser.parse_manifest',
           return_value=TargetParsedManifest('query', {'option': 'status'}, [], 'node_client'))
    @patch('vision.data_handler.data_handler.DataHandler.send_telemetry_response')
    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_receive_command_query_request_unsupported_command(self, add_cmd, resp, parsed_manifest):
        self.data_handler.receive_command_request("Mock Payload")
        assert resp.call_count == 1

    @patch('inbm_vision_lib.invoker.Invoker.add')
    def test_reset_device(self, add_cmd):
        mock_config_mgr = Mock()
        mock_config_mgr.get_element = MagicMock(return_value=[10])
        self.data_handler._config = mock_config_mgr
        self.data_handler.reset_device("123ABC")
        assert add_cmd.call_count == 2
