from unittest import TestCase
from mock import Mock, MagicMock

from vision.command.configuration_command import *
from vision.constant import AGENT, VISION_ID
from vision.configuration_constant import VISION_HB_CHECK_INTERVAL_SECS, VISION_FOTA_TIMER
from inbm_vision_lib.configuration_manager import ConfigurationException


class TestGetVisionConfigValuesCommand(TestCase):
    def setUp(self):
        self.broker = Mock()
        self.broker.publish_telemetry_event
        self.config_manager = Mock()
        self.config_manager.get_element = MagicMock(return_value=[10, 10])
        key_list = [VISION_HB_CHECK_INTERVAL_SECS, VISION_FOTA_TIMER]
        self.command = GetVisionConfigValuesCommand(
            VISION_ID, self.broker, key_list, self.config_manager, AGENT)

    def test_execute(self):
        self.command.execute()
        self.config_manager.get_element.assert_called_once()
        self.assertEqual(self.broker.publish_telemetry_event.call_count, 2)


class TestSetVisionConfigValuesCommand(TestCase):
    def setUp(self):
        self.broker = Mock()
        self.broker.publish_telemetry_event
        self.broker.data_handler.manage_configuration_update
        self.config_manager = Mock()
        self.config_manager.set_element = MagicMock(return_value=['SUCCESS', 'SUCCESS'])
        key_list = [VISION_HB_CHECK_INTERVAL_SECS + ':20', VISION_FOTA_TIMER + ':20']
        self.command = SetVisionConfigValuesCommand(
            VISION_ID, self.broker, key_list, self.config_manager, AGENT)

    def test_execute_success(self):
        self.command.execute()
        self.config_manager.set_element.assert_called_once()
        self.assertEqual(self.broker.publish_telemetry_event.call_count, 2)
        self.assertEqual(self.broker.data_handler.manage_configuration_update.call_count, 2)

    def test_execute_fail(self):
        self.config_manager.set_element = MagicMock(
            side_effect=ConfigurationException("XML file not found"))
        self.command.execute()
        self.config_manager.set_element.assert_called_once()
        self.assertEqual(self.broker.publish_telemetry_event.call_count, 1)


class TestLoadConfigFileCommand(TestCase):
    def setUp(self):
        self.broker = Mock()
        self.broker.data_handler.load_config_file
        self.config_manager = Mock()
        self.config_manager.load
        path = '/var/cache/intel-manageability/intel_manageability_vision.config'
        config_cmd_type = 'load'
        self.command = LoadConfigFileCommand(
            VISION_ID, self.broker, path, self.config_manager, config_cmd_type)

    def test_execute(self):
        self.command.execute()
        self.config_manager.load.assert_called_once()
        self.broker.data_handler.load_config_file.assert_called_once()

    def test_execute_with_error(self):
        self.broker.publish_telemetry_response
        self.broker.data_handler.load_config_file = MagicMock(
            side_effect=ConfigurationException("Load failed."))
        self.command.execute()
        self.config_manager.load.assert_called_once()
        self.broker.data_handler.load_config_file.assert_called_once()
        self.broker.publish_telemetry_response.assert_called_once()


class TestSendNodeConfigValueCommand(TestCase):
    def setUp(self):
        self.mock_xlink_manager = Mock()
        self.mock_xlink_manager.send

        self.mock_registry_manager = Mock()
        self.mock_registry_manager.get_target_ids = MagicMock(return_value='node1')

    def test_execute_get(self):
        self.command = SendNodeConfigValueCommand(self.mock_xlink_manager, self.mock_registry_manager,
                                                  ['isAliveTimerSecs'], 'get_element', ['node1'], 'node-client')
        self.command.execute()
        self.mock_xlink_manager.send.assert_called()

    def test_execute_set(self):
        self.command = SendNodeConfigValueCommand(self.mock_xlink_manager, self.mock_registry_manager,
                                                  ['isAliveTimerSecs:10'], 'set_element', ['node1'], 'node-client')
        self.command.execute()
        self.mock_xlink_manager.send.assert_called()

    def test_execute_remove(self):
        self.command = SendNodeConfigValueCommand(self.mock_xlink_manager, self.mock_registry_manager,
                                                  ['isAliveTimerSecs'], 'remove', ['node1'], 'node-client')
        self.command.execute()
        self.mock_xlink_manager.send.assert_called()

    def test_execute_append(self):
        self.command = SendNodeConfigValueCommand(self.mock_xlink_manager, self.mock_registry_manager,
                                                  ['isAliveTimerSecs'], 'append', ['node1'], 'node-client')
        self.command.execute()
        self.mock_xlink_manager.send.assert_called()

    def test_raises_no_xlink(self):
        with self.assertRaises(VisionException):
            self.command = SendNodeConfigValueCommand(None, self.mock_registry_manager,
                                                      ['isAliveTimerSecs'], 'get_element', ['node1'], 'node-client')
            self.command.execute()


class TestSendNodeConfigurationLoadManifestCommand(TestCase):

    def setUp(self):
        self.mock_xlink_manager = Mock()
        self.mock_xlink_manager.send
        self.command = SendNodeConfigurationLoadManifestCommand(
            '123ABC', self.mock_xlink_manager, "mock_manifest", "node")

    def test_execute(self):
        self.command.execute()
        self.mock_xlink_manager.send.assert_called_once()
