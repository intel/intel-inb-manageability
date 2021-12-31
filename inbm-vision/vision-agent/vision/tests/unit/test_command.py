from unittest import TestCase

from vision.command.command import *
from vision.command.broker_command import *
from inbm_vision_lib.constants import TBH
from mock import Mock, patch


class TestSendXlinkMessageCommand(TestCase):

    def setUp(self):
        self.mock_node_connector = Mock()
        self.mock_node_connector.send
        self.Command = SendXlinkMessageCommand('123ABC', self.mock_node_connector, 'xlink message')

    def test_execute(self):
        self.Command.execute()
        self.mock_node_connector.send.assert_called_once()


class TestBootDeviceCommand(TestCase):
    def setUp(self):
        self.mock_node_connector = Mock()
        self.mock_node_connector.send
        self.mock_node_connector.check_platform_type.return_value = TBH
        self.command = BootDeviceCommand('123ABC', self.mock_node_connector, Mock(), Mock())

    @patch('vision.command.command.create_success_message')
    @patch("inbm_vision_lib.shell_runner.PseudoShellRunner.run", return_value=('', '', 0))
    def test_execute_success(self, mock_run, mock_success):
        self.command.execute()
        mock_success.assert_called_once()

    @patch('vision.command.command.create_error_message')
    @patch("inbm_vision_lib.shell_runner.PseudoShellRunner.run", return_value=('reboot failed', '', 1))
    def test_raise_failed_run(self, mock_run, mock_error):
        self.command.execute()
        mock_error.assert_called_once()


class TestUpdateNodeHeartbeatCommand(TestCase):

    def setUp(self):
        self.mock_registry_manager = Mock()
        self.mock_registry_manager.update_heartbeat_timestamp
        self.command = UpdateNodeHeartbeatCommand('123ABC', self.mock_registry_manager)

    def test_execute(self):
        self.command.execute()
        self.mock_registry_manager.update_heartbeat_timestamp.assert_called_once()


class TestRegisterNodeCommand(TestCase):

    def setUp(self):
        self.mock_registry_manager = Mock()
        self.mock_registry_manager.add_registry
        self.mock_guid = 12345

    def _execute_command_called(self, command):
        command.execute()
        self.mock_registry_manager.add.assert_called_once()

    def _execute_command_not_called(self, command):
        command.execute()
        self.mock_registry_manager.add.assert_not_called()

    def test_execute_add_registry_success(self):
        mock_node_info = {'bootFwDate': "2018-10-9 00:00:00", 'bootFwVersion': '1.5.9',
                          'bootFwVendor': 'Dell Inc.', 'osType': 'Ubuntu',
                          'osVersion': '16.04.6 LTS',
                          'manufacturer': 'Dell Inc.', 'dmVerityEnabled': False,
                          'measuredBootEnabled': '', 'guid': None}
        command = RegisterNodeCommand(
            '123ABC', self.mock_registry_manager, mock_node_info)
        self._execute_command_called(command)

    def test_execute_add_registry_fail_in_date(self):
        mock_node_info = {'bootFwDate': "2018-10-9", 'bootFwVersion': '1.5.9',
                          'bootFwVendor': 'Dell Inc.', 'osType': 'Ubuntu',
                          'osVersion': '16.04.6 LTS',
                          'manufacturer': 'Dell Inc.', 'dmVerityEnabled': False,
                          'measuredBootEnabled': '', 'guid': None}
        command = RegisterNodeCommand(
            '123ABC', self.mock_registry_manager, mock_node_info)
        self._execute_command_not_called(command)

    def test_execute_add_registry_fail_in_empty_os_type(self):
        mock_node_info = {'bootFwDate': "2018-10-9 00:00:00", 'bootFwVersion': '1.5.9',
                          'bootFwVendor': 'Dell Inc.', 'osType': '',
                          'osVersion': '16.04.6 LTS',
                          'manufacturer': 'Dell Inc.', 'dmVerityEnabled': False,
                          'measuredBootEnabled': '', 'guid': None}
        command = RegisterNodeCommand(
            '123ABC', self.mock_registry_manager, mock_node_info)
        self._execute_command_not_called(command)

    def test_execute_add_registry_fail_in_os_type(self):
        mock_node_info = {'bootFwDate': "2018-10-9 00:00:00", 'bootFwVersion': '1.5.9',
                          'bootFwVendor': 'Dell Inc.', 'osType': 'Windows',
                          'osVersion': 'x64 RS5',
                          'manufacturer': 'Dell Inc.', 'dmVerityEnabled': False,
                          'measuredBootEnabled': '', 'guid': None}
        command = RegisterNodeCommand(
            '123ABC', self.mock_registry_manager, mock_node_info)
        self._execute_command_not_called(command)

    def test_execute_add_registry_no_vendor(self):
        mock_node_info = {'bootFwDate': "2018-10-9 00:00:00", 'bootFwVersion': '1.5.9',
                          'bootFwVendor': '', 'osType': 'Ubuntu',
                          'osVersion': '16.04.6 LTS',
                          'manufacturer': 'Dell Inc.', 'dmVerityEnabled': False,
                          'measuredBootEnabled': '', 'guid': None}
        command = RegisterNodeCommand(
            '123ABC', self.mock_registry_manager, mock_node_info)
        self._execute_command_called(command)

    def test_execute_add_registry_no_version(self):
        mock_node_info = {'bootFwDate': "2018-10-9 00:00:00", 'bootFwVersion': '',
                          'bootFwVendor': 'Dell Inc.', 'osType': 'Ubuntu',
                          'osVersion': '16.04.6 LTS',
                          'manufacturer': 'Dell Inc.', 'dmVerityEnabled': False,
                          'measuredBootEnabled': '', 'guid': None}
        command = RegisterNodeCommand(
            '123ABC', self.mock_registry_manager, mock_node_info)
        self._execute_command_called(command)

    def test_execute_add_registry_no_os_version(self):
        mock_node_info = {'bootFwDate': "2018-10-9 00:00:00", 'bootFwVersion': '1.5.9',
                          'bootFwVendor': 'Dell Inc.', 'osType': 'Ubuntu',
                          'osVersion': '',
                          'manufacturer': 'Dell Inc.', 'dmVerityEnabled': False,
                          'measuredBootEnabled': '', 'guid': None}
        command = RegisterNodeCommand(
            '123ABC', self.mock_registry_manager, mock_node_info)
        self._execute_command_called(command)

    def test_execute_add_registry_no_manufacturer(self):
        mock_node_info = {'bootFwDate': "2018-10-9 00:00:00", 'bootFwVersion': '1.5.9',
                          'bootFwVendor': 'Dell Inc.', 'osType': 'Ubuntu',
                          'osVersion': '16.04.6 LTS',
                          'manufacturer': '', 'dmVerityEnabled': False,
                          'measuredBootEnabled': '', 'guid': None}
        command = RegisterNodeCommand(
            '123ABC', self.mock_registry_manager, mock_node_info)
        self._execute_command_called(command)

    def test_raises_invalid_date_format(self):
        mock_node_info = {'bootFwDate': "Oct 9 2020", 'bootFwVersion': '1.5.9',
                          'bootFwVendor': 'Dell Inc.', 'osType': 'Ubuntu',
                          'osVersion': '16.04.6 LTS',
                          'manufacturer': '', 'dmVerityEnabled': False,
                          'measuredBootEnabled': '', 'guid': None}
        with self.assertRaises(VisionException):
            command = RegisterNodeCommand(
                '123ABC', self.mock_registry_manager, mock_node_info)
            command._validate_boot_fw_date()

    def test_raises_unsupported_os(self):
        mock_node_info = {'bootFwDate': "2018-10-9 00:00:00", 'bootFwVersion': '1.5.9',
                          'bootFwVendor': 'Dell Inc.', 'osType': 'RedHat',
                          'osVersion': '16.04.6 LTS',
                          'manufacturer': '', 'dmVerityEnabled': False,
                          'measuredBootEnabled': '', 'guid': None}
        with self.assertRaises(VisionException):
            command = RegisterNodeCommand(
                '123ABC', self.mock_registry_manager, mock_node_info)
            command._validate_os_type()


class TestSendTelemetryEventCommand(TestCase):

    def setUp(self):
        self.mock_broker = Mock()
        self.mock_broker.publish_telemetry_event
        mock_message = Mock()
        self.command = SendTelemetryEventCommand('123ABC', self.mock_broker, mock_message)

    def test_execute(self):
        self.command.execute()
        self.mock_broker.publish_telemetry_event.assert_called_once()


class TestCommand(TestCase):

    def setUp(self):
        self.mock_broker = Mock()
        self.mock_broker.publish_telemetry_response
        mock_response = Mock()
        self.command = SendTelemetryResponseCommand('123ABC', self.mock_broker, mock_response)

    def test_execute(self):
        self.command.execute()
        self.mock_broker.publish_telemetry_response.assert_called_once()


class TestSendRestartNodeCommand(TestCase):

    def setUp(self):
        self.mock_node_connector = Mock()
        self.mock_node_connector.send
        self.command = SendRestartNodeCommand('123ABC', self.mock_node_connector)

    def test_execute(self):
        self.command.execute()
        self.mock_node_connector.send.assert_called_once()


class TestResetDeviceCommand(TestCase):
    def setUp(self):
        self.mock_node_connector = Mock()
        self.mock_node_connector.reset_device
        self.command = ResetDeviceCommand('123ABC', self.mock_node_connector)

    def test_execute(self):
        self.command.execute()
        self.mock_node_connector.reset_device.assert_called_once()
