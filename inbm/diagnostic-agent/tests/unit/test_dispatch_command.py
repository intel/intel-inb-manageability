from unittest import TestCase

import os
import psutil
from diagnostic.dispatch_command import dispatch_command
from mock import Mock, patch

TELIT_CLOUD_IS_DOWN = 'Telit cloud is down. '
UNKNOWN_CLOUD_CONNECTOR_SENT = 'Unknown cloud connector sent'
TELIT_SERVICES_AND_BROKER_HEALTHY = 'Telit services and broker running healthy. '
TELIT_NOT_AS_EXPECTED = 'Telit services/broker not running as expected. '
ARBITRARY_STRING_1 = 'abcdefg'
TELIT_CLOUD_HEALTHY = 'Telit cloud webservice running healthy. '
NO_BATTERY_INSTALLED = 'Device has no battery installed. '
NETWORK_INTERFACE_DOWN = 'Network interfaces down.  Cannot find network interface with a default route.'
NETWORK_INTERFACE_HEALTHY = 'At least one network interface is healthy (has a default route).'
NETWORK_CHECK_DISABLED = 'Network check is disabled for the platform.'
UNKNOWN_COMMAND_INVOKED = 'Unknown command invoked'
FAILED_TO_RUN_TRTL = 'Failed to run TRTL list command'
INVALID_MEMORY_SENT = 'Invalid memory sent. Must be in MBs'
INVALID_SIZE_SENT = 'Invalid size sent. Must be in MBs'
GENERIC_ADAPTER_HEALTHY = 'Generic Adapter running healthy. '
GENERIC_ADAPTER_NOT_HEALTHY = 'Generic Adapter not running. '
BATTERY_CHECK_PASSED = 'Battery check passed. Device OK for update. '
UNIT_TEST_DISK_PATH = '/'


class TestDispatchCommand(TestCase):

    @patch("netifaces.gateways",
           return_value={})
    def test_pin_install_check_network_down(self, mock_run):
        result = dispatch_command('install_check', 30, UNIT_TEST_DISK_PATH,
                                  20, 20, 20, 'docker', 'true')
        self.assertDictEqual(result, {'cmd': 'check_network',
                                      'message': NETWORK_INTERFACE_DOWN,
                                      'rc': 1})

    @patch("inbm_common_lib.shell_runner.PseudoShellRunner.run", return_value=('200', "", 0))
    @patch.object(psutil, 'sensors_battery')
    def test_pin_health_device_battery_no_battery(self, mock_sensors_battery, mock_run):
        mock_sensors_battery.return_value = None
        result = dispatch_command('health_device_battery', 30, UNIT_TEST_DISK_PATH, 20, 20, 20,
                                  'docker', 'true')
        self.assertDictEqual(result, {'cmd': 'health_device_battery',
                                      'message': NO_BATTERY_INSTALLED, 'rc': 0})

    @patch("inbm_common_lib.shell_runner.PseudoShellRunner.run", return_value=('200', "", 0))
    @patch.object(psutil, 'sensors_battery')
    def test_pin_health_device_battery_low_battery(self, mock_sensors_battery, mock_run):
        mock_sensors_battery.return_value = Mock(percent=10, power_plugged=False)
        result = dispatch_command('health_device_battery', 30, UNIT_TEST_DISK_PATH, 20, 20, 20,
                                  'docker', 'true')
        self.assertDictEqual(result, {'cmd': 'health_device_battery',
                                      'message': 'Battery check failed. Charge to at least 20 '
                                                 'percent before update. Current charge %: 10',
                                      'rc': 1})

    @patch("inbm_common_lib.shell_runner.PseudoShellRunner.run", return_value=('200', "", 0))
    @patch.object(psutil, 'sensors_battery')
    def test_pin_health_device_battery_passed(self, mock_sensors_battery, mock_run):
        mock_sensors_battery.return_value = Mock(percent=50, power_plugged=False)
        result = dispatch_command('health_device_battery', 30, UNIT_TEST_DISK_PATH, 20, 20, 20,
                                  'docker', 'true')
        # Note that this seems like a bug
        self.assertDictEqual(result, {'cmd': 'health_device_battery',
                                      'message': BATTERY_CHECK_PASSED, 'rc': 0})

    @patch("inbm_common_lib.shell_runner.PseudoShellRunner.run", return_value=('200', "", 0))
    def test_pin_health_device_battery_invalid_power(self, mock_run):
        result = dispatch_command('health_device_battery', 30, UNIT_TEST_DISK_PATH, 20, 110, 20,
                                  'docker', 'true')
        self.assertDictEqual(result, {'cmd': 'health_device_battery',
                                      'message': 'Invalid power sent. Must be in percent',
                                      'rc': 1})

    @patch("inbm_common_lib.shell_runner.PseudoShellRunner.run", return_value=('200', "", 0))
    @patch('diagnostic.command_pattern.get_free_space', return_value=40000005)
    def test_pin_check_storage_good(self, mock_free_space, mock_run):
        result = dispatch_command('check_storage', 30, UNIT_TEST_DISK_PATH,
                                  20, 20, 20, 'docker', 'true')
        self.assertDictEqual(result,
                             {'cmd': 'check_storage',
                              'message': 'Min storage check passed.  Available: 40000005. ',
                              'rc': 0})

    @patch("inbm_common_lib.shell_runner.PseudoShellRunner.run", return_value=('200', "", 0))
    @patch('diagnostic.command_pattern.get_free_space', return_value=2000005)
    def test_pin_check_storage_not_enough(self, mock_free_space, mock_run):
        result = dispatch_command('check_storage', 30, UNIT_TEST_DISK_PATH,
                                  20, 20, 20, 'docker', 'true')
        self.assertDictEqual(result, {'cmd': 'check_storage',
                                      'message': 'Less than 31457280 bytes free. Available: '
                                                 '2000005. ', 'rc': 1})

    @patch("inbm_common_lib.shell_runner.PseudoShellRunner.run", return_value=('200', "", 0))
    @patch('diagnostic.command_pattern.get_free_space', return_value=3000005)
    def test_pin_check_storage_size_is_None(self, mock_free_space, mock_run):
        result = dispatch_command('check_storage', None,
                                  UNIT_TEST_DISK_PATH, 20, 20, 20, 'docker', 'true')
        self.assertDictEqual(result, {'cmd': 'check_storage',
                                      'message': 'Less than 20971520 bytes free. Available: '
                                                 '3000005. ', 'rc': 1})

    @patch("inbm_common_lib.shell_runner.PseudoShellRunner.run", return_value=('200', "", 0))
    @patch('diagnostic.command_pattern.get_free_space', return_value=3000005)
    def test_pin_check_storage_size_min_storage_is_not_int(self, mock_free_space, mock_run):
        result = dispatch_command('check_storage', None, UNIT_TEST_DISK_PATH, 20, 20, 'not an int',
                                  'docker', 'true')
        self.assertDictEqual(result, {'cmd': 'check_storage', 'message': INVALID_SIZE_SENT,
                                      'rc': 1})

    @patch("inbm_common_lib.shell_runner.PseudoShellRunner.run", return_value=('200', "", 0))
    @patch('diagnostic.command_pattern.get_free_memory', return_value=123456789)
    def test_pin_check_memory_passed(self, mock_free_memory, mock_run):
        result = dispatch_command('check_memory', 30, UNIT_TEST_DISK_PATH,
                                  20, 20, 20, 'docker', 'true')
        self.assertDictEqual(result, {'cmd': 'check_memory',
                                      'message': 'Min memory check passed. Available: 123456789. ',
                                      'rc': 0})

    @patch("inbm_common_lib.shell_runner.PseudoShellRunner.run", return_value=('200', "", 0))
    @patch('diagnostic.command_pattern.get_free_memory', return_value=200)
    def test_pin_check_memory_failed(self, mock_free_memory, mock_run):
        result = dispatch_command('check_memory', 30, UNIT_TEST_DISK_PATH,
                                  20, 20, 20, 'docker', 'true')
        self.assertDictEqual(result, {'cmd': 'check_memory',
                                      'message': 'Less than 20971520 bytes free. Available: 200. ',
                                      'rc': 1})

    @patch("inbm_common_lib.shell_runner.PseudoShellRunner.run", return_value=('200', "", 0))
    @patch('diagnostic.command_pattern.get_free_memory', return_value=123456789)
    def test_pin_check_memory_invalid(self, mock_free_memory, mock_run):
        mock_free_memory.return_value = 123456789
        result = dispatch_command('check_memory', 30, UNIT_TEST_DISK_PATH, 'not an integer', 20, 20,
                                  'docker', 'true')
        self.assertDictEqual(result, {'cmd': 'check_memory', 'message': INVALID_MEMORY_SENT,
                                      'rc': 1})

    @patch("netifaces.gateways",
           return_value={'default': {2: ('134.134.155.251', 'eno1')}})
    def test_pin_check_network_healthy(self, mock_run):
        result = dispatch_command('check_network', 30, UNIT_TEST_DISK_PATH,
                                  20, 20, 20, 'docker', 'true')
        self.assertDictEqual(result, {'cmd': 'check_network',
                                      'message': NETWORK_INTERFACE_HEALTHY,
                                      'rc': 0})

    def test_check_network_diable_on_platform(self):
        result = dispatch_command('check_network', 30, UNIT_TEST_DISK_PATH,
                                  20, 20, 20, 'docker', 'false')
        self.assertDictEqual(result, {'cmd': 'check_network',
                                      'message': NETWORK_CHECK_DISABLED,
                                      'rc': 0})

    @patch("netifaces.gateways",
           return_value={})
    def test_pin_check_network_down(self, mock_run):
        result = dispatch_command('check_network', 30, UNIT_TEST_DISK_PATH,
                                  20, 20, 20, 'docker', 'true')
        self.assertDictEqual(result, {'cmd': 'check_network',
                                      'message': NETWORK_INTERFACE_DOWN,
                                      'rc': 1})

    @patch('inbm_lib.trtl.Trtl.list', return_value=("", ARBITRARY_STRING_1))
    def test_pin_container_health_check_good(self, mock_list):
        result = dispatch_command('container_health_check', 30, UNIT_TEST_DISK_PATH, 20, 20, 20,
                                  'docker', 'true')
        self.assertDictEqual(result, {'cmd': 'container_health_check',
                                      'message': ARBITRARY_STRING_1,
                                      'rc': 0})

    @patch('inbm_lib.trtl.Trtl.list', return_value=(ARBITRARY_STRING_1 + ' err',
                                                    ARBITRARY_STRING_1))
    def test_pin_container_health_check_error(self, mock_list):
        result = dispatch_command('container_health_check', 30,
                                  UNIT_TEST_DISK_PATH, 20, 20, 20, 'docker', 'true')
        self.assertDictEqual(result, {'cmd': 'container_health_check',
                                      'message': ARBITRARY_STRING_1 + ' err',
                                      'rc': 1})

    @patch('inbm_lib.trtl.Trtl.list', return_value=(FAILED_TO_RUN_TRTL, ""))
    def test_pin_container_health_check_trtl_not_found(self, mock_list):
        result = dispatch_command('container_health_check', 30,
                                  UNIT_TEST_DISK_PATH, 20, 20, 20, 'docker', 'true')
        self.assertDictEqual(result, {'cmd': 'container_health_check',
                                      'message': FAILED_TO_RUN_TRTL,
                                      'rc': 1})

    @patch("inbm_common_lib.shell_runner.PseudoShellRunner.run", return_value=('200', "", 0))
    def test_pin_invalid_command(self, mock_run):
        result = dispatch_command('invalid_command', 30,
                                  UNIT_TEST_DISK_PATH, 20, 20, 20, 'docker', 'true')
        self.assertDictEqual(result, {'message': UNKNOWN_COMMAND_INVOKED, 'rc': 1})

    @patch('inbm_lib.detect_os.detect_os', return_value='Ubuntu')
    @patch('os.path.exists', return_value=True)
    def test_software_check_pass(self, mock_path_exists, mock_detect_os):
        result = dispatch_command('swCheck', 30,
                                  UNIT_TEST_DISK_PATH, 20, 20, 20, 'trtl', 'true')
        self.assertDictEqual(result, {'cmd': 'swCheck',
                                      'message': 'All required software present ',
                                      'rc': 0})

    @patch('inbm_lib.detect_os.detect_os', return_value='Ubuntu')
    @patch('os.path.exists', return_value=False)
    def test_software_check_fail(self, mock_path_exists, mock_detect_os):
        result = dispatch_command('swCheck', 30,
                                  UNIT_TEST_DISK_PATH, 20, 20, 20, 'trtl', 'true')
        self.assertDictEqual(result, {'cmd': 'swCheck',
                                      'message': 'Trtl not present ',
                                      'rc': 1})
