import unittest
from unittest import TestCase

from ddt import data, ddt, unpack
from diagnostic.constants import MIN_MEMORY_MB, MIN_STORAGE_MB, DOCKER_BENCH_SECURITY_INTERVAL_SEC, \
    MIN_POWER_PERCENT, NETWORK_CHECK, DEFAULT_MIN_POWER_PERCENT, DEFAULT_MIN_MEMORY_MB, DEFAULT_MIN_STORAGE_MB, \
    DEFAULT_DOCKER_BENCH_SECURITY_INTERVAL_SEC
from diagnostic.diagnostic_checker import DiagnosticChecker
from mock import patch, Mock


@ddt
class TestDiagnosticChecker(TestCase):

    def setUp(self):
        self.dc = DiagnosticChecker(Mock())

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    def test_check_sw_mandatory_notsplit(self, m_sub, m_connect):
        self.dc.sw_list = ' trtl docker '
        self.assertEqual(self.dc._check_sw_mandatory_list('docker'), False)

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    def test_check_sw_mandatory_list_success(self, m_sub, m_connect):
        self.dc.sw_list = '\n  trtl\n     docker\n'
        self.assertEqual(self.dc._check_sw_mandatory_list('docker'), True)

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    def test_check_sw_mandatory_missing_sw_in_list(self, m_sub, m_connect):
        self.dc.sw_list = '  trtl\n  '
        self.assertEqual(self.dc._check_sw_mandatory_list('docker'), False)

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    def test_check_sw_mandatory_wrong_sw(self, m_sub, m_connect):
        self.dc.sw_list = '  trtl\n docker\n '
        self.assertEqual(self.dc._check_sw_mandatory_list('test'), False)

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    def test_check_sw_mandatory_None_sw_list(self, m_sub, m_connect):
        self.dc.sw_list = None
        self.assertEqual(self.dc._check_sw_mandatory_list('test'), False)

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    def test_check_sw_mandatory_list_NoneSW(self, m_sub, m_connect):
        self.dc.sw_list = '  trtl\n docker\n '
        self.assertEqual(self.dc._check_sw_mandatory_list(None), False)

    @unpack
    @data((MIN_MEMORY_MB, 10), (MIN_STORAGE_MB, 20), (DOCKER_BENCH_SECURITY_INTERVAL_SEC, 30), (MIN_POWER_PERCENT, 5), (NETWORK_CHECK, 'false'))
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    def test_set_configuration_value_fail_lower(self, path, val, mock_subscribe, mock_connect):
        self.dc.set_configuration_value(val, path)
        if path == MIN_MEMORY_MB:
            self.assertEquals(self.dc._min_memory_MB.config_value, 10)
        elif path == MIN_STORAGE_MB:
            self.assertEquals(self.dc._min_storage_MB.config_value, 100)
        elif path == DOCKER_BENCH_SECURITY_INTERVAL_SEC:
            self.assertEquals(self.dc.docker_bench_security_interval_sec.config_value, 900)
        elif path == MIN_POWER_PERCENT:
            self.assertEquals(self.dc._min_power_percent.config_value, 20)
        elif path == NETWORK_CHECK:
            self.assertEquals(self.dc._network_check, 'false')

    @unpack
    @data((MIN_MEMORY_MB, 350), (MIN_STORAGE_MB, 200), (DOCKER_BENCH_SECURITY_INTERVAL_SEC, 18001),
          (MIN_POWER_PERCENT, 85))
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    def test_set_configuration_value_fail_higher(self,  path, val, mock_subscribe, mock_connect):
        self.dc.set_configuration_value(val, path)
        if path == MIN_MEMORY_MB:
            self.assertEquals(self.dc._min_memory_MB.config_value, DEFAULT_MIN_MEMORY_MB)
        elif path == MIN_STORAGE_MB:
            self.assertEquals(self.dc._min_storage_MB.config_value, DEFAULT_MIN_STORAGE_MB)
        elif path == DOCKER_BENCH_SECURITY_INTERVAL_SEC:
            self.assertEquals(self.dc.docker_bench_security_interval_sec.config_value,
                              DEFAULT_DOCKER_BENCH_SECURITY_INTERVAL_SEC)
        elif path == MIN_POWER_PERCENT:
            self.assertEquals(self.dc._min_power_percent.config_value, DEFAULT_MIN_POWER_PERCENT)

    @unpack
    @data((MIN_MEMORY_MB, 150), (MIN_STORAGE_MB, 120), (DOCKER_BENCH_SECURITY_INTERVAL_SEC, 1000),
          (MIN_POWER_PERCENT, 17))
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    def test_set_configuration_value_success(self, path, val, mock_subscribe, mock_connect):
        self.dc.set_configuration_value(val, path)
        if path == MIN_MEMORY_MB:
            self.assertEquals(self.dc._min_memory_MB.config_value, 150)
        elif path == MIN_STORAGE_MB:
            self.assertEquals(self.dc._min_storage_MB.config_value, 120)
        elif path == DOCKER_BENCH_SECURITY_INTERVAL_SEC:
            self.assertEquals(self.dc.docker_bench_security_interval_sec.config_value,
                              1000)
        elif path == MIN_POWER_PERCENT:
            self.assertEquals(self.dc._min_power_percent.config_value, 17)

    @patch("inbm_common_lib.shell_runner.PseudoShellRunner.run",
           return_value=('eth0', "", 0))
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('diagnostic.command_pattern.get_free_space', return_value=50000000)
    def test_execute_success(self, mock_free_space, mock_sub, mock_connect, mock_publish, mock_run):
        request = {'id': 123, 'cmd': 'install_check', 'size': None}
        self.dc.execute(request)
