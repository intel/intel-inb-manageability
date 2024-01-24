import os
import unittest
from unittest import TestCase

from ddt import data, ddt, unpack
from diagnostic.constants import CMD_CHANNEL, STATE_CHANNEL, CONFIGURATION_UPDATE_CHANNEL, \
    MIN_MEMORY_MB, MIN_STORAGE_MB, DOCKER_BENCH_SECURITY_INTERVAL_SEC, MIN_POWER_PERCENT, NETWORK_CHECK
from diagnostic.main import Diagnostic, LoggingPath
from unittest.mock import patch, ANY

from diagnostic.constants import DEFAULT_MIN_MEMORY_MB
from diagnostic.constants import DEFAULT_MIN_POWER_PERCENT
from diagnostic.constants import DEFAULT_MIN_STORAGE_MB
from diagnostic.constants import DEFAULT_DOCKER_BENCH_SECURITY_INTERVAL_SEC


@ddt
class TestDiagnostic(TestCase):

    @staticmethod
    @patch('diagnostic.main.LoggingPath.get_log_config_path',
           return_value='./fpm-template/etc/intel-manageability/public/diagnostic-agent/logging.ini')
    def _build_diagnostic(mock_logger):
        return Diagnostic()


class TestLoggingPath(TestCase):

    @patch.dict(os.environ, {'LOGGERCONFIG': '/var/logs'})
    def test_get_os_set_logging_path(self):
        self.assertEqual(LoggingPath.get_log_config_path(), '/var/logs')

    def test_get_os_not_set_logging_path(self):
        self.assertEqual(LoggingPath.get_log_config_path(),
                         '/etc/intel-manageability/public/diagnostic-agent/logging.ini')


if __name__ == '__main__':
    unittest.main()
