from telemetry.constants import DEFAULT_LOGGING_PATH
from telemetry.telemetry import PathLogger, Telemetry
from mock import patch
from unittest import TestCase
import os


class TestTelemetry(TestCase):

    @patch('telemetry.telemetry.fileConfig', autospec=True)
    def test_service_name_prefixed_inbm(self, fileconfig) -> None:
        t = Telemetry()
        self.assertFalse(' ' in t._svc_name_)
        self.assertEqual(t._svc_name_.split('-')[0], 'inbm')


class TestLoggingPath(TestCase):

    @patch.dict(os.environ, {'LOGGERCONFIG': '/var/logs'})
    def test_get_os_set_logging_path(self) -> None:
        self.assertEqual(PathLogger.get_log_config_path(), '/var/logs')

    def test_get_os_not_set_logging_path(self) -> None:
        self.assertEqual(PathLogger.get_log_config_path(), DEFAULT_LOGGING_PATH)
