import unittest
from unittest import TestCase
from mock import patch
import os

from configuration.configuration import LoggingPath, Configuration


class TestConfiguration(TestCase):

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client', autospec=True)
    def test_service_name_prefixed_inbm(self, MockClient):
        c = Configuration()
        self.assertFalse(' ' in c._svc_name_)
        self.assertEqual(c._svc_name_.split('-')[0], 'inbm')


class TestLoggingPath(TestCase):

    @patch.dict(os.environ, {'LOGGERCONFIG': '/var/logs'})
    def test_get_os_set_logging_path(self):
        self.assertEqual(LoggingPath.get_log_config_path(), '/var/logs')

    def test_get_os_not_set_logging_path(self):
        self.assertEqual(LoggingPath.get_log_config_path(),
                         '/etc/intel-manageability/public/configuration-agent/logging.ini')


if __name__ == '__main__':
    unittest.main()
