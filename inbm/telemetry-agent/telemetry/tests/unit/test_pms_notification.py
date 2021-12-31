import sys
import os
import logging
from future import standard_library
from mock import patch, Mock, MagicMock
from telemetry.pms_notification import PMSNotification, PmsException
from telemetry.telemetry_handling import publish_telemetry_update
from inbm_lib.mqttclient.mqtt import MQTT
from unittest import TestCase
standard_library.install_aliases()

logger = logging.getLogger(__name__)


class TestPMSNotification(TestCase):
    def setUp(self):
        self.pmsn = PMSNotification(MQTT)

    def test_import_pmslibrary_success(self):
        sys.path.insert(0, os.path.dirname(__file__))
        self.pmsn.import_pms_library()

    def test_import_pmslibrary_fail(self):
        self.assertRaises(PmsException, self.pmsn.import_pms_library)

    @patch('telemetry.telemetry_handling.publish_dynamic_telemetry')
    @patch('libPmsPython.PmsConnectionType')
    @patch('libPmsPython.PmsConnection.Connect', return_value=False)
    def test_telemetry_with_pms_notification(self, mock_connect, mock_type, mock_telemetry):
        sys.path.insert(0, os.path.dirname(__file__))
        self.pmsn.register_pms_notification(Mock())
        mock_connect.assert_called_once()
        mock_telemetry.assert_called_once()
