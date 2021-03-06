import sys, os
from inbm_common_lib.pms.pms_helper import PMSHelper, PmsException
from mock import patch, Mock, MagicMock
from unittest import TestCase


class TestPMSHelper(TestCase):
    def setUp(self):
        self.pms = PMSHelper()

    def test_import_pms_library_success(self):
        sys.path.insert(0, os.path.dirname(__file__))
        self.pms._import_pms_library()

    def test_import_pms_library_fail(self):
        self.assertRaises(PmsException, self.pms._import_pms_library)

    @patch('libPmsPython.PmsConnectionType')
    @patch('libPmsPython.PmsConnection.Connect', return_value=False)
    def test_telemetry_with_pms_connection_error(self, mock_connect, mock_type):
        sys.path.insert(0, os.path.dirname(__file__))
        self.assertRaises(PmsException, self.pms.get_rm_telemetry)
        mock_connect.assert_called_once()

    @patch('libPmsPython.PmsConnection.Connect', return_value=False)
    def test_reset_device_with_pms_connection_error(self, mock_connect):
        sys.path.insert(0, os.path.dirname(__file__))
        self.assertRaises(PmsException, self.pms.reset_device, '12345')
        mock_connect.assert_called_once()

    @patch('libPmsPython.PmsReset.ResetRequest', return_value=-1)
    @patch('libPmsPython.PmsConnection.Connect', return_value=True)
    def test_reset_device_with_reset_device_fail(self, connect, reset):
        sys.path.insert(0, os.path.dirname(__file__))
        self.assertRaises(PmsException, self.pms.reset_device, '12345')
        connect.assert_called_once()
        reset.assert_called_once()

    @patch('libPmsPython.PmsConnection.Connect', return_value=True)
    def test_reset_device_success(self, connect):
        sys.path.insert(0, os.path.dirname(__file__))
        self.pms.reset_device('12345')
        connect.assert_called_once()
