import sys
import os
from inbm_common_lib.pms.pms_helper import PMSHelper, PmsException
from unittest.mock import patch, Mock, MagicMock
from unittest import TestCase


class TestPMSHelper(TestCase):
    def setUp(self) -> None:
        self.pms = PMSHelper()

    def test_import_pms_library_success(self) -> None:
        sys.path.insert(0, os.path.dirname(__file__))
        self.pms._import_pms_library()

    def test_import_pms_library_fail(self) -> None:
        self.assertRaises(PmsException, self.pms._import_pms_library)

    @patch('libPmsPython.PmsConnectionType')
    @patch('libPmsPython.PmsConnection.Connect', return_value=False)
    def test_telemetry_with_pms_connection_error(self, mock_connect: Mock, mock_type: Mock) -> None:
        sys.path.insert(0, os.path.dirname(__file__))
        self.assertRaises(PmsException, self.pms.get_rm_telemetry)
        mock_connect.assert_called_once()

    @patch('libPmsPython.PmsConnection.Connect', return_value=False)
    def test_reset_device_with_pms_connection_error(self, mock_connect: Mock) -> None:
        sys.path.insert(0, os.path.dirname(__file__))
        self.assertRaises(PmsException, self.pms.reset_device, '12345')
        mock_connect.assert_called_once()

    @patch('libPmsPython.PmsReset.ResetRequest', return_value=-1)
    @patch('libPmsPython.PmsConnection.Connect', return_value=True)
    def test_reset_device_with_reset_device_fail(self, connect: Mock, reset: Mock) -> None:
        sys.path.insert(0, os.path.dirname(__file__))
        self.assertRaises(PmsException, self.pms.reset_device, '12345')
        connect.assert_called_once()
        reset.assert_called_once()

    @patch('libPmsPython.PmsConnection.Connect', return_value=True)
    def test_reset_device_success(self, connect: Mock) -> None:
        sys.path.insert(0, os.path.dirname(__file__))
        self.pms.reset_device('12345')
        connect.assert_called_once()
