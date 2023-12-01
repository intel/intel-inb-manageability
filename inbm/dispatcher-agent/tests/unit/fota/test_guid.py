from unittest import TestCase
from mock import patch

from unit.common.mock_resources import *
from dispatcher.fota.guid import _parse_guid, extract_guid
from dispatcher.fota.fota_error import FotaError


class TestGuid(TestCase):

    @patch('dispatcher.fota.guid.PseudoShellRunner.run',
           return_value=("System Firmware type,{6B29FC40-CA47-1067-B31D-00DD010662D} version 27 is updatable", "", 0))
    def test_extract_guid(self, mock_shell):
        self.assertEqual(extract_guid("tool"), "6B29FC40-CA47-1067-B31D-00DD010662D")

    @patch('dispatcher.fota.guid.PseudoShellRunner.run',
           return_value=("", "", 1))
    def test_raise_on_error_code_extracting_guid(self, mock_shell):
        with self.assertRaises(FotaError):
            extract_guid("tool")

    @patch('dispatcher.fota.guid.PseudoShellRunner.run',
           return_value=("", "", 0))
    def test_raise_error_when_no_guid(self, mock_shell):
        with self.assertRaisesRegex(FotaError, "Firmware Update Aborted: No System Firmware type GUID found"):
            extract_guid("tool")

    def test_parse_guid(self):
        output = 'System Firmware type,{6B29FC40-CA47-1067-B31D-00DD010662D} version 27 is updatable'
        result = _parse_guid(output)
        self.assertEqual(result, '6B29FC40-CA47-1067-B31D-00DD010662D')

    def test_parse_guid_new_string(self):
        output = 'system-firmware type,{6B29FC40-CA47-1067-B31D-00DD010662D} version 27 is updatable'
        result = _parse_guid(output)
        self.assertEqual(result, '6B29FC40-CA47-1067-B31D-00DD010662D')

    def test_parse_guid_none(self):
        output = ''
        result = _parse_guid(output)
        self.assertEqual(result, None)
