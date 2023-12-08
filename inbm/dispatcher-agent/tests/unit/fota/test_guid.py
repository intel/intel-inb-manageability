from unittest import TestCase
from unittest.mock import patch

from unit.common.mock_resources import *
from dispatcher.fota.guid import _parse_guids, extract_guids
from dispatcher.fota.fota_error import FotaError


class TestGuid(TestCase):

    @patch('dispatcher.fota.guid.PseudoShellRunner.run',
           return_value=("System Firmware type,{6B29FC40-CA47-1067-B31D-00DD010662D} version 27 is updatable", "", 0))
    def test_find_the_guid(self, mock_shell):
        self.assertEqual(extract_guids("tool", ['Firmware', 'foo']), ["6B29FC40-CA47-1067-B31D-00DD010662D"])

    @patch('dispatcher.fota.guid.PseudoShellRunner.run',
        return_value=("System Firmware type,{6B29FC40-CA47-1067-B31D-00DD010662D} version 27 is updatable", "", 0))
    def test_not_find_the_guid_and_raise_exception(self, mock_shell):
        with self.assertRaises(FotaError):
            self.assertEqual(extract_guids("tool", ['foo', 'bar']), [])

    @patch('dispatcher.fota.guid.PseudoShellRunner.run',
           return_value=("", "", 1))
    def test_raise_on_error_code_extracting_guid(self, mock_shell):
        with self.assertRaises(FotaError):
            extract_guids("tool", ['System', 'system'])

    @patch('dispatcher.fota.guid.PseudoShellRunner.run',
           return_value=("", "", 0))
    def test_raise_error_when_no_guid(self, mock_shell):
        with self.assertRaises(FotaError) as cm:
            extract_guids("tool", ['System', 'system'])
            self.assertEqual(
                str(cm.exception),
                "Firmware Update Aborted: No GUIDs found matching types: ['System', 'system']"
            )

    def test_parse_guid(self):
        output = 'System Firmware type,{6B29FC40-CA47-1067-B31D-00DD010662D} version 27 is updatable'
        result = _parse_guids(output, ['System Firmware'])
        self.assertEquals(result, ['6B29FC40-CA47-1067-B31D-00DD010662D'])

    def test_parse_guid_new_string(self):
        output = 'system-firmware type,{6B29FC40-CA47-1067-B31D-00DD010662D} version 27 is updatable'
        result = _parse_guids(output, ['system-firmware'])
        self.assertEqual(result, ['6B29FC40-CA47-1067-B31D-00DD010662D'])

    def test_parse_guid_none(self):
        output = ''
        result = _parse_guids(output, [])
        self.assertEqual(result, [])
