from unittest import TestCase

from mock import patch
from unit.common.mock_resources import *
from dispatcher.fota.guid import _parse_guid, extract_guid


class TestGuid(TestCase):
    def test_parse_guid(self):
        output = 'System Firmware type,{6B29FC40-CA47-1067-B31D-00DD010662D} version 27 is updatable'
        result = _parse_guid(output)
        self.assertEquals(result, '6B29FC40-CA47-1067-B31D-00DD010662D')

    def test_parse_guid_new_string(self):
        output = 'system-firmware type,{6B29FC40-CA47-1067-B31D-00DD010662D} version 27 is updatable'
        result = _parse_guid(output)
        self.assertEquals(result, '6B29FC40-CA47-1067-B31D-00DD010662D')

    def test_parse_guid_none(self):
        output = ''
        result = _parse_guid(output)
        self.assertEquals(result, None)

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run',
           return_value=('system-firmware type,{6B29FC40-CA47-1067-B31D-00DD010662D} version 27 is updatable', '', 0))
    def test_extra_guid(self, mock_runner):
        self.assertEquals(extract_guid("tool"), "6B29FC40-CA47-1067-B31D-00DD010662D")
