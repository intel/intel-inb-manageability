from unittest import TestCase

from unit.common.mock_resources import *
from dispatcher.fota.guid import _parse_guid


class TestGuid(TestCase):
    def test_parse_guid(self) -> None:
        output = 'System Firmware type,{6B29FC40-CA47-1067-B31D-00DD010662D} version 27 is updatable'
        result = _parse_guid(output)
        self.assertEqual(result, '6B29FC40-CA47-1067-B31D-00DD010662D')

    def test__parse_guid_new_string(self) -> None:
        output = 'system-firmware type,{6B29FC40-CA47-1067-B31D-00DD010662D} version 27 is updatable'
        result = _parse_guid(output)
        self.assertEqual(result, '6B29FC40-CA47-1067-B31D-00DD010662D')

    def test__parse_guid_none(self) -> None:
        output = ''
        result = _parse_guid(output)
        self.assertEqual(result, None)
