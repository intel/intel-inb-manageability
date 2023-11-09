import datetime
from unittest import TestCase

from unit.common.mock_resources import *
from inbm_lib.xmlhandler import XmlHandler
from dispatcher.fota.manifest import parse, parse_tool_options, parse_guid
import os

TEST_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                    '../../../fpm-template/usr/share/dispatcher-agent/'
                                    'manifest_schema.xsd')


class TestManifest(TestCase):

    def test_parses_valid_manifest_successfully(self):
        parsed = XmlHandler(fake_ota_success, is_file=False, schema_location=TEST_SCHEMA_LOCATION)
        resource = parsed.get_children('ota/type/fota')

        manifest_info = parse(resource)
        self.assertEqual('test', manifest_info.bios_vendor)
        self.assertEqual('A.B.D.E.F', manifest_info.bios_version)
        self.assertEqual(datetime.datetime.strptime(
            '06/12/2017', "%m/%d/%Y"), manifest_info.bios_release_date)
        self.assertEqual('testmanufacturer', manifest_info.platform_mfg)
        self.assertEqual('testproduct', manifest_info.platform_product)

    def test_parses_without_tool_options(self):
        parsed = XmlHandler(fake_ota_no_tool_option, is_file=False,
                            schema_location=TEST_SCHEMA_LOCATION)
        resource = parsed.get_children('ota/type/fota')

        tool_options = parse_tool_options(resource)
        self.assertEqual(None, tool_options)

    def test_parses_with_tool_options(self):
        parsed = XmlHandler(fake_ota_success, is_file=False, schema_location=TEST_SCHEMA_LOCATION)
        resource = parsed.get_children('ota/type/fota')

        tool_options = parse_tool_options(resource)
        self.assertEqual('/p /b', tool_options)

    def test_parses_with_guid(self):
        parsed = XmlHandler(fake_fota_guid, is_file=False, schema_location=TEST_SCHEMA_LOCATION)
        resource = parsed.get_children('ota/type/fota')

        guid = parse_guid(resource)
        self.assertEqual('6B29FC40-CA47-1067-B31D-00DD010662DA', guid)

    def test_parses_without_guid(self):
        parsed = XmlHandler(fake_fota_no_guid, is_file=False, schema_location=TEST_SCHEMA_LOCATION)
        resource = parsed.get_children('ota/type/fota')

        guid = parse_guid(resource)
        self.assertEqual(None, guid)
