from unittest import TestCase
import os

from .common.mock_resources import *
from dispatcher.ota_parser import AotaParser, SotaParser, PotaParser, FotaParser
from inbm_lib.xmlhandler import XmlHandler

TEST_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                    '../../fpm-template/usr/share/dispatcher-agent/'
                                    'manifest_schema.xsd')


class TestOtaParser(TestCase):

    def setUp(self) -> None:
        self.resource = {'username': 'tj', 'password': 'tj123'}
        self.parsed = MockXmlFunctions(fake_ota_invalid, is_file=False,
                                       schema_location=TEST_SCHEMA_LOCATION)

    def test_parse_aota_with_empty_command_should_include_signature(self) -> None:
        result = AotaParser('remote').parse(
            {'cmd': '', 'app': '', 'fetch': 'https://www.google.com/'}, {}, self.parsed)
        self.assertTrue('signature' in result)

    def test_parse_aota_valid_command_should_contain_fetch(self) -> None:
        result = AotaParser('remote').parse(
            {'cmd': 'cmd_1', 'app': 'app_1', 'fetch': 'http://www.google.com/'}, {}, self.parsed)
        self.assertTrue('google' in str(result))
    
    def test_parse_aota_with_signature_returns_correct_signature(self) -> None:
        result = AotaParser('remote').parse(
            {'cmd': 'cmd_1', 'app': 'app_1', 'fetch': 'http://www.google.com/', 'signature': 'abcdefg', 'sigversion': '384'}, {}, self.parsed)
        self.assertEqual(384, result['hash_algorithm'])
        self.assertEqual('abcdefg', result['signature'])

    def test_parse_sota_empty_fields_should_include_hash_algorithm(self) -> None:
        result = SotaParser('remote').parse(
            {'cmd': '', 'signature': '', 'release_date': '', 'fetch': 'https://www.google.com/'}, {}, self.parsed)
        self.assertTrue('hash_algorithm' in result)

    def test_parse_pota_empty_fields_should_include_fota(self) -> None:
        p = PotaParser('remote')
        result = p.parse(
            {'fota': '', 'sota': '', 'targetType': 'node', 'targets': ' ', 'fetch': 'https://www.google.com/'}, {}, self.parsed)
        self.assertTrue('fota' in result)    


class MockXmlFunctions(XmlHandler):

    def get_attribute(self, x, y) -> str:
        return 'xy'

    def get_children(self, x):
        return {'type': 'fota', 'fetch': 'https://www.google.com/'}
