from unittest import TestCase
import os

from .common.mock_resources import *
from dispatcher.ota_parser import AotaParser, SotaParser, PotaParser, FotaParser
from inbm_lib.xmlhandler import XmlHandler

TEST_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                    '../../fpm-template/usr/share/dispatcher-agent/'
                                    'manifest_schema.xsd')


class TestOtaParser(TestCase):

    def setUp(self):
        self.resource = {'username': 'tj', 'password': 'tj123'}
        self.parsed = MockXmlFunctions(fake_ota_invalid, is_file=False,
                                       schema_location=TEST_SCHEMA_LOCATION)

    def test_parse_aota_a(self):
        result = AotaParser('remote').parse(
            {'cmd': '', 'app': '', 'fetch': 'https://www.google.com/'}, {}, self.parsed)
        self.assertTrue('signature' in result)

    def test_parse_aota_b(self):
        result = AotaParser('remote').parse(
            {'cmd': 'cmd_1', 'app': 'app_1', 'fetch': 'http://www.google.com/'}, {}, self.parsed)
        self.assertTrue('google' in str(result))

    def test_parse_sota_a(self):
        result = SotaParser('remote').parse(
            {'cmd': '', 'signature': '', 'release_date': '', 'fetch': 'https://www.google.com/'}, {}, self.parsed)
        self.assertTrue('hash_algorithm' in result)

    def test_parse_pota_a(self):
        p = PotaParser('remote')
        result = p.parse(
            {'fota': '', 'sota': '', 'targetType': 'node', 'targets': ' ', 'fetch': 'https://www.google.com/'}, {}, self.parsed)
        self.assertTrue('fota' in result)


class MockXmlFunctions(XmlHandler):

    def get_attribute(self, x, y):
        return 'xy'

    def get_children(self, x):
        return {'type': 'fota', 'fetch': 'https://www.google.com/'}
