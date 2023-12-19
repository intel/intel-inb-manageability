import logging

from unittest import TestCase
from unittest.mock import patch

from inbc.inbc import Inbc
from inbc.parser.parser import ArgsParser

logger = logging.getLogger(__name__)


class TestSourceOsParser(TestCase):
    def setUp(self):
        self.arg_parser = ArgsParser()
        self.maxDiff = None

    def test_parse_add_arguments_successfully(self):
        f = self.arg_parser.parse_args(
            ['source', 'os', 'add',
             '-sources', 'deb http://example.com/ focal main restricted universe',
             'deb-src http://example.com/ focal-security main'])
        self.assertEqual(f.s, ['deb http://example.com/ focal main restricted universe',
                               'deb-src http://example.com/ focal-security main'])

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    def test_create_add_manifest_successfully(self, m_connect):
        p = self.arg_parser.parse_args(
            ['source', 'os', 'add',
             '-sources', 'deb http://example.com/ focal main restricted universe',
                         'deb-src http://example.com/ focal-security main'])
        Inbc(p, 'source', False)
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>source</type><osSource>' \
                   '<add><repos>' \
                   '<source_pkg>deb http://example.com/ focal main restricted universe</source_pkg>' \
                   '<source_pkg>deb-src http://example.com/ focal-security main</source_pkg>' \
                   '</repos></add></osSource></manifest>'
        self.assertEqual(p.func(p), expected)

    def test_parse_remove_arguments_successfully(self):
        f = self.arg_parser.parse_args(
            ['source', 'os', 'remove',
             '-sources', 'deb http://example.com/ focal main restricted universe',
             'deb-src http://example.com/ focal-security main'])
        self.assertEqual(f.s, ['deb http://example.com/ focal main restricted universe',
                         'deb-src http://example.com/ focal-security main'])

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    def test_create_remove_manifest_successfully(self, m_connect):
        p = self.arg_parser.parse_args(
            ['source', 'os', 'remove',
             '-sources', 'deb http://example.com/ focal main restricted universe',
                         'deb-src http://example.com/ focal-security main'])
        Inbc(p, 'source', False)
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>source</type><osSource>' \
                   '<remove><repos>' \
                   '<source_pkg>deb http://example.com/ focal main restricted universe</source_pkg>' \
                   '<source_pkg>deb-src http://example.com/ focal-security main</source_pkg>' \
                   '</repos></remove></osSource></manifest>'
        self.assertEqual(p.func(p), expected)

    def test_parse_update_arguments_successfully(self):
        f = self.arg_parser.parse_args(
            ['source', 'os', 'update',
             '-sources',
             'deb http://example.com/ focal main restricted universe',
             'deb-src http://example.com/ focal-security main'])
        self.assertEqual(f.s, ['deb http://example.com/ focal main restricted universe',
                         'deb-src http://example.com/ focal-security main'])

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    def test_create_update_manifest_successfully(self, m_connect):
        p = self.arg_parser.parse_args(
            ['source', 'os', 'update',
             '-sources', 'deb http://example.com/ focal main restricted universe',
                         'deb-src http://example.com/ focal-security main'])
        Inbc(p, 'source', False)
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>source</type><osSource>' \
                   '<update><repos>' \
                   '<source_pkg>deb http://example.com/ focal main restricted universe</source_pkg>' \
                   '<source_pkg>deb-src http://example.com/ focal-security main</source_pkg>' \
                   '</repos></update></osSource></manifest>'
        self.assertEqual(p.func(p), expected)

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    def test_create_list_manifest_successfully(self, m_connect):
        p = self.arg_parser.parse_args(
            ['source', 'os', 'list'])
        Inbc(p, 'source', False)
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>source</type><osSource>' \
                   '<list/></osSource></manifest>'
        self.assertEqual(p.func(p), expected)
