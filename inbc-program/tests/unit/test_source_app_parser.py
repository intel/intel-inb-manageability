import pytest
from unittest import TestCase
from unittest.mock import patch

from inbc.inbc import Inbc
from inbc.parser.parser import ArgsParser
from inbc.inbc_exception import InbcException


class TestSourceApplicationParser(TestCase):
    def setUp(self):
        self.arg_parser = ArgsParser()
        self.maxDiff = None

    def test_parse_add_all_arguments_successfully(self):
        f = self.arg_parser.parse_args(
            ['source', 'application', 'add',
             '--gpgKeyUri', 'https://repositories.intel.com/gpu/intel-graphics.key',
             '--gpgKeyName', 'intel-graphics.gpg',
             '--sources', 'deb http://example.com/ focal main restricted universe',
             'deb-src http://example.com/ focal-security main',
             '--filename', 'intel-gpu-jammy.list'])
        self.assertEqual(f.gpgKeyUri, 'https://repositories.intel.com/gpu/intel-graphics.key')
        self.assertEqual(f.gpgKeyName, 'intel-graphics.gpg')
        self.assertEqual(f.sources, ['deb http://example.com/ focal main restricted universe',
                                     'deb-src http://example.com/ focal-security main'])
        self.assertEqual(f.filename, 'intel-gpu-jammy.list')

    def test_parse_add_arguments_deb822_format_separate_lines_successfully(self):
        f = self.arg_parser.parse_args(
            ['source', 'application', 'add',
             '--sources', 'X-Repolib-Name: Google Chrome',
             'Enabled: yes',
             'Types: deb',
             'URIs: https://dl-ssl.google.com/linux/linux_signing_key.pub',
             'Suites: stable',
             'Components: main',
             '--filename', 'intel-gpu-jammy.list'])
        self.assertEqual(f.gpgKeyUri, None)
        self.assertEqual(f.gpgKeyName, None)
        self.assertEqual(f.sources, ['X-Repolib-Name: Google Chrome',
                                     'Enabled: yes',
                                     'Types: deb',
                                     'URIs: https://dl-ssl.google.com/linux/linux_signing_key.pub',
                                     'Suites: stable',
                                     'Components: main'])
        self.assertEqual(f.filename, 'intel-gpu-jammy.list')

    def test_raise_application_add_with_only_one_gpgKeyUri_param(self):
        with patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect') as m_connect:
            p = self.arg_parser.parse_args(
                ['source', 'application', 'add',
                 '--gpgKeyUri', 'https://repositories.intel.com/gpu/intel-graphics.key',
                 '--sources', 'deb http://example.com/ focal main restricted universe',
                 'deb-src http://example.com/ focal-security main',
                 '--filename', 'intel-gpu-jammy.list'])
            with pytest.raises(InbcException,
                               match="Source requires either both gpgKeyUri and gpgKeyName "
                                     "to be provided, or neither of them."):
                Inbc(p, 'source', False)

    def test_raise_application_add_with_only_one_gpgKeyName_param(self):
        with patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect') as m_connect:
            p = self.arg_parser.parse_args(
                ['source', 'application', 'add',
                 '--gpgKeyName', 'intel-graphics.gpg',
                 '--sources', 'deb http://example.com/ focal main restricted universe',
                 'deb-src http://example.com/ focal-security main',
                 '--filename', 'intel-gpu-jammy.list'])
            with pytest.raises(InbcException,
                               match="Source requires either both gpgKeyUri and gpgKeyName "
                                     "to be provided, or neither of them."):
                Inbc(p, 'source', False)

    def test_create_add_deb_822_format_manifest_successfully(self):
        p = self.arg_parser.parse_args(
            ['source', 'application', 'add',
             '--sources', 'X-Repolib-Name: Google Chrome',
             'Enabled: yes',
             'Types: deb',
             'URIs: https://dl-ssl.google.com/linux/linux_signing_key.pub',
             'Suites: stable',
             'Components: main',
             '--filename', 'google-chrome.sources'])
        with patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect') as m_connect:
            Inbc(p, 'source', False)
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>source</type><applicationSource>' \
                   '<add><repo><repos><source_pkg>X-Repolib-Name: Google Chrome</source_pkg>' \
                   '<source_pkg>Enabled: yes</source_pkg>' \
                   '<source_pkg>Types: deb</source_pkg>' \
                   '<source_pkg>URIs: https://dl-ssl.google.com/linux/linux_signing_key.pub</source_pkg>' \
                   '<source_pkg>Suites: stable</source_pkg>' \
                   '<source_pkg>Components: main</source_pkg>' \
                   '</repos><filename>google-chrome.sources</filename></repo></add></applicationSource></manifest>'
        self.assertEqual(p.func(p), expected)

    def test_create_add_all_param_manifest_successfully(self):
        p = self.arg_parser.parse_args(
            ['source', 'application', 'add',
             '--gpgKeyUri', 'https://repositories.intel.com/gpu/intel-graphics.key',
             '--gpgKeyName', 'intel-graphics.gpg',
             '--sources', 'deb http://example.com/ focal main restricted universe',
             'deb-src http://example.com/ focal-security main',
             '--filename', 'intel-gpu-jammy.list'])
        with patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect') as m_connect:
            Inbc(p, 'source', False)
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>source</type><applicationSource>' \
                   '<add><gpg><uri>https://repositories.intel.com/gpu/intel-graphics.key</uri>' \
                   '<keyname>intel-graphics.gpg</keyname></gpg><repo><repos>' \
                   '<source_pkg>deb http://example.com/ focal main restricted universe</source_pkg>' \
                   '<source_pkg>deb-src http://example.com/ focal-security main</source_pkg>' \
                   '</repos><filename>intel-gpu-jammy.list</filename></repo></add></applicationSource></manifest>'
        self.assertEqual(p.func(p), expected)

    def test_create_add_minus_gpg_manifest_successfully(self):
        p = self.arg_parser.parse_args(
            ['source', 'application', 'add',
             '--sources', 'deb http://example.com/ focal main restricted universe',
             'deb-src http://example.com/ focal-security main',
             '--filename', 'intel-gpu-jammy.list'])
        with patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect') as m_connect:
            Inbc(p, 'source', False)
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>source</type><applicationSource>' \
                   '<add><repo><repos>' \
                   '<source_pkg>deb http://example.com/ focal main restricted universe</source_pkg>' \
                   '<source_pkg>deb-src http://example.com/ focal-security main</source_pkg>' \
                   '</repos><filename>intel-gpu-jammy.list</filename></repo></add></applicationSource></manifest>'
        self.assertEqual(p.func(p), expected)

    def test_parse_all_remove_arguments_successfully(self):
        f = self.arg_parser.parse_args(
            ['source', 'application', 'remove',
             '--gpgKeyName', 'intel-gpu-jammy.gpg',
             '--filename', 'intel-gpu-jammy.list'])
        self.assertEqual(f.gpgKeyName, 'intel-gpu-jammy.gpg')
        self.assertEqual(f.filename, 'intel-gpu-jammy.list')

    def test_parse_minus_gpg_remove_arguments_successfully(self):
        f = self.arg_parser.parse_args(
            ['source', 'application', 'remove',
             '--filename', 'intel-gpu-jammy.list'])
        self.assertEqual(f.gpgKeyName, None)
        self.assertEqual(f.filename, 'intel-gpu-jammy.list')

    def test_create_remove_manifest_all_params_successfully(self):
        p = self.arg_parser.parse_args(
            ['source', 'application', 'remove',
             '--gpgKeyName', 'intel-gpu-jammy.gpg',
             '--filename', 'intel-gpu-jammy.list'])
        with patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect') as m_connect:
            Inbc(p, 'source', False)
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>source</type><applicationSource>' \
                   '<remove><gpg><keyname>intel-gpu-jammy.gpg</keyname></gpg>' \
                   '<repo><filename>intel-gpu-jammy.list</filename></repo></remove></applicationSource></manifest>'
        self.assertEqual(p.func(p), expected)

    def test_create_remove_manifest_minus_gpg_successfully(self):
        p = self.arg_parser.parse_args(
            ['source', 'application', 'remove',
             '--filename', 'intel-gpu-jammy.list'])
        with patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect') as m_connect:
            Inbc(p, 'source', False)
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>source</type><applicationSource><remove>' \
                   '<repo><filename>intel-gpu-jammy.list</filename></repo></remove></applicationSource></manifest>'
        self.assertEqual(p.func(p), expected)

    def test_parse_update_arguments_successfully(self):
        f = self.arg_parser.parse_args(
            ['source', 'application', 'update',
             '--sources', 'deb http://example.com/ focal main restricted universe',
             'deb-src http://example.com/ focal-security main',
             '--filename', 'intel-gpu-jammy.list'])
        self.assertEqual(f.sources, ['deb http://example.com/ focal main restricted universe',
                                     'deb-src http://example.com/ focal-security main'])
        self.assertEqual(f.filename, 'intel-gpu-jammy.list')

    def test_create_update_manifest_successfully(self):
        p = self.arg_parser.parse_args(
            ['source', 'application', 'update',
             '--sources', 'deb http://example.com/ focal main restricted universe',
             'deb-src http://example.com/ focal-security main',
             '--filename', 'intel-gpu-jammy.list'])
        with patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect') as m_connect:
            Inbc(p, 'source', False)
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>source</type><applicationSource>' \
                   '<update><repo><repos><source_pkg>deb http://example.com/ focal main restricted universe' \
                   '</source_pkg><source_pkg>deb-src http://example.com/ focal-security main</source_pkg>' \
                   '</repos><filename>intel-gpu-jammy.list</filename></repo></update></applicationSource></manifest>'
        self.assertEqual(p.func(p), expected)

    def test_create_list_manifest_successfully(self):
        p = self.arg_parser.parse_args(
            ['source', 'application', 'list'])
        with patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect') as m_connect:
            Inbc(p, 'source', False)
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>source</type><applicationSource>' \
                   '<list/></applicationSource></manifest>'
        self.assertEqual(p.func(p), expected)
