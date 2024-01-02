from unittest import TestCase
from unittest.mock import patch

from inbc.inbc import Inbc
from inbc.parser.parser import ArgsParser


class TestSourceApplicationParser(TestCase):
    def setUp(self):
        self.arg_parser = ArgsParser()
        self.maxDiff = None

    def test_parse_add_arguments_successfully(self):
        f = self.arg_parser.parse_args(
            ['source', 'application', 'add',
             '-gpgKeyPath', 'https://repositories.intel.com/gpu/intel-graphics.key',
             '-gpgKeyName', 'intel-graphics.gpg',
             '-source', 'echo "deb https://repositories.intel.com/gpu/ubuntu jammy/production/2328 unified"',
             '-fileName', 'intel-gpu-jammy.list'])
        self.assertEqual(f.gkp, 'https://repositories.intel.com/gpu/intel-graphics.key')
        self.assertEqual(f.gkn, 'intel-graphics.gpg')
        self.assertEqual(f.s, 'echo "deb https://repositories.intel.com/gpu/ubuntu jammy/production/2328 unified"')
        self.assertEqual(f.f, 'intel-gpu-jammy.list')

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    def test_create_add_manifest_successfully(self, m_connect):
        p = self.arg_parser.parse_args(
            ['source', 'application', 'add',
             '-gpgKeyPath', 'https://repositories.intel.com/gpu/intel-graphics.key',
             '-gpgKeyName', 'intel-graphics.gpg',
             '-source', 'echo "deb https://repositories.intel.com/gpu/ubuntu jammy/production/2328 unified"',
             '-fileName', 'intel-gpu-jammy.list'])
        Inbc(p, 'source', False)
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>source</type><applicationSource>' \
                   '<add><gpg><path>https://repositories.intel.com/gpu/intel-graphics.key</path>' \
                   '<keyname>intel-graphics.gpg</keyname></gpg><repo><source>' \
                   'echo &quot;deb https://repositories.intel.com/gpu/ubuntu jammy/production/2328 unified&quot;' \
                   '</source><filename>intel-gpu-jammy.list</filename></repo></add></applicationSource></manifest>'
        self.assertEqual(p.func(p), expected)

    def test_parse_remove_arguments_successfully(self):
        f = self.arg_parser.parse_args(
            ['source', 'application', 'remove',
             '-gpgKeyId', '46C1680FC119E61A501811823A319F932D945953',
             '-fileName', 'intel-gpu-jammy.list'])
        self.assertEqual(f.gki, '46C1680FC119E61A501811823A319F932D945953')
        self.assertEqual(f.f, 'intel-gpu-jammy.list')

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    def test_create_remove_manifest_successfully(self, m_connect):
        p = self.arg_parser.parse_args(
            ['source', 'application', 'remove',
             '-gpgKeyId', '46C1680FC119E61A501811823A319F932D945953',
             '-fileName', 'intel-gpu-jammy.list'])
        Inbc(p, 'source', False)
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>source</type><applicationSource>' \
                   '<remove><gpg><keyid>46C1680FC119E61A501811823A319F932D945953</keyid></gpg>' \
                   '<repo><filename>intel-gpu-jammy.list</filename></repo></remove></applicationSource></manifest>'
        self.assertEqual(p.func(p), expected)

    def test_parse_update_arguments_successfully(self):
        f = self.arg_parser.parse_args(
            ['source', 'application', 'update',
             '-source',
             'echo "deb https://repositories.intel.com/gpu/ubuntu jammy/production/2328 unified"',
             '-fileName', 'intel-gpu-jammy.list'])
        self.assertEqual(f.s,
                         'echo "deb https://repositories.intel.com/gpu/ubuntu jammy/production/2328 unified"')
        self.assertEqual(f.f, 'intel-gpu-jammy.list')

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    def test_create_update_manifest_successfully(self, m_connect):
        p = self.arg_parser.parse_args(
            ['source', 'application', 'update',
             '-source', 'echo "deb https://repositories.intel.com/gpu/ubuntu jammy/production/2328 unified"',
             '-fileName', 'intel-gpu-jammy.list'])
        Inbc(p, 'source', False)
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>source</type><applicationSource>' \
                   '<update><repo><source_pkg>' \
                   'echo &quot;deb https://repositories.intel.com/gpu/ubuntu jammy/production/2328 unified&quot;' \
                   '</source_pkg><filename>intel-gpu-jammy.list</filename></repo></update></applicationSource></manifest>'
        self.assertEqual(p.func(p), expected)

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    def test_create_list_manifest_successfully(self, m_connect):
        p = self.arg_parser.parse_args(
            ['source', 'application', 'list'])
        Inbc(p, 'source', False)
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>source</type><applicationSource>' \
                   '<list/></applicationSource></manifest>'
        self.assertEqual(p.func(p), expected)
