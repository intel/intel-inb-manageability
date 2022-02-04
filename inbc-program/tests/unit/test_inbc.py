from datetime import datetime
from unittest import TestCase
from inbc.inbc import Inbc
from inbc.parser import ArgsParser, fota, sota, load, get, set
from inbc.constants import COMMAND_FAIL, COMMAND_SUCCESS
from inbc.inbc_exception import InbcCode, InbcException
from inbc.command.ota_command import FotaCommand

from inbm_common_lib.platform_info import PlatformInformation
from inbm_vision_lib.request_message_constants import *
from mock import patch, mock_open, Mock
from io import StringIO

OVER_FIFTY_CHARACTER_STRING = "ThisIsWayTooLongOfAManufacturerNameForThisTestAndMore"
OVER_FIVE_HUNDRED_CHARACTER_STRING = "OverFiveHundredCharacterStringOverFiveHundredCharacterStringOverFiveHundred" \
                                     "CharacterStringOverFiveHundredCharacterStringOverFiveHundredCharacterStringOver" \
                                     "FiveHundredCharacterStringOverFiveHundredCharacterStringOverFiveHundred" \
                                     "CharacterStringOverFiveHundredCharacterStringOverFiveHundredCharacterString" \
                                     "OverFiveHundredCharacterStringOverFiveHundredCharacterStringOverFiveHundred" \
                                     "CharacterStringOverFiveHundredCharacterStringOverFiveHundredCharacterString" \
                                     "OverFiveHundredCharacterStringOverFiveHundredCharacterString"
OVER_ONE_THOUSAND_CHARACTER_STRING = "OverFiveHundredCharacterStringOverFiveHundredCharacterStringOverFiveHundred" \
                                     "CharacterStringOverFiveHundredCharacterStringOverFiveHundredCharacterStringOver" \
                                     "FiveHundredCharacterStringOverFiveHundredCharacterStringOverFiveHundred" \
                                     "CharacterStringOverFiveHundredCharacterStringOverFiveHundredCharacterString" \
                                     "OverFiveHundredCharacterStringOverFiveHundredCharacterStringOverFiveHundred" \
                                     "CharacterStringOverFiveHundredCharacterStringOverFiveHundredCharacterString" \
                                     "OverFiveHundredCharacterStringOverFiveHundredCharacterStringOverFiveHundred" \
                                     "CharacterStringOverFiveHundredCharacterStringOverFiveHundredCharacterStringOver" \
                                     "FiveHundredCharacterStringOverFiveHundredCharacterStringOverFiveHundred" \
                                     "CharacterStringOverFiveHundredCharacterStringOverFiveHundredCharacterString" \
                                     "OverFiveHundredCharacterStringOverFiveHundredCharacterStringOverFiveHundred" \
                                     "CharacterStringOverFiveHundredCharacterStringOverFiveHundredCharacterStringOver" \
                                     "FiveHundredCharacterStringFiveHundredCharacterStringFiveHundredCharacterString" \
                                     "FiveHundredCharacterStringFiveHundredCharacterStringFiveHundredCharacterString" \
                                     "FiveHundredCharacterString"


class TestINBC(TestCase):

    def setUp(self):
        self.arg_parser = ArgsParser()
        self.maxDiff = None

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    def test_hddl_fota_manifest_pass(self, mock_reconnect):
        f = self.arg_parser.parse_args(
            ['fota', '-p', '/var/cache/manageability/repository-tool/BIOS.img',
             '--target', '123ABC', '456DEF'])
        self.assertFalse(f.nohddl)
        self.assertEqual(f.biosversion, '5.12')
        self.assertEqual(f.manufacturer, 'intel')
        self.assertEqual(f.path, '/var/cache/manageability/repository-tool/BIOS.img')
        self.assertEqual(f.product, 'kmb-hddl2')
        self.assertEqual(f.releasedate, '2024-12-31')
        self.assertEqual(f.target, ['123ABC', '456DEF'])
        self.assertEqual(f.vendor, 'Intel')

    def test_non_hddl_fota_manifest_pass(self):
        f = self.arg_parser.parse_args(
            ['fota', '--nohddl', '-un', 'username', '-to', '/b /p', '-u', 'https://abc.com/test.tar'])
        self.assertTrue(f.nohddl)
        self.assertEqual(f.biosversion, '5.12')
        self.assertEqual(f.manufacturer, 'intel')
        self.assertEqual(f.uri, 'https://abc.com/test.tar')
        self.assertEqual(f.product, 'kmb-hddl2')
        self.assertEqual(f.releasedate, '2024-12-31')
        self.assertEqual(f.tooloptions, '/b /p')
        self.assertEqual(f.vendor, 'Intel')
        self.assertEqual(f.username, 'username')

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    def test_non_hddl_sota_manifest_pass(self, mock_reconnect):
        f = self.arg_parser.parse_args(
            ['sota', '--nohddl', '-un', 'username', '-u', 'https://abc.com/test.tar'])
        self.assertTrue(f.nohddl)
        self.assertEqual(f.uri, 'https://abc.com/test.tar')
        self.assertEqual(f.username, 'username')

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    def test_hddl_sota_manifest_pass(self, mock_reconnect):
        f = self.arg_parser.parse_args(
            ['sota', '-p', '/var/cache/manageability/repository-tool/sota.mender',
             '--target', '123ABC', '456DEF'])
        self.assertFalse(f.nohddl)
        self.assertEqual(f.path, '/var/cache/manageability/repository-tool/sota.mender')
        self.assertEqual(f.target, ['123ABC', '456DEF'])

    def test_hddl_load_manifest_pass(self):
        f = self.arg_parser.parse_args(
            ['load', '-p', '/var/cache/manageability/intel_manageability_node.conf',
             '--target', '123ABC', '456DEF'])
        self.assertFalse(f.nohddl)
        self.assertEqual(f.path, '/var/cache/manageability/intel_manageability_node.conf')
        self.assertEqual(f.target, ['123ABC', '456DEF'])

    def test_non_hddl_load_manifest_pass(self):
        f = self.arg_parser.parse_args(
            ['load', '--nohddl', '-u', 'https://abc.com/intel_manageability.conf'])
        self.assertTrue(f.nohddl)
        self.assertEqual(f.uri, 'https://abc.com/intel_manageability.conf')

    @patch('sys.stderr', new_callable=StringIO)
    def test_load_raises_both_path_and_uri(self, mock_stderr):
        with self.assertRaises(SystemExit):
            self.arg_parser.parse_args(
                ['load', '--nohddl', '-p', '/var/cache/manageability/intel_manageability_node.conf',
                 '--uri', 'https://abc.com/intel_manageability.conf'])
        self.assertRegexpMatches(mock_stderr.getvalue(), r"argument --uri/-u: not allowed with argument --path/-p")

    @patch('sys.stderr', new_callable=StringIO)
    def test_load_raises_neither_path_nor_uri(self, mock_stderr):
        with self.assertRaises(SystemExit):
            f = self.arg_parser.parse_args(
                ['load', '--nohddl'])
        self.assertRegexpMatches(mock_stderr.getvalue(), r"error: one of the arguments --uri/-u --path/-p is required")

    @patch('inbc.command.ota_command.FotaCommand.trigger_manifest')
    @patch('sys.stderr', new_callable=StringIO)
    def test_raise_invalid_fota_date_format(self, mock_stderr, mock_trigger):
        with self.assertRaises(SystemExit):
            self.arg_parser.parse_args(
                ['fota', '-p', '/var/cache/manageability/repository-tool/BIOS.img', '-r', '12-31-2024',
                 '-m', 'Intel', '--target', '123ABC', '456DEF'])
        self.assertRegexpMatches(mock_stderr.getvalue(), r"Not a valid date - format YYYY-MM-DD:")

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('sys.stderr', new_callable=StringIO)
    def test_raise_too_long_fota_signature(self, mock_stderr, mock_reconnect):
        with self.assertRaises(SystemExit):
            self.arg_parser.parse_args(['fota', '-p', '/var/cache/manageability/repository-tool/BIOS.img',
                                        '-r', '2024-12-31',
                                        '-m', 'Intel',
                                        '-s', OVER_ONE_THOUSAND_CHARACTER_STRING,
                                        '--target', '123ABC', '456DEF'])
        self.assertRegexpMatches(mock_stderr.getvalue(
        ), r"Signature is greater than allowed string size")

    @patch('sys.stderr', new_callable=StringIO)
    def test_raise_too_long_fota_path(self, mock_stderr):
        with self.assertRaises(SystemExit):
            self.arg_parser.parse_args(['fota', '-p', OVER_FIVE_HUNDRED_CHARACTER_STRING,
                                        '-r', '2024-12-31',
                                        '-m', 'Intel',
                                        '--target', '123ABC', '456DEF'])
        self.assertRegexpMatches(mock_stderr.getvalue(
        ), r"Path is greater than allowed string size")

    @patch('sys.stderr', new_callable=StringIO)
    def test_raise_too_long_fota_manufacturer(self, mock_stderr):
        with self.assertRaises(SystemExit):
            self.arg_parser.parse_args(['fota', '-p', '/var/cache/manageability/repository-tool/BIOS.img',
                                        '-r', '2024-12-31',
                                        '-m', OVER_FIFTY_CHARACTER_STRING,
                                        '--target', '123ABC', '456DEF'])
        self.assertRegexpMatches(mock_stderr.getvalue(
        ), r"Manufacturer is greater than allowed string size")

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('sys.stderr', new_callable=StringIO)
    def test_raise_too_long_fota_vendor(self, mock_stderr, mock_reconnect):
        with self.assertRaises(SystemExit):
            self.arg_parser.parse_args(
                ['fota', '-p', '/var/cache/manageability/repository-tool/BIOS.img',
                 '-r', '2024-12-31', '-v', OVER_FIFTY_CHARACTER_STRING,
                 '--target', '123ABC', '456DEF'])
        self.assertRegexpMatches(mock_stderr.getvalue(
        ), r"Vendor is greater than allowed string size")

    @patch('sys.stderr', new_callable=StringIO)
    def test_raise_too_long_fota_bios_version(self, mock_stderr):
        with self.assertRaises(SystemExit):
            self.arg_parser.parse_args(
                ['fota', '-p',
                 '/var/cache/manageability/repository-tool/BIOS.img',
                 '-r', '2024-12-31',
                 '-v', 'Intel',
                 '-b', OVER_FIFTY_CHARACTER_STRING,
                 '--target', '123ABC', '456DEF'])
            print("Error")
            print(mock_stderr.getvalue())
        self.assertRegexpMatches(mock_stderr.getvalue(
        ), r"BIOS Version is greater than allowed string size")

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    @patch('inbm_vision_lib.timer.Timer.start')
    def test_create_query_manifest(self, t_start, mock_agent, m_sub, m_pub, m_connect, mock_reconnect):
        p = self.arg_parser.parse_args(['query', '-o', 'all', '-tt', 'node'])
        Inbc(p, 'query', False)
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>cmd</type><cmd>query</cmd><query>' \
                   '<option>all</option><targetType>node</targetType></query></manifest>'
        self.assertEqual(p.func(p), expected)
        assert t_start.call_count == 3

    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('inbc.parser.get_dmi_system_info',
           return_value=PlatformInformation(datetime(2011, 10, 13), 'Intel', '5.12', 'intel', 'kmb'))
    @patch('inbc.parser.getpass.getpass', return_value='123abc')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbm_vision_lib.timer.Timer.start')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_create_non_hddl_fota_manifest_with_targets(self, mock_agent, mock_start, m_sub, m_pub, m_connect,
                                                        m_pass, m_dmi, mock_reconnect, mock_thread):
        p = self.arg_parser.parse_args(
            ['fota', '--nohddl', '-u', 'https://abc.com/package.bin', '-un', 'frank', '-to', '/b /p'])
        Inbc(p, 'fota', False)
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>fota</type>' \
                   '<repo>remote</repo></header><type><fota name="sample">' \
                   '<biosversion>5.12</biosversion><vendor>Intel</vendor><manufacturer>intel</manufacturer>' \
                   '<product>kmb</product><releasedate>2024-12-31</releasedate><tooloptions>/b /p</tooloptions>' \
                   '<username>frank</username><password>123abc</password>' \
                   '<fetch>https://abc.com/package.bin</fetch></fota></type></ota></manifest>'
        self.assertEqual(p.func(p), expected)
        assert mock_start.call_count == 3

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbm_vision_lib.timer.Timer.start')
    @patch('inbc.command.ota_command.copy_file_to_target_location',
           return_value='/var/cache/manageability/repository-tool/BIOS.img')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_create_hddl_fota_manifest_with_targets(self, mock_agent, mock_copy, mock_start, m_sub, m_pub,
                                                    m_connect, mock_reconnect):
        p = self.arg_parser.parse_args(
            ['fota', '-p', '/var/cache/manageability/repository-tool/BIOS.img', '-r', '2024-12-31', '--target',
             '123ABC', '456DEF'])
        Inbc(p, 'fota', False)
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>fota</type>' \
                   '<repo>local</repo></header><type><fota name="sample"><targetType>node</targetType>' \
                   '<targets><target>123ABC</target><target>456DEF</target></targets>' \
                   '<biosversion>5.12</biosversion><vendor>Intel</vendor><manufacturer>intel</manufacturer>' \
                   '<product>kmb-hddl2</product><releasedate>2024-12-31</releasedate><path>/var/cache/manageability' \
                   '/repository-tool/BIOS.img</path></fota></type></ota></manifest>'
        self.assertEqual(p.func(p), expected)
        mock_copy.assert_called_once()
        assert mock_start.call_count == 3

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_create_hddl_fota_manifest_without_targets(self, mock_agent, mock_reconnect):
        f = self.arg_parser.parse_args(
            ['fota', '-p', '/var/cache/manageability/repository-tool/BIOS.img', '-r', '2024-12-31'])
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>fota</type' \
                   '><repo>local</repo></header><type><fota name="sample"><targetType>node</targetType>' \
                   '<targets><target>None</target></targets>' \
                   '<biosversion>5.12</biosversion><vendor>Intel</vendor' \
                   '><manufacturer>intel</manufacturer><product>kmb-hddl2</product><releasedate>2024-12-31' \
                   '</releasedate><path>/var/cache/manageability/repository-tool/BIOS.img</path>' \
                   '</fota></type></ota></manifest>'
        self.assertEqual(f.func(f), expected)

    def test_create_hddl_fota_manifest_clean_input(self):
        f = self.arg_parser.parse_args(
            ['fota', '-p', '/var/\'cache/<manageability/\x00repository-tool/BIOS.img', '--target', '&123\x00ABC',
             '-b', '5.\x0014', '-m', 'Int\x00el', '-v', 'ven\x00dor', '-r', '2024-12-31'])

        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>fota</type' \
                   '><repo>local</repo></header><type><fota name="sample"><targetType>node</targetType>' \
                   '<targets><target>&amp;123ABC</target></targets>' \
                   '<biosversion>5.14</biosversion><vendor>vendor</vendor' \
                   '><manufacturer>Intel</manufacturer><product>kmb-hddl2</product><releasedate>2024-12-31' \
                   '</releasedate><path>/var/&#x27;cache/&lt;manageability/repository-tool/BIOS.img</path>' \
                   '</fota></type></ota></manifest>'
        self.assertEqual(f.func(f), expected)

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbm_vision_lib.timer.Timer.start')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    @patch('inbc.command.ota_command.copy_file_to_target_location',
           side_effect=['/var/cache/manageability/repository-tool/fip.bin',
                        '/var/cache/manageability/repository-tool/test.mender'])
    def test_create_pota_manifest_with_targets(self, copy_file, mock_agent, t_start, mock_subscribe, mock_publish,
                                               mock_connect, mock_reconnect):
        p = self.arg_parser.parse_args(
            ['pota', '-fp', './fip.bin', '-sp', './temp/test.mender', '--target', '123ABC', '456DEF'])
        Inbc(p, 'pota', False)

        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>pota</type>' \
                   '<repo>local</repo></header><type><pota><targetType>node</targetType><targets>' \
                   '<target>123ABC</target><target>456DEF</target></targets><fota name="sample">' \
                   '<biosversion>5.12</biosversion><manufacturer>intel</manufacturer><product>kmb-hddl2</product>' \
                   '<vendor>Intel</vendor><releasedate>2024-12-31</releasedate>' \
                   '<path>/var/cache/manageability/repository-tool/fip.bin</path></fota><sota>' \
                   '<cmd logtofile="y">update</cmd><release_date>2024-12-31</release_date>' \
                   '<path>/var/cache/manageability/repository-tool/test.mender</path></sota></pota>' \
                   '</type></ota></manifest>'

        self.assertEqual(p.func(p), expected)
        self.assertEqual(copy_file.call_count, 2)
        assert t_start.call_count == 3

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbm_vision_lib.timer.Timer.start')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    @patch('inbc.command.ota_command.copy_file_to_target_location',
           side_effect=['/var/cache/manageability/repository-tool/fip.bin',
                        '/var/cache/manageability/repository-tool/test.mender'])
    def test_create_pota_manifest_clean_input(self, copy_file, mock_agent, t_start, mock_subscribe, mock_publish,
                                              mock_connect, mock_reconnect):
        p = self.arg_parser.parse_args(
            ['pota', '-fp', './fip\x00.bin', '-sp', './\'temp/\x00test.mender', '--target', '\x00123ABC', '&456DEF\x00',
             '-v', 'ven\x00dor\'', '-m', 'Int\x00el', '-b', '5.\x0014'])
        Inbc(p, 'pota', False)

        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>pota</type>' \
                   '<repo>local</repo></header><type><pota><targetType>node</targetType><targets>' \
                   '<target>123ABC</target><target>&amp;456DEF</target></targets><fota name="sample">' \
                   '<biosversion>5.14</biosversion><manufacturer>Intel</manufacturer><product>kmb-hddl2</product>' \
                   '<vendor>vendor&#x27;</vendor><releasedate>2024-12-31</releasedate>' \
                   '<path>/var/cache/manageability/repository-tool/fip.bin</path></fota><sota>' \
                   '<cmd logtofile="y">update</cmd><release_date>2024-12-31</release_date>' \
                   '<path>/var/cache/manageability/repository-tool/test.mender</path></sota></pota>' \
                   '</type></ota></manifest>'

        self.assertEqual(p.func(p), expected)
        self.assertEqual(copy_file.call_count, 2)
        assert t_start.call_count == 3

    @patch('inbc.command.command.Command.terminate_operation')
    @patch('sys.stderr', new_callable=StringIO)
    def test_raise_too_long_pota_sota_path(self, mock_stderr, mock_terminate):
        with self.assertRaises(SystemExit):
            self.arg_parser.parse_args(['pota', '-fp', './fip.bin', '-sp', OVER_FIVE_HUNDRED_CHARACTER_STRING,
                                        '-r', '2024-12-31', '-sr', '2024-12-31'])
        self.assertRegexpMatches(mock_stderr.getvalue(
        ), r"SOTA path is greater than allowed string size")

    @patch('sys.stderr', new_callable=StringIO)
    def test_raise_too_long_pota_fota_path(self, mock_stderr):
        with self.assertRaises(SystemExit):
            self.arg_parser.parse_args(['pota', '-fp', OVER_FIVE_HUNDRED_CHARACTER_STRING, '-sp',
                                        './temp/test.mender', '-r', '2024-12-31', '-sr', '2024-12-31'])
        self.assertRegexpMatches(mock_stderr.getvalue(
        ), r"FOTA path is greater than allowed string size")

    @patch('sys.stderr', new_callable=StringIO)
    def test_raise_invalid_pota_sota_release_date_format(self, mock_stderr):
        with self.assertRaises(SystemExit):
            self.arg_parser.parse_args(
                ['pota', '-fp', './fip.bin', '-sp', './temp/test.mender', '-r', '2024-12-31', '-sr', '12-31-2024'])
        self.assertRegexpMatches(mock_stderr.getvalue(), r"Not a valid date - format YYYY-MM-DD:")

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('sys.stderr', new_callable=StringIO)
    def test_raise_invalid_pota_fota_release_date_format(self, mock_stderr, mock_reconnect):
        with self.assertRaises(SystemExit):
            self.arg_parser.parse_args(
                ['pota', '-fp', './fip.bin', '-sp', './temp/test.mender', '-r', '12-25-2021'])
        self.assertRegexpMatches(mock_stderr.getvalue(), r"Not a valid date - format YYYY-MM-DD:")

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbm_vision_lib.timer.Timer.start')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    @patch('inbc.command.ota_command.copy_file_to_target_location',
           side_effect=['/var/cache/manageability/repository-tool/fip.bin',
                        '/var/cache/manageability/repository-tool/test.mender'])
    def test_create_pota_manifest_without_targets(self, copy_file, mock_agent, t_start, mock_subscribe, mock_publish,
                                                  mock_connect, mock_reconnect):
        p = self.arg_parser.parse_args(
            ['pota', '-fp', './fip.bin', '-sp', './temp/test.mender'])
        Inbc(p, 'pota', False)

        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>pota</type>' \
                   '<repo>local</repo></header><type><pota><targetType>node</targetType><targets>' \
                   '<target>None</target></targets><fota name="sample">' \
                   '<biosversion>5.12</biosversion><manufacturer>intel</manufacturer><product>kmb-hddl2</product>' \
                   '<vendor>Intel</vendor><releasedate>2024-12-31</releasedate>' \
                   '<path>/var/cache/manageability/repository-tool/fip.bin</path></fota><sota>' \
                   '<cmd logtofile="y">update</cmd><release_date>2024-12-31</release_date>' \
                   '<path>/var/cache/manageability/repository-tool/test.mender</path></sota></pota>' \
                   '</type></ota></manifest>'

        self.assertEqual(p.func(p), expected)
        self.assertEqual(copy_file.call_count, 2)
        assert t_start.call_count == 3

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('inbc.parser.detect_os', return_value='ABC')
    def test_non_ubuntu_supported_no_hddl_pota_manifest(self, mock_os, mock_reconnect):
        pota = self.arg_parser.parse_args(
            ['pota', '--nohddl', '-fp', '/var/cache/fip.bin', '-sp', '/var/cache/temp/test.mender'])
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>pota</type>' \
                   '<repo>local</repo></header><type><pota><fota name="sample"><biosversion>5.12</biosversion>' \
                   '<manufacturer>intel</manufacturer><product>kmb-hddl2</product><vendor>Intel</vendor>' \
                   '<releasedate>2024-12-31</releasedate><path>/var/cache/fip.bin</path></fota><sota>' \
                   '<cmd logtofile="y">update</cmd><release_date>2024-12-31</release_date>' \
                   '<path>/var/cache/temp/test.mender</path></sota></pota></type></ota></manifest>'
        self.assertEqual(pota.func(pota), expected)

    @patch('inbc.parser.detect_os', return_value='Ubuntu')
    def test_ubuntu_supported_no_hddl_pota_manifest(self, mock_os):
        pota = self.arg_parser.parse_args(
            ['pota', '--nohddl', '-fp', '/var/cache/fip.bin', '-sp', '/var/cache/file.mender'])
        with self.assertRaisesRegex(InbcException,
                                    "POTA is not supported with local 'path' tags on non HDDL Ubuntu device."):
            pota.func(pota)

    @patch('sys.stderr', new_callable=StringIO)
    def test_raise_hddl_no_path(self, mock_stderr):
        s = self.arg_parser.parse_args(['sota', '-t', '123ABC', '456DEF'])
        with self.assertRaisesRegex(InbcException, 'argument --path/-p: required with HDDL command.'):
            s.func(s)

    def test_create_local_ubuntu_update_manifest(self):
        s = self.arg_parser.parse_args(['sota', '--nohddl'])
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>sota</type' \
                   '><repo>remote</repo></header><type><sota><cmd logtofile="y">update</cmd></sota></type></ota></manifest>'
        self.assertEqual(s.func(s), expected)

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('inbc.parser.getpass.getpass', return_value='123abc')
    def test_create_non_hddl_sota_manifest(self, mock_pass, mock_reconnect):
        s = self.arg_parser.parse_args(
            ['sota', '--nohddl', '-u', 'https://abc.com/test.tar', '-un', 'Frank'])
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>sota</type' \
                   '><repo>remote</repo></header><type><sota><cmd ' \
                   'logtofile="y">update</cmd>' \
                   '<fetch>https://abc.com/test.tar</fetch><username>Frank</username><password>123abc</password>' \
                   '<release_date>2024-12-31</release_date></sota></type></ota></manifest>'
        self.assertEqual(s.func(s), expected)

    def test_create_hddl_sota_manifest_with_targets(self):
        s = self.arg_parser.parse_args(
            ['sota', '-p', '/var/cache/manageability/repository-tool/BIOS.img', '-t', '123ABC', '456DEF'])

        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>sota</type' \
                   '><repo>local</repo></header><type><sota><cmd ' \
                   'logtofile="y">update</cmd><targetType>node</targetType><targets><target>123ABC</target>' \
                   '<target>456DEF</target></targets>' \
                   '<release_date>2024-12-31</release_date>' \
                   '<path>/var/cache/manageability/repository-tool/BIOS.img</path></sota></type></ota></manifest>'
        self.assertEqual(s.func(s), expected)

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    def test_create_sota_manifest_clean_inputs(self, mock_subscribe, mock_publish, mock_connect):
        s = self.arg_parser.parse_args(
            ['sota', '-p', '/var/ca\x00che/mana<geability/reposi&tory-tool/BIOS.img', '-t', '123\x00ABC', '\x00456DEF'])

        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>sota</type' \
                   '><repo>local</repo></header><type><sota><cmd ' \
                   'logtofile="y">update</cmd><targetType>node</targetType><targets><target>123ABC</target>' \
                   '<target>456DEF</target></targets>' \
                   '<release_date>2024-12-31</release_date>' \
                   '<path>/var/cache/mana&lt;geability/reposi&amp;tory-tool/BIOS.img</path></sota></type></ota></manifest>'
        self.assertEqual(s.func(s), expected)

    @patch('inbc.parser.get_dmi_system_info',
           return_value=PlatformInformation('2024-12-31', 'Intel', '5.12', 'intel', 'kmb'))
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_create_nohddl_fota_manifest_without_targets(self, mock_agent, mock_dmi):
        f = self.arg_parser.parse_args(
            ['fota', '--nohddl', '-u', 'https://abc.com/BIOS.img', '-r', '2024-12-31'])
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>fota</type' \
                   '><repo>remote</repo></header><type><fota name="sample">' \
                   '<biosversion>5.12</biosversion><vendor>Intel</vendor' \
                   '><manufacturer>intel</manufacturer><product>kmb</product><releasedate>2024-12-31' \
                   '</releasedate><fetch>https://abc.com/BIOS.img</fetch>' \
                   '</fota></type></ota></manifest>'
        self.assertEqual(f.func(f), expected)

    @patch('sys.stderr', new_callable=StringIO)
    def test_create_nohddl_fota_manifest_check_only_one_either_uri_or_fetch_tag(self, mock_sys_err):
        with self.assertRaises(SystemExit):
            self.arg_parser.parse_args(
                ['fota', '--nohddl', '-u', 'https://abc.com/BIOS.img', '-p',
                 '/var/cache/manageability/reposi&tory-tool/BIOS.img', '-r', '2024-12-31'])
        self.assertRegexpMatches(mock_sys_err.getvalue(
        ), r"argument --path/-p: not allowed with argument --uri/-u")

    @patch('sys.stderr', new_callable=StringIO)
    def test_raise_invalid_sota_release_date_format(self, mock_stderr):
        with self.assertRaises(SystemExit):
            self.arg_parser.parse_args(
                ['sota', '-p', '/var/cache/manageability/repository-tool/BIOS.img', '-r', '12-31-2024'])
        self.assertRegexpMatches(mock_stderr.getvalue(), r"Not a valid date - format YYYY-MM-DD:")

    @patch('sys.stderr', new_callable=StringIO)
    def test_raise_too_long_sota_path(self, mock_stderr):
        with self.assertRaises(SystemExit):
            self.arg_parser.parse_args(['sota', '-p', OVER_FIVE_HUNDRED_CHARACTER_STRING,
                                        '--target', '123ABC', '456DEF'])
        self.assertRegexpMatches(mock_stderr.getvalue(
        ), r"Path is greater than allowed string size")

    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_create_hddl_sota_manifest_without_targets(self, mock_agent):
        s = self.arg_parser.parse_args(
            ['sota', '-p', '/var/cache/manageability/repository-tool/BIOS.img'])

        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>sota</type' \
                   '><repo>local</repo></header><type><sota><cmd ' \
                   'logtofile="y">update</cmd><targetType>node</targetType><targets><target>None</target></targets>' \
                   '<release_date>2024-12-31</release_date>' \
                   '<path>/var/cache/manageability/repository-tool/BIOS.img' \
                   '</path></sota></type></ota></manifest>'
        self.assertEqual(s.func(s), expected)

    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_create_hddl_pota_uri_manifest_nohddl_ubuntu(self, mock_agent):
        s = self.arg_parser.parse_args(
            ['pota', '--nohddl', '-fu', '/var/cache/manageability/repository-tool/fip.bin'])

        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>pota</type' \
                   '><repo>remote</repo></header><type><pota><fota name="sample">' \
                   '<biosversion>5.12</biosversion><manufacturer>intel</manufacturer><product>kmb-hddl2</product>' \
                   '<vendor>Intel</vendor><releasedate>2024-12-31</releasedate>' \
                   '<fetch>/var/cache/manageability/repository-tool/fip.bin</fetch></fota><sota><cmd ' \
                   'logtofile="y">update</cmd>' \
                   '<release_date>2024-12-31</release_date>' \
                   '</sota></pota></type></ota></manifest>'
        self.assertEqual(s.func(s), expected)

    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    @patch('inbc.parser.detect_os', return_value='NonUbuntu')
    def test_create_hddl_pota_uri_manifest_nohddl_non_ubuntu(self, mock_os, mock_agent):
        s = self.arg_parser.parse_args(
            ['pota', '--nohddl', '-fu', '/var/cache/manageability/repository-tool/fip.bin', '-su',
             '/var/cache/manageability/repository-tool/file.mender'])

        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>pota</type' \
                   '><repo>remote</repo></header><type><pota><fota name="sample">' \
                   '<biosversion>5.12</biosversion><manufacturer>intel</manufacturer><product>kmb-hddl2</product>' \
                   '<vendor>Intel</vendor><releasedate>2024-12-31</releasedate>' \
                   '<fetch>/var/cache/manageability/repository-tool/fip.bin</fetch></fota><sota><cmd ' \
                   'logtofile="y">update</cmd>' \
                   '<release_date>2024-12-31</release_date>' \
                   '<fetch>/var/cache/manageability/repository-tool/file.mender</fetch>' \
                   '</sota></pota></type></ota></manifest>'
        self.assertEqual(s.func(s), expected)

    def test_raise_invalid_pota_path_manifest(self):
        pota = self.arg_parser.parse_args(
            ['pota', '-fp', '/var/cache/manageability/intel_manageability_node.conf',
             '-su', '/var/cache/manageability/repository-tool/file.mender'])
        with self.assertRaisesRegex(InbcException,
                                    "POTA requires 'fotauri, sotauri' args while using remote URIs and  'fotapath, sotapath' args while using path tags."):
            pota.func(pota)

    def test_raise_invalid_pota_uri_manifest(self):
        pota = self.arg_parser.parse_args(
            ['pota', '-fp', '/var/cache/manageability/intel_manageability_node.conf',
             '-su', '/var/cache/manageability/repository-tool/file.mender'])
        with self.assertRaisesRegex(InbcException,
                                    "POTA requires 'fotauri, sotauri' args while using remote URIs and  'fotapath, sotapath' args while using path tags."):
            pota.func(pota)

    def test_load_manifest(self):
        load = self.arg_parser.parse_args(
            ['load', '-p', '/var/cache/manageability/repository-tool/BIOS.img', '-tt', 'node'])

        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>config</type><config><cmd>load' \
                   '</cmd><targetType>node</targetType><configtype><load>' \
                   '<path>/var/cache/manageability/repository-tool/BIOS.img</path></load>' \
                   '</configtype></config></manifest>'
        self.assertEqual(load.func(load), expected)

    def test_raise_not_supported_no_hddl_load_manifest(self):
        load = self.arg_parser.parse_args(
            ['load', '--nohddl', '-p', '/var/cache/manageability/intel_manageability_node.conf',
             '--target', '123ABC', '456DEF'])
        with self.assertRaisesRegex(InbcException, 'Load command is only supported for HDDL.'):
            load.func(load)

    def test_load_manifest_clean_inputs(self):
        load = self.arg_parser.parse_args(
            ['load', '-p', '/var/cach&e/managea\x00bility/repository-tool/BIOS.img', '-tt', 'node'])

        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>config</type><config><cmd>load' \
                   '</cmd><targetType>node</targetType><configtype><load>' \
                   '<path>/var/cach&amp;e/manageability/repository-tool/BIOS.img</path></load>' \
                   '</configtype></config></manifest>'
        self.assertEqual(load.func(load), expected)

    def test_get_manifest(self):
        g = self.arg_parser.parse_args(
            ['get', '-p', '/var/cache/manageability/repository-tool/BIOS.img', '--targettype', 'vision'])

        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>config</type><config><cmd>' \
                   'get_element</cmd><targetType>vision</targetType><configtype>' \
                   '<get><path>/var/cache/manageability/repository-tool/BIOS.img</path>' \
                   '</get></configtype></config></manifest>'
        self.assertEqual(g.func(g), expected)

    @patch('inbc.command.command.Command.terminate_operation')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    def test_set_manifest(self, mock_reconnect, mock_terminate):
        s = self.arg_parser.parse_args(
            ['set', '-p', '/var/cache/manageability/repository-tool/BIOS.img', '-tt', 'node-client'])

        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>config</type><config><cmd>' \
                   'set_element</cmd><targetType>node-client</targetType><configtype>' \
                   '<set><path>/var/cache/manageability/repository-tool/BIOS.img</path>' \
                   '</set></configtype></config></manifest>'
        self.assertEqual(s.func(s), expected)

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('inbc.command.command.Command.terminate_operation')
    def test_restart_manifest(self, mock_terminate, mock_reconnect):
        s = self.arg_parser.parse_args(
            ['restart'])

        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>cmd</type><cmd>restart</cmd>' \
                   '<restart><targetType>node</targetType></restart></manifest>'
        self.assertEqual(s.func(s), expected)

    def test_raise_not_supported_no_hddl_restart_manifest(self):
        restart = self.arg_parser.parse_args(
            ['restart', '--nohddl'])
        with self.assertRaisesRegex(InbcException, 'Restart command is only supported for HDDL.'):
            restart.func(restart)

    @patch('inbc.command.command.Command.terminate_operation')
    def test_restart_with_targets_manifest(self, mock_terminate):
        s = self.arg_parser.parse_args(
            ['restart', '-t', '123ABC', '456DEF'])

        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>cmd</type><cmd>restart</cmd>' \
                   '<restart><targetType>node</targetType><targets><target>123ABC</target><target>456DEF' \
                   '</target></targets></restart></manifest>'
        self.assertEqual(s.func(s), expected)

    def test_query_manifest(self):
        s = self.arg_parser.parse_args(['query', '-o', 'all', '-tt', 'node'])

        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>cmd</type><cmd>query</cmd><query>' \
                   '<option>all</option><targetType>node</targetType></query></manifest>'

        self.assertEqual(s.func(s), expected)

    @patch('sys.stderr', new_callable=StringIO)
    def test_raise_invalid_query_option(self, mock_stderr):
        with self.assertRaises(SystemExit):
            self.arg_parser.parse_args(
                ['query', '-o', 'everything'])
        self.assertRegexpMatches(mock_stderr.getvalue(), r"invalid choice: 'everything'")

    @patch('threading.Thread._bootstrap_inner')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('inbm_vision_lib.timer.Timer.stop')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_terminate_operation_success(self, mock_agent, t_stop, mock_reconnect, mock_thread):
        with patch("builtins.open", mock_open(read_data="XLINK_SIMULATOR=False")) as mock_file:
            c = FotaCommand(Mock())
            c.terminate_operation(COMMAND_SUCCESS, InbcCode.SUCCESS.value)
        print(t_stop.call_count)
        assert t_stop.call_count == 2

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    @patch('inbm_vision_lib.timer.Timer.stop')
    def test_terminate_operation_failed(self, t_stop, mock_agent, mock_reconnect):
        with patch("builtins.open", mock_open(read_data="XLINK_SIMULATOR=False")) as mock_file:
            c = FotaCommand(Mock())
            c.terminate_operation(COMMAND_FAIL, InbcCode.FAIL.value)
        t_stop.assert_called_once()
