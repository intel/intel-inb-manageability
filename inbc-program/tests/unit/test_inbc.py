from datetime import datetime
from unittest import TestCase
from inbc.inbc import Inbc
from inbc.parser import ArgsParser, fota, sota, load, get, set, append, remove
from inbc.constants import COMMAND_FAIL, COMMAND_SUCCESS
from inbc.inbc_exception import InbcCode, InbcException
from inbc.command.ota_command import FotaCommand

from inbm_common_lib.platform_info import PlatformInformation
from inbm_lib.request_message_constants import *
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

    def test_fota_manifest_pass(self):
        f = self.arg_parser.parse_args(
            ['fota', '-un', 'username', '-to', '/b /p', '-u', 'https://abc.com/test.tar'])
        self.assertEqual(f.uri, 'https://abc.com/test.tar')
        self.assertEqual(f.releasedate, '2026-12-31')
        self.assertEqual(f.tooloptions, '/b /p')
        self.assertEqual(f.username, 'username')

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    def test_sota_manifest_pass(self, mock_reconnect):
        f = self.arg_parser.parse_args(
            ['sota', '-un', 'username', '-u', 'https://abc.com/test.tar'])
        self.assertEqual(f.uri, 'https://abc.com/test.tar')
        self.assertEqual(f.username, 'username')

    def test_load_manifest_pass(self):
        f = self.arg_parser.parse_args(
            ['load', '-u', 'https://abc.com/intel_manageability.conf'])
        self.assertEqual(f.uri, 'https://abc.com/intel_manageability.conf')

    @patch('sys.stderr', new_callable=StringIO)
    def test_load_raises_no_uri(self, mock_stderr):
        with self.assertRaises(SystemExit):
            self.arg_parser.parse_args(['load'])
        self.assertRegexpMatches(mock_stderr.getvalue(), r"the following arguments are required: --uri/-u")

    @patch('inbc.command.ota_command.FotaCommand.trigger_manifest')
    @patch('sys.stderr', new_callable=StringIO)
    def test_raise_invalid_fota_date_format(self, mock_stderr, mock_trigger):
        with self.assertRaises(SystemExit):
            self.arg_parser.parse_args(
                ['fota', '-u', 'https://abc.com/test.tar', '-r', '12-31-2024',
                 '-m', 'Intel', '--target', '123ABC', '456DEF'])
        self.assertRegexpMatches(mock_stderr.getvalue(), r"Not a valid date - format YYYY-MM-DD:")

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('sys.stderr', new_callable=StringIO)
    def test_raise_too_long_fota_signature(self, mock_stderr, mock_reconnect):
        with self.assertRaises(SystemExit):
            self.arg_parser.parse_args(['fota', '-u', 'https://abc.com/test.tar',
                                        '-r', '2024-12-31',
                                        '-m', 'Intel',
                                        '-s', OVER_ONE_THOUSAND_CHARACTER_STRING])
        self.assertRegexpMatches(mock_stderr.getvalue(
        ), r"Signature is greater than allowed string size")

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbm_lib.timer.Timer.start')
    def test_create_query_manifest(self, t_start, m_sub, m_pub, m_connect, mock_reconnect):
        p = self.arg_parser.parse_args(['query', '-o', 'all'])
        Inbc(p, 'query', False)
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>cmd</type><cmd>query</cmd><query>' \
                   '<option>all</option></query></manifest>'
        self.assertEqual(p.func(p), expected)

    def test_create_fota_manifest(self, mock_start, m_sub, m_pub,
                                  m_connect, m_pass, m_dmi, mock_reconnect, mock_thread):
        p = self.arg_parser.parse_args(
            ['fota', '-u', 'https://abc.com/package.bin', '-un', 'frank', '-to', '/b /p'])
        Inbc(p, 'fota', False)
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>fota</type>' \
                   '<repo>remote</repo></header><type><fota name="sample">' \
                   '<biosversion>ADLSFWI1.R00</biosversion><vendor>Intel Corporation</vendor>' \
                   '<manufacturer>Intel Corporation</manufacturer>' \
                   '<product>Alder Lake Client Platform</product><releasedate>2024-12-31</releasedate>' \
                   '<tooloptions>/b /p</tooloptions>' \
                   '<username>frank</username><password>123abc</password>' \
                   '<fetch>https://abc.com/package.bin</fetch></fota></type></ota></manifest>'
        self.assertEqual(p.func(p), expected)
        assert mock_start.call_count == 1

    @patch('threading.Thread.start')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('inbc.parser.get_dmi_system_info',
           return_value=PlatformInformation(datetime(2011, 10, 13), 'Intel Corporation', 'ADLSFWI1.R00',
                                            'Intel Corporation', 'Alder Lake Client Platform'))
    @patch('inbc.parser.getpass.getpass', return_value='123abc')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('inbm_lib.timer.Timer.start')
    def test_create_fota_manifest_clean_input(self, mock_start, m_sub, m_pub,
                                  m_connect, m_pass, m_dmi, mock_reconnect, mock_thread):
        f = self.arg_parser.parse_args(
            ['fota', '-u', 'https://abc.com/\x00package.bin', '-r', '2024-12-31'])
        Inbc(f, 'fota', False)
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>fota</type' \
                   '><repo>remote</repo></header><type><fota name="sample">' \
                   '<biosversion>ADLSFWI1.R00</biosversion><vendor>Intel Corporation</vendor' \
                   '><manufacturer>Intel Corporation</manufacturer><product>Alder Lake Client Platform</product>' \
                   '<releasedate>2024-12-31' \
                   '</releasedate><fetch>https://abc.com/package.bin</fetch></fota></type></ota></manifest>'
        self.assertEqual(f.func(f), expected)

    @patch('sys.stderr', new_callable=StringIO)
    def test_raise_invalid_pota_sota_release_date_format(self, mock_stderr):
        with self.assertRaises(SystemExit):
            self.arg_parser.parse_args(
                ['pota', '-fp', './fip.bin', '-sp', './temp/test.mender', '-r', '2024-12-31', '-sr', '12-31-2024'])
        self.assertRegexpMatches(mock_stderr.getvalue(), r"Not a valid date - format YYYY-MM-DD:")

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('sys.stderr', new_callable=StringIO)
    def test_raise_invalid_pota_fota_release_date_format(self, mock_stderr, mock_reconnect):
        with self.assertRaises(SystemExit):
            self.arg_parser.parse_args(
                ['pota', '-fp', './fip.bin', '-sp', './temp/test.mender', '-r', '12-25-2021'])
        self.assertRegexpMatches(mock_stderr.getvalue(), r"Not a valid date - format YYYY-MM-DD:")

    def test_create_ubuntu_update_manifest(self):
        s = self.arg_parser.parse_args(['sota'])
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>sota</type' \
                   '><repo>remote</repo></header><type><sota><cmd logtofile="y">update</cmd></sota></type>' \
                   '</ota></manifest>'
        self.assertEqual(s.func(s), expected)

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('inbc.parser.getpass.getpass', return_value='123abc')
    def test_create_sota_manifest(self, mock_pass, mock_reconnect):
        s = self.arg_parser.parse_args(
            ['sota', '-u', 'https://abc.com/test.tar', '-un', 'Frank'])
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>sota</type' \
                   '><repo>remote</repo></header><type><sota><cmd ' \
                   'logtofile="y">update</cmd>' \
                   '<fetch>https://abc.com/test.tar</fetch><username>Frank</username><password>123abc</password>' \
                   '<release_date>2026-12-31</release_date></sota></type></ota></manifest>'
        self.assertEqual(s.func(s), expected)

    @patch('inbc.parser.get_dmi_system_info',
           return_value=PlatformInformation('2024-12-31', 'Intel', '5.12', 'Intel', 'kmb'))
    def test_create_fota_manifest(self, mock_dmi):
        f = self.arg_parser.parse_args(
            ['fota', '-u', 'https://abc.com/BIOS.img', '-r', '2024-12-31'])
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>fota</type' \
                   '><repo>remote</repo></header><type><fota name="sample">' \
                   '<biosversion>5.12</biosversion><vendor>Intel</vendor' \
                   '><manufacturer>Intel</manufacturer><product>kmb</product>' \
                   '<releasedate>2024-12-31' \
                   '</releasedate><fetch>https://abc.com/BIOS.img</fetch>' \
                   '</fota></type></ota></manifest>'
        self.assertEqual(f.func(f), expected)

    @patch('sys.stderr', new_callable=StringIO)
    def test_raise_invalid_sota_release_date_format(self, mock_stderr):
        with self.assertRaises(SystemExit):
            self.arg_parser.parse_args(
                ['sota', '-u', 'https://abc.com/test.mender', '-r', '12-31-2024'])
        self.assertRegexpMatches(mock_stderr.getvalue(), r"Not a valid date - format YYYY-MM-DD:")

    @patch('inbc.parser._gather_system_details',
           return_value=PlatformInformation(datetime(2011, 10, 13), 'Intel Corporation', 'ADLSFWI1.R00',
                                            'Intel Corporation', 'Alder Lake Client Platform'))
    @patch('inbc.parser.detect_os', return_value='NonUbuntu')
    def test_create_pota_uri_manifest_non_ubuntu(self, mock_os, mock_info):
        p = PlatformInformation()
        s = self.arg_parser.parse_args(
            ['pota', '-fu', '/var/cache/manageability/repository-tool/fip.bin', '-su',
             '/var/cache/manageability/repository-tool/file.mender'])

        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>pota</type' \
                   '><repo>remote</repo></header><type><pota><fota name="sample">' \
                   '<biosversion>ADLSFWI1.R00</biosversion><manufacturer>Intel Corporation</manufacturer>' \
                   '<product>Alder Lake Client Platform</product>' \
                   '<vendor>Intel Corporation</vendor><releasedate>2026-12-31</releasedate>' \
                   '<fetch>/var/cache/manageability/repository-tool/fip.bin</fetch></fota><sota><cmd ' \
                   'logtofile="y">update</cmd>' \
                   '<release_date>2026-12-31</release_date>' \
                   '<fetch>/var/cache/manageability/repository-tool/file.mender</fetch>' \
                   '</sota></pota></type></ota></manifest>'
        self.assertEqual(s.func(s), expected)

    def test_load_manifest(self):
        load = self.arg_parser.parse_args(
            ['load', '-u', 'https://abc.com/intel_manageability.conf'])

        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>config</type><config><cmd>load' \
                   '</cmd><configtype><load>' \
                   '<fetch>https://abc.com/intel_manageability.conf</fetch></load>' \
                   '</configtype></config></manifest>'
        self.assertEqual(load.func(load), expected)

    def test_append_manifest(self):
        append = self.arg_parser.parse_args(['append', '--path', 'trustedRepositories:https://abc.com'])

        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>config</type><config><cmd>append' \
                   '</cmd><configtype><append>' \
                   '<path>trustedRepositories:https://abc.com</path></append>' \
                   '</configtype></config></manifest>'
        self.assertEqual(append.func(append), expected)

    def test_remove_manifest(self):
        remove = self.arg_parser.parse_args(['remove', '--path', 'trustedRepositories:https://abc.com'])

        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>config</type><config><cmd>remove' \
                   '</cmd><configtype><remove>' \
                   '<path>trustedRepositories:https://abc.com</path></remove>' \
                   '</configtype></config></manifest>'
        self.assertEqual(remove.func(remove), expected)

    def test_raise_not_supported_restart_manifest(self):
        restart = self.arg_parser.parse_args(['restart'])
        with self.assertRaisesRegex(InbcException, 'Restart command is not supported.'):
            restart.func(restart)

    def test_query_manifest(self):
        s = self.arg_parser.parse_args(['query', '-o', 'all'])

        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>cmd</type><cmd>query</cmd><query>' \
                   '<option>all</option></query></manifest>'

        self.assertEqual(s.func(s), expected)

    @patch('sys.stderr', new_callable=StringIO)
    def test_raise_invalid_query_option(self, mock_stderr):
        with self.assertRaises(SystemExit):
            self.arg_parser.parse_args(
                ['query', '-o', 'everything'])
        self.assertRegexpMatches(mock_stderr.getvalue(), r"invalid choice: 'everything'")

    @patch('threading.Thread._bootstrap_inner')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('inbm_lib.timer.Timer.stop')
    def test_fota_terminate_operation_success(self, t_stop, mock_reconnect, mock_thread):
        c = FotaCommand(Mock())
        c.terminate_operation(COMMAND_SUCCESS, InbcCode.SUCCESS.value)
        print(t_stop.call_count)
        assert t_stop.call_count == 1

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('inbm_lib.timer.Timer.stop')
    def test_fota_terminate_operation_failed(self, t_stop, mock_reconnect):
        c = FotaCommand(Mock())
        c.terminate_operation(COMMAND_FAIL, InbcCode.FAIL.value)
        t_stop.assert_called_once()
