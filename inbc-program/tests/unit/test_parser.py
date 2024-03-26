from unittest import TestCase
from inbc.parser.parser import ArgsParser
from io import StringIO
from inbc.inbc import Inbc
from inbc.inbc_exception import InbcCode, InbcException

from unittest.mock import patch

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


class TestInbc(TestCase):
    def setUp(self) -> None:
        self.arg_parser = ArgsParser()
        self.maxDiff = None

    def test_load_manifest_pass(self) -> None:
        f = self.arg_parser.parse_args(
            ['load', '-u', 'https://abc.com/intel_manageability.conf'])
        self.assertEqual(f.uri, 'https://abc.com/intel_manageability.conf')
    
    def test_parser_source_returns_non_empty_namespace(self) -> None:
        exit = False
        try:
            f = self.arg_parser.parse_args(['source'])
        except SystemExit as e:
            exit = True

        self.assertTrue(exit)

    def test_parser_sota_returns_non_empty_namespace(self) -> None:
        f = self.arg_parser.parse_args(['sota'])
        self.assertNotEqual(vars(f), {})

    @patch('inbc.inbc.Broker')
    @patch('inbm_lib.timer.Timer.start')
    def test_create_query_manifest(self, t_start, m_broker) -> None:
        p = self.arg_parser.parse_args(['query', '-o', 'all'])
        Inbc(p, 'query', False)
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>cmd</type><cmd>query</cmd><query>' \
                   '<option>all</option></query></manifest>'
        self.assertEqual(p.func(p), expected)

    def test_load_manifest(self) -> None:
        load = self.arg_parser.parse_args(
            ['load', '-u', 'https://abc.com/intel_manageability.conf'])

        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>config</type><config><cmd>load' \
                   '</cmd><configtype><load>' \
                   '<fetch>https://abc.com/intel_manageability.conf</fetch></load>' \
                   '</configtype></config></manifest>'
        self.assertEqual(load.func(load), expected)

    def test_append_manifest(self) -> None:
        append = self.arg_parser.parse_args(
            ['append', '--path', 'trustedRepositories:https://abc.com'])

        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>config</type><config><cmd>append' \
                   '</cmd><configtype><append>' \
                   '<path>trustedRepositories:https://abc.com</path></append>' \
                   '</configtype></config></manifest>'
        self.assertEqual(append.func(append), expected)

    def test_remove_manifest(self) -> None:
        remove = self.arg_parser.parse_args(
            ['remove', '--path', 'trustedRepositories:https://abc.com'])

        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>config</type><config><cmd>remove' \
                   '</cmd><configtype><remove>' \
                   '<path>trustedRepositories:https://abc.com</path></remove>' \
                   '</configtype></config></manifest>'
        self.assertEqual(remove.func(remove), expected)

    def test_create_restart_manifest(self):
        s = self.arg_parser.parse_args(['restart'])
        
        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>cmd</type><cmd>restart</cmd></manifest>'
        assert expected == s.func(s)
        
    def test_query_manifest(self) -> None:
        s = self.arg_parser.parse_args(['query', '-o', 'all'])

        expected = '<?xml version="1.0" encoding="utf-8"?><manifest><type>cmd</type><cmd>query</cmd><query>' \
                   '<option>all</option></query></manifest>'

        self.assertEqual(s.func(s), expected)

    @patch('sys.stderr', new_callable=StringIO)
    def test_raise_invalid_query_option(self, mock_stderr) -> None:
        with self.assertRaises(SystemExit):
            self.arg_parser.parse_args(
                ['query', '-o', 'everything'])
        self.assertRegexpMatches(mock_stderr.getvalue(), r"invalid choice: 'everything'")
