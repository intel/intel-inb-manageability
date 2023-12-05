from inbc.parser.parser import ArgsParser
from unittest import TestCase


class TestSourceOsParser(TestCase):
    def setUp(self):
        self.arg_parser = ArgsParser()
        self.maxDiff = None

    def test_parse_add_arguments_successfully(self):
        f = self.arg_parser.parse_args(
            ['source', 'os', 'add',
             '-sources', '"deb http://example.com/ focal main restricted universe" '
                         '"deb-src http://example.com/ focal-security main"'])
        self.assertEqual(f.s, '"deb http://example.com/ focal main restricted universe" '
                              '"deb-src http://example.com/ focal-security main"')

    def test_parse_remove_arguments_successfully(self):
        f = self.arg_parser.parse_args(
            ['source', 'os', 'remove',
             '-sources',
             '"deb http://example.com/ focal main restricted universe" '
             '"deb-src http://example.com/ focal-security main"'])
        self.assertEqual(f.s,
                         '"deb http://example.com/ focal main restricted universe" '
                         '"deb-src http://example.com/ focal-security main"')

    def test_parse_update_arguments_successfully(self):
        f = self.arg_parser.parse_args(
            ['source', 'os', 'update',
             '-sources',
             '"deb http://example.com/ focal main restricted universe" '
             '"deb-src http://example.com/ focal-security main"'])
        self.assertEqual(f.s,
                         '"deb http://example.com/ focal main restricted universe" '
                         '"deb-src http://example.com/ focal-security main"')

    def test_parse_list_arguments_successfully(self):
        f = self.arg_parser.parse_args(['source', 'os', 'list'])
