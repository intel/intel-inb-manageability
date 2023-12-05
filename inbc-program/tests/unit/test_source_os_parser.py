from inbc.parser.parser import ArgsParser
from unittest import TestCase


class TestSourceOSParser(TestCase):
    def setUp(self):
        self.arg_parser = ArgsParser()
        self.maxDiff = None

    def test_add_manifest_pass(self):
        f = self.arg_parser.parse_args(
            ['source', 'os', 'add',
             '-sources', '"deb http://example.com/ focal main restricted universe" "deb-src http://example.com/ focal-security main"'])
        self.assertEqual(f.s, '"deb http://example.com/ focal main restricted universe" "deb-src http://example.com/ focal-security main"')

    def test_remove_manifest_pass(self):
        f = self.arg_parser.parse_args(
            ['source', 'os', 'remove',
             '-sources',
             '"deb http://example.com/ focal main restricted universe" "deb-src http://example.com/ focal-security main"'])
        self.assertEqual(f.s,
                         '"deb http://example.com/ focal main restricted universe" "deb-src http://example.com/ focal-security main"')

    def test_update_manifest_pass(self):
        f = self.arg_parser.parse_args(
            ['source', 'os', 'update',
             '-sources',
             '"deb http://example.com/ focal main restricted universe" "deb-src http://example.com/ focal-security main"'])
        self.assertEqual(f.s,
                         '"deb http://example.com/ focal main restricted universe" "deb-src http://example.com/ focal-security main"')

    def test_list_manifest_pass(self):
        f = self.arg_parser.parse_args(['source', 'os', 'list'])
