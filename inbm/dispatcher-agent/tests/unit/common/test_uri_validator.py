from unittest import TestCase

import sys

from dispatcher.common.uri_utilities import is_valid_uri, uri_to_filename, get_uri_prefix


class TestUriValidator(TestCase):

    def test_uri_validator(self) -> None:
        self.assertFalse(is_valid_uri("") is None)

        self.assertFalse(is_valid_uri(None))
        self.assertFalse(is_valid_uri(""))

        self.assertFalse(is_valid_uri(None) is None)
        self.assertTrue(is_valid_uri("http://www.example.com/"))
        self.assertFalse(is_valid_uri("http;;/www.example.com/"))
        self.assertFalse(is_valid_uri("http%%;//www.example.com/"))
        self.assertTrue(is_valid_uri("file:///etc/passwd"))
        self.assertFalse(is_valid_uri("gopher://example.com/"))
        self.assertTrue(is_valid_uri("https://www.example.com/"))
        self.assertTrue(is_valid_uri("ftp://www.example.com/"))

    def test_uri_to_filename(self) -> None:
        self.assertEqual("a.txt", uri_to_filename("http://www.google.com/b/c/a.txt"))
        self.assertEqual("q.txt", uri_to_filename("http://www.google.com/q.txt?33"))
        self.assertEqual("foo", uri_to_filename("foo"))
        self.assertEqual("", uri_to_filename(""))

    def test_get_uri_prefix(self) -> None:
        self.assertEqual("http://www.google.com/",
                         get_uri_prefix("http://www.google.com/b/c/a.txt"))
        self.assertEqual("http://www.google.com/",
                         get_uri_prefix("http://www.google.com/q.txt?33"))
        self.assertEqual("", get_uri_prefix("foo"))
        self.assertEqual("", get_uri_prefix(""))
