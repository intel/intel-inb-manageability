from unittest import TestCase

from inbm_common_lib.version import read_version, read_commit


class TestVersion(TestCase):
    def test_read_version(self) -> None:
        input = "12345\nVersion: 1.2.3\r\nCommit: abcdef\n"
        expected_version = "1.2.3"
        actual_version = read_version(input)

        self.assertEqual(expected_version, actual_version)

    def test_read_version_missing(self) -> None:
        input = "12345\r\nCommit: abcdef\n"
        expected_version = None
        actual_version = read_version(input)

        self.assertEqual(expected_version, actual_version)

    def test_read_commit(self) -> None:
        input = "12345\nVersion: 1.2.3\r\nCommit: abcdef\n"
        expected_commit = "abcdef"
        actual_commit = read_commit(input)

        self.assertEqual(expected_commit, actual_commit)

    def test_read_commit_missing(self) -> None:
        input = "12345\nVersion: 1.2.3\r\n"
        expected_commit = None
        actual_commit = read_commit(input)

        self.assertEqual(expected_commit, actual_commit)
