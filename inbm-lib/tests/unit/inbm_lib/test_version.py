from unittest import TestCase
from inbm_lib.version import get_inbm_version, get_inbm_commit
from inbm_lib.version import get_friendly_inbm_version_commit
from unittest.mock import patch, Mock

INBM_VERSION_TEXT = "Version: 1.2.3\r\nCommit: abcdefg\r\n"
INBM_VERSION_TEXT_HOST = "Version: 2.3.4\r\nCommit: aaabbbc\r\n"
INBM_VERSION_TEXT_NODE = "Version: 3.4.5\r\nCommit: fffeeed\r\n"


class TestVersion(TestCase):
    @patch('inbm_lib.version._read_inbm_version_file')
    def test_get_inbm_version(self, version: Mock) -> None:
        version.return_value = INBM_VERSION_TEXT
        self.assertEqual("1.2.3", get_inbm_version())

    @patch('inbm_lib.version._read_inbm_version_file')
    def test_get_inbm_commit(self, version: Mock) -> None:
        version.return_value = INBM_VERSION_TEXT
        self.assertEqual("abcdefg", get_inbm_commit())

    @patch('inbm_lib.version._read_inbm_version_file')
    def test_get_friendly_inbm_version_commit(self, tc: Mock) -> None:
        tc.return_value = INBM_VERSION_TEXT

        self.assertEqual("Intel(R) Manageability version 1.2.3 (abcdefg)",
                         get_friendly_inbm_version_commit())
