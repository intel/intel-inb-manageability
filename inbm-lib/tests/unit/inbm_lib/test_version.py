from unittest import TestCase
from inbm_lib.version import get_inbm_version, get_inbm_commit, get_inbm_vision_host_version, get_inbm_vision_host_commit, get_inbm_vision_node_version, get_inbm_vision_node_commit
from inbm_lib.version import get_friendly_inbm_version_commit, get_friendly_inbm_vision_version_commit
from mock import patch

INBM_VERSION_TEXT = "Version: 1.2.3\r\nCommit: abcdefg\r\n"
INBM_VERSION_TEXT_HOST = "Version: 2.3.4\r\nCommit: aaabbbc\r\n"
INBM_VERSION_TEXT_NODE = "Version: 3.4.5\r\nCommit: fffeeed\r\n"


class TestVersion(TestCase):
    @patch('inbm_lib.version._read_inbm_version_file')
    def test_get_inbm_version(self, version) -> None:
        version.return_value = INBM_VERSION_TEXT
        self.assertEquals("1.2.3", get_inbm_version())

    @patch('inbm_lib.version._read_inbm_version_file')
    def test_get_inbm_commit(self, version) -> None:
        version.return_value = INBM_VERSION_TEXT
        self.assertEquals("abcdefg", get_inbm_commit())

    @patch('inbm_lib.version._read_inbm_vision_version_file_host')
    def test_get_inbm_vision_host_version(self, version) -> None:
        version.return_value = INBM_VERSION_TEXT_HOST
        self.assertEquals("2.3.4", get_inbm_vision_host_version())

    @patch('inbm_lib.version._read_inbm_vision_version_file_host')
    def test_get_inbm_vision_host_commit(self, version) -> None:
        version.return_value = INBM_VERSION_TEXT_HOST
        self.assertEquals("aaabbbc", get_inbm_vision_host_commit())

    @patch('inbm_lib.version._read_inbm_vision_version_file_node')
    def test_get_inbm_vision_node_version(self, version) -> None:
        version.return_value = INBM_VERSION_TEXT_NODE
        self.assertEquals("3.4.5", get_inbm_vision_node_version())

    @patch('inbm_lib.version._read_inbm_vision_version_file_node')
    def test_get_inbm_vision_node_commit(self, version) -> None:
        version.return_value = INBM_VERSION_TEXT_NODE
        self.assertEquals("fffeeed", get_inbm_vision_node_commit())

    @patch('inbm_lib.version._read_inbm_vision_version_file_host')
    @patch('inbm_lib.version._read_inbm_vision_version_file_node')
    @patch('inbm_lib.version._read_inbm_version_file')
    def test_get_friendly_inbm_version_commit(self, tc, bc_node, bc_host) -> None:
        tc.return_value = INBM_VERSION_TEXT
        bc_node.return_value = INBM_VERSION_TEXT_NODE
        bc_host.return_value = INBM_VERSION_TEXT_HOST

        self.assertEquals("Intel(R) Manageability version 1.2.3 (abcdefg)",
                          get_friendly_inbm_version_commit())

    @patch('inbm_lib.version._read_inbm_vision_version_file_host')
    @patch('inbm_lib.version._read_inbm_vision_version_file_node')
    @patch('inbm_lib.version._read_inbm_version_file')
    def test_get_friendly_inbm_vision_version_commit(self, tc, bc_node, bc_host) -> None:
        tc.return_value = INBM_VERSION_TEXT
        bc_node.return_value = INBM_VERSION_TEXT_NODE
        bc_host.return_value = INBM_VERSION_TEXT_HOST

        # Use host version when both node+host present
        self.assertEquals("Intel(R) Manageability Vision host version 2.3.4 (aaabbbc)",
                          get_friendly_inbm_vision_version_commit())

    @patch('inbm_lib.version._read_inbm_vision_version_file_host')
    @patch('inbm_lib.version._read_inbm_vision_version_file_node')
    @patch('inbm_lib.version._read_inbm_version_file')
    def test_get_friendly_inbm_vision_version_commit_node_only(self, tc, bc_node, bc_host) -> None:
        tc.return_value = INBM_VERSION_TEXT
        bc_node.return_value = INBM_VERSION_TEXT_NODE
        bc_host.return_value = None

        # Use node version.
        self.assertEquals("Intel(R) Manageability Vision node version 3.4.5 (fffeeed)",
                          get_friendly_inbm_vision_version_commit())
