from unittest import TestCase
from mock import patch

from diagnostic.filesystem_utilities import get_free_space


class TestFilesystemUtilities(TestCase):

    @patch("inbm_common_lib.shell_runner.PseudoShellRunner().run", return_value=('line\nFree ('
                                                                               'estimated): '
                                                                               '2716983296	('
                                                                               'min: '
                                                                               '2716983296)',
                                                                               "", 0))
    @patch('diagnostic.filesystem_utilities._get_filesystem_type', return_value='btrfs')
    def test_correct_free_space_btrfs_a(self, mock_fstype, mock_shell):
        self.assertEqual(get_free_space('/var/log'), 2716983296)

    @patch('diagnostic.filesystem_utilities._get_non_btrfs_space', return_value=2700000)
    @patch("inbm_common_lib.shell_runner.PseudoShellRunner().run",
           return_value=("command not found: 'btrfs'", "", 1))
    @patch('diagnostic.filesystem_utilities._get_filesystem_type', return_value='btrfs')
    def test_correct_free_space_btrfs_b(self, mock_fstype, mock_shell, mock_psutil):
        self.assertEqual(get_free_space('/var/foo'), 2700000)
