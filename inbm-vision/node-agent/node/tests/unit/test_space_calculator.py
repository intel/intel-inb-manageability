
import logging
import re
from unittest import TestCase

from mock import patch
from node.space_calculator import get_free_space, _calculate_btrfs_free_space

logger = logging.getLogger(__name__)


class TestSpaceCalculator(TestCase):

    @patch("inbm_vision_lib.shell_runner.PseudoShellRunner.run", return_value=('Free ('
                                                                               'estimated): '
                                                                               '2716983296	('
                                                                               'min: '
                                                                               '2716983296)',
                                                                               "", 0))
    @patch('node.space_calculator._get_fstype_root_part', return_value='btrfs')
    def test_correct_free_space_btrfs_a(self, mock_fstype, mock_shell):
        self.assertEqual(get_free_space(), 2716983296)

    @patch('node.space_calculator._get_non_btrfs_space', return_value=2700000)
    @patch("inbm_vision_lib.shell_runner.PseudoShellRunner.run",
           return_value=("command not found: 'btrfs'", "", 1))
    @patch('node.space_calculator._get_fstype_root_part', return_value='btrfs')
    def test_correct_free_space_btrfs_b(self, mock_fstype, mock_shell, mock_psutil):
        self.assertEqual(get_free_space(), 2700000)

    @patch("inbm_vision_lib.shell_runner.PseudoShellRunner.run", return_value=('Error'
                                                                               '',
                                                                               "", 1))
    @patch('node.space_calculator._get_non_btrfs_space', side_effect=KeyError)
    def test_calculate_btrfs_free_space_throw_exception(self, mock_non_btrfs, mock_shell):
        self.assertRaises(KeyError, _calculate_btrfs_free_space)
