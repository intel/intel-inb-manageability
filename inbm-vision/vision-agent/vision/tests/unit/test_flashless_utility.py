
from unittest import TestCase

from vision.flashless_utility import copy_backup_flashless_files, rollback_flashless_files
from vision.constant import VisionException
from mock import patch


class TestFlashlessUtility(TestCase):

    @patch('os.path.isfile', return_value=True)
    @patch('shutil.copy')
    def test_copy_backup_flashless_files_pass(self, mock_copy, mock_is_file):
        copy_backup_flashless_files()
        assert mock_copy.call_count == 3

    @patch('shutil.copy', side_effect=OSError)
    def test_copy_backup_flashless_files_fail(self, mock_copy):
        self.assertRaises(VisionException, copy_backup_flashless_files)

    @patch('os.path.isfile', return_value=True)
    @patch('shutil.copy')
    def test_rollback_flashless_files_pass(self, mock_copy, mock_is_file):
        rollback_flashless_files()
        assert mock_copy.call_count == 3

    @patch('shutil.copy', side_effect=FileNotFoundError)
    def test_rollback_flashless_files_fail(self, mock_copy):
        self.assertRaises(VisionException, rollback_flashless_files)
