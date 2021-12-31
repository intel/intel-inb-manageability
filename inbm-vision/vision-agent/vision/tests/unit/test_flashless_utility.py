
from unittest import TestCase

from vision.flashless_utility import copy_backup_flashless_files, rollback_flashless_files
from mock import patch


class TestFlashlessUtility(TestCase):

    @patch('shutil.copy')
    def test_copy_backup_flashless_files_pass(self, shutil_copy):
        copy_backup_flashless_files()
        assert shutil_copy.call_count == 3

    @patch('shutil.copy', side_effect=FileNotFoundError)
    def test_copy_backup_flashless_files_fail(self, shutil_copy):
        self.assertRaises(FileNotFoundError, copy_backup_flashless_files)

    @patch('shutil.copy')
    def test_rollback_flashless_files_pass(self, shutil_copy):
        rollback_flashless_files()
        assert shutil_copy.call_count == 3

    @patch('shutil.copy', side_effect=FileNotFoundError)
    def test_rollback_flashless_files_fail(self, shutil_copy):
        self.assertRaises(FileNotFoundError, rollback_flashless_files)
