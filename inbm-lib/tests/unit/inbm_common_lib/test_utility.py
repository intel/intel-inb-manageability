import shutil
from mock import patch
from unittest import TestCase

from inbm_common_lib.exceptions import UrlSecurityException
from inbm_common_lib.utility import clean_input, get_canonical_representation_of_path, canonicalize_uri, validate_file_type, remove_file, copy_file, move_file


class TestUtility(TestCase):
    def test_clean_input(self) -> None:
        self.assertEquals(clean_input('\x00Hello<\x00There&You"\x00'),
                          'Hello&lt;There&amp;You&quot;')

    def test_get_canonical_representation_of_absolute_path(self) -> None:
        self.assertEquals('/var/cache/manageability',
                          get_canonical_representation_of_path("/var/cache/manageability"))

    def test_canonicalize_url(self) -> None:
        self.assertEqual('https://www.example.com/a/c',
                         canonicalize_uri('https://www.example.com/a/b/../c').value)
        self.assertEqual('https://a/', canonicalize_uri('a').value)
        self.assertEqual('', canonicalize_uri('').value)
        self.assertEqual('/var/lib/foo.txt', canonicalize_uri('/var/lib/foo.txt').value)

    @patch('tarfile.is_tarfile', return_value=None)
    @patch('inbm_common_lib.utility.get_file_type', return_value="gzip compressed data")
    def test_validate_file_type_pass(self, check_file, is_tar) -> None:
        path = ["/path/to/file"]
        validate_file_type(path)
        check_file.assert_called_once()
        is_tar.assert_called_once()

    @patch('tarfile.is_tarfile', return_value=None)
    @patch('inbm_common_lib.utility.get_file_type', return_value="EICAR virus test files")
    def test_validate_file_type_raise_error(self, check_file, is_tar) -> None:
        path = ["/path/to/file"]
        with self.assertRaises(TypeError):
            validate_file_type(path)
        check_file.assert_called_once()
        is_tar.assert_called_once()

    @patch('os.remove')
    @patch('os.path.isfile', return_value=True)
    @patch('os.path.exists', return_value=True)
    def test_remove_file(self, mock_exists, mock_is_file, mock_remove) -> None:
        remove_file('path')
        mock_remove.assert_called_once()
        with self.assertRaises(UrlSecurityException):
            canonicalize_uri('https://www.example.com/a/c%00.tar')

    @patch('os.path.isfile', return_value=True)
    @patch('shutil.copy')
    def test_copies_file(self, mock_copy, mock_is_file) -> None:
        try:
            copy_file('/home/usr', '/etc')
        except IOError as e:
            self.fail(f"Unexpected exception raised during test: {e}")

    @patch("os.path.islink", return_value=True)
    def test_raises_when_copy_src_is_symlink(self, mock_is_symlink) -> None:
        with self.assertRaises(IOError):
            copy_file('/home/usr', '/etc')

    @patch('shutil.copyfile', side_effect=shutil.SameFileError)
    def test_raises_during_copy_file(self, mock_copy) -> None:
        with self.assertRaises(IOError):
            copy_file('/home/usr', '/etc')

    @patch('shutil.move')
    @patch('os.path.exists', return_value=True)
    def test_move_file_successfully(self, os_path, move_file) -> None:
        try:
            move_file('/home/usr', '/etc')
        except IOError as e:
            self.fail(f"Unexpected exception raised during test: {e}")
        # os_path.assert_called_once()
        # move_file.assert_called()

    @patch('os.path.exists', return_value=False)
    def test_raise_when_move_file_dne(self, os_path) -> None:
        with self.assertRaises(IOError):
            move_file('/home/usr', '/etc')
        # os_path.assert_called_once()
        # move_file.assert_not_called()

    @patch('os.path.exists', return_value=True)
    def test_move_file_throw_exception(self, os_path) -> None:
        with self.assertRaises(IOError):
            move_file('/home/usr', '/etc')
        # os_path.assert_called_once()

    @patch("os.path.islink", return_value=True)
    def test_raises_when_move_src_is_symlink(self, mock_is_symlink) -> None:
        with self.assertRaises(IOError):
            move_file('/home/usr', '/etc')
