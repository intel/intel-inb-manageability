from inbm_common_lib.utility import clean_input, get_canonical_representation_of_path, canonicalize_uri, validate_file_type, remove_file
from mock import patch, Mock
from inbm_common_lib.exceptions import UrlSecurityException
from unittest import TestCase


class TestUtility(TestCase):
    def test_clean_input(self):
        self.assertEquals(clean_input('\x00Hello<\x00There&You"\x00'),
                          'Hello&lt;There&amp;You&quot;')

    def test_get_canonical_representation_of_absolute_path(self):
        self.assertEquals('/var/cache/manageability', get_canonical_representation_of_path("/var/cache/manageability"))

    def test_canonicalize_url(self):
        self.assertEqual('https://www.example.com/a/c', canonicalize_uri('https://www.example.com/a/b/../c').value)
        self.assertEqual('https://a/', canonicalize_uri('a').value)
        self.assertEqual('', canonicalize_uri('').value)
        self.assertEqual('/var/lib/foo.txt', canonicalize_uri('/var/lib/foo.txt').value)

    @patch('tarfile.is_tarfile', return_value=None)
    @patch('inbm_common_lib.utility.get_file_type', return_value=("gzip compressed data"))
    def test_validate_file_type_pass(self, check_file, is_tar):
        path = ["/path/to/file"]
        validate_file_type(path)
        check_file.assert_called_once()
        is_tar.assert_called_once()

    @patch('tarfile.is_tarfile', return_value=None)
    @patch('inbm_common_lib.utility.get_file_type', return_value=("EICAR virus test files"))
    def test_validate_file_type_raise_error(self, check_file, is_tar):
        path = ["/path/to/file"]
        with self.assertRaises(TypeError):
            validate_file_type(path)
        check_file.assert_called_once()
        is_tar.assert_called_once()

    @patch('os.remove')
    @patch('os.path.isfile', return_value=True)
    @patch('os.path.exists', return_value=True)
    def test_remove_file(self, mock_exists,mock_is_file, mock_remove):
        remove_file('path')
        mock_remove.assert_called_once()
        with self.assertRaises(UrlSecurityException):
            canonicalize_uri('https://www.example.com/a/c%00.tar')

