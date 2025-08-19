import shutil
import tempfile
import tarfile
import os
from unittest.mock import patch, Mock, mock_open, MagicMock
from unittest import TestCase

from inbm_common_lib.exceptions import UrlSecurityException
from inbm_common_lib.utility import clean_input, get_canonical_representation_of_path, canonicalize_uri, \
    validate_file_type, remove_file, copy_file, move_file, create_file_with_contents, get_image_build_date, \
    safe_extract
from inbm_common_lib.constants import UNKNOWN


class TestUtility(TestCase):
    def test_clean_input(self) -> None:
        self.assertEqual(clean_input('\x00Hello<\x00There&You"\x00'),
                         'Hello&lt;There&amp;You&quot;')

    def test_get_canonical_representation_of_absolute_path(self) -> None:
        self.assertEqual('/var/cache/manageability',
                         get_canonical_representation_of_path("/var/cache/manageability"))

    def test_canonicalize_url(self) -> None:
        self.assertEqual('https://www.example.com/a/c',
                         canonicalize_uri('https://www.example.com/a/b/../c').value)
        self.assertEqual('https://a/', canonicalize_uri('a').value)
        self.assertEqual('', canonicalize_uri('').value)
        self.assertEqual('/var/lib/foo.txt', canonicalize_uri('/var/lib/foo.txt').value)

    @patch('tarfile.is_tarfile', return_value=None)
    @patch('inbm_common_lib.utility.get_file_type', return_value="gzip compressed data")
    def test_validate_file_type_pass(self, check_file: Mock, is_tar: Mock) -> None:
        path = ["/path/to/file"]
        validate_file_type(path)
        check_file.assert_called_once()
        is_tar.assert_called_once()

    @patch('tarfile.is_tarfile', return_value=None)
    @patch('inbm_common_lib.utility.get_file_type', return_value="EICAR virus test files")
    def test_validate_file_type_raise_error(self, check_file: Mock, is_tar: Mock) -> None:
        path = ["/path/to/file"]
        with self.assertRaises(TypeError):
            validate_file_type(path)
        check_file.assert_called_once()
        is_tar.assert_called_once()

    @patch('os.remove')
    @patch('os.path.isfile', return_value=True)
    @patch('os.path.exists', return_value=True)
    def test_remove_file(self, mock_exists: Mock, mock_is_file: Mock, mock_remove: Mock) -> None:
        remove_file('path')
        mock_remove.assert_called_once()
        with self.assertRaises(UrlSecurityException):
            canonicalize_uri('https://www.example.com/a/c%00.tar')

    @patch('os.path.isfile', return_value=True)
    @patch('shutil.copy')
    def test_copies_file(self, mock_copy: Mock, mock_is_file: Mock) -> None:
        try:
            copy_file('/home/usr', '/etc')
        except IOError as e:
            self.fail(f"Unexpected exception raised during test: {e}")

    @patch("os.path.islink", return_value=True)
    def test_raises_when_copy_src_is_symlink(self, mock_is_symlink: Mock) -> None:
        with self.assertRaises(IOError):
            copy_file('/home/usr', '/etc')

    @patch('shutil.copyfile', side_effect=shutil.SameFileError)
    def test_raises_during_copy_file(self, mock_copy: Mock) -> None:
        with self.assertRaises(IOError):
            copy_file('/home/usr', '/etc')

    @patch('shutil.move')
    @patch('os.path.exists', return_value=True)
    def test_move_file_successfully(self, os_path: Mock, move_file: Mock) -> None:
        try:
            move_file('/home/usr', '/etc')
        except IOError as e:
            self.fail(f"Unexpected exception raised during test: {e}")
        # os_path.assert_called_once()
        # move_file.assert_called()

    @patch('os.path.exists', return_value=False)
    def test_raise_when_move_file_dne(self, os_path: Mock) -> None:
        with self.assertRaises(IOError):
            move_file('/home/usr', '/etc')
        # os_path.assert_called_once()
        # move_file.assert_not_called()

    @patch('os.path.exists', return_value=True)
    def test_move_file_throw_exception(self, os_path: Mock) -> None:
        with self.assertRaises(IOError):
            move_file('/home/usr', '/etc')
        # os_path.assert_called_once()

    @patch("os.path.islink", return_value=True)
    def test_raises_when_move_src_is_symlink(self, mock_is_symlink: Mock) -> None:
        with self.assertRaises(IOError):
            move_file('/home/usr', '/etc')

    def test_create_file_with_contents_successfully(self) -> None:
        try:
            m = mock_open()
            lines = ['line1', 'line2']
            with patch('builtins.open', m) as m_open:
                create_file_with_contents('/etc/apt/sources.list.d/docker.list', lines)
            
            m_open.assert_called_once_with('/etc/apt/sources.list.d/docker.list', 'w')
            
            handle = m()
            handle.writelines.assert_called_once_with([line + "\n" for line in lines])

        except IOError as e:
            self.fail(f"Unexpected exception raised during test: {e}")

    @patch('builtins.open', new_callable=mock_open, read_data='IMAGE_BUILD_DATE="20241026100955"')
    @patch('os.path.exists', return_value=True)
    def test_get_image_build_date_successfully(self, mock_exist: Mock, mock_open: Mock) -> None:
        try:
            self.assertEqual(get_image_build_date(), "20241026100955")
        except IOError as e:
            self.fail(f"Unexpected exception raised during test: {e}")
        mock_open.assert_called_once_with('/etc/image-id', 'r')

    @patch('builtins.open', new_callable=mock_open, read_data='')
    @patch('os.path.exists', return_value=True)
    def test_get_image_build_date_with_no_version_found(self, mock_exist: Mock, mock_open: Mock) -> None:
        try:
            self.assertEqual(get_image_build_date(), UNKNOWN)
        except IOError as e:
            self.fail(f"Unexpected exception raised during test: {e}")
        mock_open.assert_called_once_with('/etc/image-id', 'r')


class TestSafeExtract(TestCase):
    """Test cases for the safe_extract method to verify path traversal protection"""
    
    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self.mock_tarball = MagicMock(spec=tarfile.TarFile)
        
    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def _create_mock_member(self, name: str, is_file: bool = True, is_symlink: bool = False, 
                           is_hardlink: bool = False, linkname: str = "") -> Mock:
        """Helper to create a mock TarInfo member"""
        member = Mock(spec=tarfile.TarInfo)
        member.name = name
        member.isfile.return_value = is_file
        member.isdir.return_value = not is_file
        member.issym.return_value = is_symlink
        member.islnk.return_value = is_hardlink
        member.linkname = linkname
        return member
    
    def test_safe_extract_normal_files_succeeds(self) -> None:
        """Test that normal files within the extraction directory are extracted successfully"""
        members = [
            self._create_mock_member("file1.txt"),
            self._create_mock_member("subdir/file2.txt"),
            self._create_mock_member("another/deep/file3.txt")
        ]
        
        self.mock_tarball.getmembers.return_value = members
        
        # Should not raise any exceptions
        safe_extract(self.mock_tarball, self.temp_dir)
        
        # Verify extract was called for each member
        self.assertEqual(self.mock_tarball.extract.call_count, 3)
    
    def test_safe_extract_with_specific_members(self) -> None:
        """Test that only specified members are extracted"""
        all_members = [
            self._create_mock_member("file1.txt"),
            self._create_mock_member("file2.txt"),
            self._create_mock_member("file3.txt")
        ]
        members_to_extract = [all_members[0], all_members[2]]  # Only first and third
        
        self.mock_tarball.getmembers.return_value = all_members
        
        safe_extract(self.mock_tarball, self.temp_dir, members_to_extract)
        
        # Should only extract 2 members
        self.assertEqual(self.mock_tarball.extract.call_count, 2)
    
    def test_safe_extract_absolute_path_attack_fails(self) -> None:
        """Test that absolute paths are rejected"""
        members = [self._create_mock_member("/etc/passwd")]
        self.mock_tarball.getmembers.return_value = members
        
        with self.assertRaises(IOError) as cm:
            safe_extract(self.mock_tarball, self.temp_dir)
        
        self.assertIn("Attempted absolute path in tar file", str(cm.exception))
        self.mock_tarball.extract.assert_not_called()
    
    def test_safe_extract_parent_directory_traversal_fails(self) -> None:
        """Test that parent directory traversal attempts are rejected"""
        traversal_paths = [
            "../etc/passwd",
            "subdir/../../../etc/passwd",
            "dir1/dir2/../../../../../../etc/passwd"
        ]
        
        for path in traversal_paths:
            with self.subTest(path=path):
                members = [self._create_mock_member(path)]
                self.mock_tarball.getmembers.return_value = members
                
                with self.assertRaises(IOError) as cm:
                    safe_extract(self.mock_tarball, self.temp_dir)
                
                self.assertIn("Attempted path traversal in tar file", str(cm.exception))
                self.mock_tarball.extract.assert_not_called()
    
    @patch('inbm_common_lib.utility.is_within_directory')
    def test_safe_extract_outside_directory_fails(self, mock_is_within: Mock) -> None:
        """Test that paths resolving outside the extraction directory are rejected"""
        mock_is_within.return_value = False
        
        members = [self._create_mock_member("normalfile.txt")]
        self.mock_tarball.getmembers.return_value = members
        
        with self.assertRaises(IOError) as cm:
            safe_extract(self.mock_tarball, self.temp_dir)
        
        self.assertIn("Attempted path traversal in tar file", str(cm.exception))
        self.mock_tarball.extract.assert_not_called()
    
    def test_safe_extract_symlink_absolute_path_fails(self) -> None:
        """Test that symlinks pointing to absolute paths are rejected"""
        members = [self._create_mock_member("link.txt", is_symlink=True, linkname="/etc/passwd")]
        self.mock_tarball.getmembers.return_value = members
        
        with self.assertRaises(IOError) as cm:
            safe_extract(self.mock_tarball, self.temp_dir)
        
        self.assertIn("Attempted symlink to absolute path in tar file", str(cm.exception))
        self.mock_tarball.extract.assert_not_called()
    
    def test_safe_extract_hardlink_absolute_path_fails(self) -> None:
        """Test that hardlinks pointing to absolute paths are rejected"""
        members = [self._create_mock_member("link.txt", is_hardlink=True, linkname="/etc/passwd")]
        self.mock_tarball.getmembers.return_value = members
        
        with self.assertRaises(IOError) as cm:
            safe_extract(self.mock_tarball, self.temp_dir)
        
        self.assertIn("Attempted symlink to absolute path in tar file", str(cm.exception))
        self.mock_tarball.extract.assert_not_called()
    
    @patch('inbm_common_lib.utility.is_within_directory')
    def test_safe_extract_symlink_outside_directory_fails(self, mock_is_within: Mock) -> None:
        """Test that symlinks pointing outside extraction directory are rejected"""
        # First call for the member itself, second for the link target
        mock_is_within.side_effect = [True, False]
        
        members = [self._create_mock_member("subdir/link.txt", is_symlink=True, linkname="../../../etc/passwd")]
        self.mock_tarball.getmembers.return_value = members
        
        with self.assertRaises(IOError) as cm:
            safe_extract(self.mock_tarball, self.temp_dir)
        
        self.assertIn("Attempted symlink outside extraction directory", str(cm.exception))
        self.mock_tarball.extract.assert_not_called()
    
    def test_safe_extract_valid_symlink_succeeds(self) -> None:
        """Test that valid symlinks within extraction directory are allowed"""
        members = [
            self._create_mock_member("file.txt"),
            self._create_mock_member("subdir/link.txt", is_symlink=True, linkname="../file.txt")
        ]
        self.mock_tarball.getmembers.return_value = members
        
        # Should not raise any exceptions
        safe_extract(self.mock_tarball, self.temp_dir)
        
        self.assertEqual(self.mock_tarball.extract.call_count, 2)
    
    def test_safe_extract_duplicate_paths_fails(self) -> None:
        """Test that duplicate paths in the same archive are rejected"""
        members = [
            self._create_mock_member("file.txt"),
            self._create_mock_member("file.txt")  # Duplicate
        ]
        self.mock_tarball.getmembers.return_value = members
        
        with self.assertRaises(IOError) as cm:
            safe_extract(self.mock_tarball, self.temp_dir)
        
        self.assertIn("Attempted to extract duplicate path", str(cm.exception))
        # Should not extract anything due to the duplicate
        self.mock_tarball.extract.assert_not_called()
    
    def test_safe_extract_normalized_duplicate_paths_fails(self) -> None:
        """Test that paths that normalize to the same location are rejected"""
        members = [
            self._create_mock_member("file.txt"),
            self._create_mock_member("./file.txt")  # Normalizes to same path
        ]
        self.mock_tarball.getmembers.return_value = members
        
        with self.assertRaises(IOError) as cm:
            safe_extract(self.mock_tarball, self.temp_dir)
        
        self.assertIn("Attempted to extract duplicate path", str(cm.exception))
        self.mock_tarball.extract.assert_not_called()
    
    def test_safe_extract_numeric_owner_parameter_passed(self) -> None:
        """Test that numeric_owner parameter is properly passed to extract"""
        members = [self._create_mock_member("file.txt")]
        self.mock_tarball.getmembers.return_value = members
        
        safe_extract(self.mock_tarball, self.temp_dir, numeric_owner=True)
        
        # Verify extract was called with numeric_owner=True
        self.mock_tarball.extract.assert_called_with(members[0], self.temp_dir, numeric_owner=True)
    
    def test_safe_extract_empty_member_list(self) -> None:
        """Test that empty member list is handled correctly"""
        self.mock_tarball.getmembers.return_value = []
        
        # Should not raise any exceptions
        safe_extract(self.mock_tarball, self.temp_dir)
        
        self.mock_tarball.extract.assert_not_called()
    
    def test_safe_extract_path_normalization(self) -> None:
        """Test that paths are properly normalized"""
        members = [
            self._create_mock_member("./file.txt"),
            self._create_mock_member("subdir/../other.txt"),
            self._create_mock_member("dir1/./dir2/file.txt")
        ]
        self.mock_tarball.getmembers.return_value = members
        
        safe_extract(self.mock_tarball, self.temp_dir)
        
        # Verify that normalized paths were used
        call_args_list = self.mock_tarball.extract.call_args_list
        self.assertEqual(len(call_args_list), 3)
        
        # Check that the member names were normalized
        extracted_members = [call[0][0] for call in call_args_list]
        self.assertEqual(extracted_members[0].name, "file.txt")
        self.assertEqual(extracted_members[1].name, "other.txt")
        self.assertEqual(extracted_members[2].name, "dir1/dir2/file.txt")