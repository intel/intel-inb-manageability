import sys
sys.path.insert(0, '../../../')
sys.path.insert(0, '../')
sys.path.insert(0, '../../')
sys.path.insert(0, './')
sys.path.insert(0, '../../../../')
sys.path.insert(0, '/home/runner/GITHUB_ACTION_RUNNERS/_work/intel-inb-manageability/intel-inb-manageability/inbm/dispatcher-agent/dispatcher/source/')
sys.path.insert(0, '/home/runner/GITHUB_ACTION_RUNNERS/_work/intel-inb-manageability/intel-inb-manageability/inbm/dispatcher-agent/')
sys.path.insert(0, '/home/runner/GITHUB_ACTION_RUNNERS/_work/intel-inb-manageability/intel-inb-manageability/inbm-lib/')
import pytest
from unittest.mock import patch, MagicMock
from dispatcher.source.ubuntu_source_manager import UbuntuApplicationSourceManager, ApplicationAddSourceParameters
from unittest.mock import patch, mock_open
from dispatcher.source.ubuntu_source_manager import UbuntuApplicationSourceManager, ApplicationSourceList
from dispatcher.source.ubuntu_source_manager import UbuntuApplicationSourceManager, ApplicationRemoveSourceParameters, SourceError, LINUX_GPG_KEY_PATH, UBUNTU_APT_SOURCES_LIST_D
from dispatcher.source.ubuntu_source_manager import UbuntuApplicationSourceManager, SourceError, ApplicationUpdateSourceParameters
from dispatcher.source.ubuntu_source_manager import UbuntuOsSourceManager, SourceParameters, SourceError
from dispatcher.source.ubuntu_source_manager import UbuntuOsSourceManager, SourceError
from unittest.mock import patch, mock_open, call

#DO NOT DELETE THIS LINE - TestUbuntuApplicationSourceManagerAdd
'''
ADD HUMAN FEEDBACK BELOW:

'''
class TestUbuntuApplicationSourceManagerAdd:
    @pytest.fixture
    def mock_dispatcher_broker(self):
        return MagicMock()

    @pytest.fixture
    def mock_application_source_manager(self, mock_dispatcher_broker):
        return UbuntuApplicationSourceManager(mock_dispatcher_broker)

    @pytest.mark.parametrize('gpg_key_name, gpg_key_uri, source_list_file_name, sources', [
        ('key1', 'http://example.com/key1', 'file1', ['deb http://example.com/ubuntu/ bionic main restricted']),
        (None, None, 'file2', ['deb http://example.com/ubuntu/ bionic main restricted']),
    ])
    @patch('dispatcher.source.ubuntu_source_manager.verify_source')
    @patch('dispatcher.source.ubuntu_source_manager.add_gpg_key')
    @patch('dispatcher.source.ubuntu_source_manager.create_file_with_contents')
    def test_add(self, mock_create_file_with_contents, mock_add_gpg_key, mock_verify_source, mock_application_source_manager, gpg_key_name, gpg_key_uri, source_list_file_name, sources):
        # Arrange
        parameters = ApplicationAddSourceParameters(gpg_key_name=gpg_key_name, gpg_key_uri=gpg_key_uri, source_list_file_name=source_list_file_name, sources=sources)

        # Act
        mock_application_source_manager.add(parameters)

        # Assert
        if gpg_key_name and gpg_key_uri:
            mock_verify_source.assert_called_once_with(source=gpg_key_uri.rsplit('/', 1)[0], dispatcher_broker=mock_application_source_manager._dispatcher_broker)
            mock_add_gpg_key.assert_called_once_with(gpg_key_uri, gpg_key_name)
        mock_create_file_with_contents.assert_called_once_with(f'/etc/apt/sources.list.d/{source_list_file_name}', sources)

#DO NOT DELETE THIS LINE - TestUbuntuApplicationSourceManagerList
'''
ADD HUMAN FEEDBACK BELOW:

'''
class TestUbuntuApplicationSourceManagerList:
    @pytest.mark.parametrize('file_content, expected_output', [
        # Test with one source
        (["deb http://archive.ubuntu.com/ubuntu/ bionic main restricted"], 
         [ApplicationSourceList(name="sources.list", sources=["deb http://archive.ubuntu.com/ubuntu/ bionic main restricted"])]),
        # Test with multiple sources
        (["deb http://archive.ubuntu.com/ubuntu/ bionic main restricted", "deb-src http://archive.ubuntu.com/ubuntu/ bionic main restricted"], 
         [ApplicationSourceList(name="sources.list", sources=["deb http://archive.ubuntu.com/ubuntu/ bionic main restricted", "deb-src http://archive.ubuntu.com/ubuntu/ bionic main restricted"])]),
        # Test with no sources
        ([""], [ApplicationSourceList(name="sources.list", sources=[])]),
        # Test with commented lines
        (["# deb http://archive.ubuntu.com/ubuntu/ bionic main restricted"], [ApplicationSourceList(name="sources.list", sources=[])]),
        # Test with blank lines
        ([""], [ApplicationSourceList(name="sources.list", sources=[])]),
    ])
    @patch("glob.glob")
    @patch("builtins.open", new_callable=mock_open)
    def test_list(self, mock_open, mock_glob, file_content, expected_output):
        # Mock the glob.glob call to return a list with one file
        mock_glob.return_value = ["sources.list"]
        # Mock the open call to return an iterator over the file_content list
        handle = mock_open.return_value.__enter__.return_value
        handle.__iter__.return_value = iter(file_content)
        handle.readlines.return_value = file_content
        # Create an instance of UbuntuApplicationSourceManager
        manager = UbuntuApplicationSourceManager(None)
        # Call the list method and assert that the output matches the expected output
        assert manager.list() == expected_output

#DO NOT DELETE THIS LINE - TestUbuntuApplicationSourceManagerRemove
'''
ADD HUMAN FEEDBACK BELOW:

'''
class TestUbuntuApplicationSourceManagerRemove:
    @pytest.fixture
    def manager(self):
        return UbuntuApplicationSourceManager(MagicMock())

    @pytest.fixture
    def parameters(self):
        return ApplicationRemoveSourceParameters(source_list_file_name='test.list', gpg_key_name='test.key')

    @pytest.mark.parametrize('file_exists, key_exists, expected_exception', [
        (True, True, None),
        (True, False, None),
        (False, True, SourceError),
        (False, False, SourceError),
    ])
    @patch('dispatcher.source.ubuntu_source_manager.remove_file')
    @patch('dispatcher.source.ubuntu_source_manager.get_canonical_representation_of_path')
    @patch('dispatcher.source.ubuntu_source_manager.os.path.join')
    def test_remove(self, mock_join, mock_get_canonical, mock_remove_file, file_exists, key_exists, expected_exception, manager, parameters):
        # Mocking the dependent functions
        mock_join.return_value = 'test_path'
        mock_get_canonical.return_value = 'canonical_path'
        mock_remove_file.side_effect = [key_exists, file_exists]

        # If an exception is expected, check if it's raised
        if expected_exception:
            with pytest.raises(expected_exception):
                manager.remove(parameters)
        else:
            manager.remove(parameters)

        # Check if the dependent functions were called with the correct arguments
        mock_join.assert_any_call(LINUX_GPG_KEY_PATH, parameters.gpg_key_name)
        mock_join.assert_any_call(UBUNTU_APT_SOURCES_LIST_D, parameters.source_list_file_name)
        mock_get_canonical.assert_called_once_with('test_path')
        assert mock_remove_file.call_count == 2

#DO NOT DELETE THIS LINE - TestUbuntuApplicationSourceManagerUpdate
'''
ADD HUMAN FEEDBACK BELOW:

'''
class TestUbuntuApplicationSourceManagerUpdate:
    @pytest.fixture
    def manager(self):
        broker = MagicMock()
        return UbuntuApplicationSourceManager(broker)

    @pytest.fixture
    def parameters(self):
        return ApplicationUpdateSourceParameters(source_list_file_name='test', sources=['deb http://archive.ubuntu.com/ubuntu/ bionic main restricted'])

    @pytest.mark.parametrize('exception, expected_exception', [
        (IOError('IOError'), SourceError),
        (OSError('OSError'), SourceError)
    ])
    def test_update_raises_exception(self, manager, parameters, exception, expected_exception):
        """Test that update raises the correct exception when an error occurs."""
        with patch('inbm_common_lib.utility.create_file_with_contents', side_effect=exception):
            with pytest.raises(expected_exception):
                manager.update(parameters)

    def test_update_successful(self, manager, parameters, tmp_path):
        """Test that update successfully updates the source file."""
        with patch('os.path.join', return_value=str(tmp_path / 'test')), \
             patch('inbm_common_lib.utility.create_file_with_contents', return_value=None) as mock_create_file:
            manager.update(parameters)
            mock_create_file.assert_called_once_with(
                str(tmp_path / 'test'), ['deb http://archive.ubuntu.com/ubuntu/ bionic main restricted']
            )

#DO NOT DELETE THIS LINE - TestUbuntuOsSourceManagerAdd
'''
ADD HUMAN FEEDBACK BELOW:

'''
class TestUbuntuOsSourceManagerAdd:
    @pytest.fixture
    def manager(self):
        return UbuntuOsSourceManager()

    @pytest.mark.parametrize('sources', [
        (['deb http://archive.ubuntu.com/ubuntu/ bionic main restricted']),  # single source
        (['deb http://archive.ubuntu.com/ubuntu/ bionic main restricted', 'deb http://archive.ubuntu.com/ubuntu/ bionic universe']),  # multiple sources
        (['deb http://archive.ubuntu.com/ubuntu/ bionic main restricted', 'deb http://archive.ubuntu.com/ubuntu/ bionic main restricted']),  # duplicate sources
    ])
    def test_add_valid_sources(self, manager, sources):
        # Mock the open function
        with patch('builtins.open', mock_open()) as m:
            params = SourceParameters(sources=sources)
            manager.add(params)
            m.assert_called_once_with('/etc/apt/sources.list', 'a')
            handle = m()
            for source in sources:
                handle.write.assert_any_call(f"{source}\n")

    @pytest.mark.parametrize('sources', [
        (['http://archive.ubuntu.com/ubuntu/ bionic main restricted']),  # missing deb
        (['deb archive.ubuntu.com/ubuntu/ bionic main restricted']),  # missing http://
        (['deb http://archive.ubuntu.com/ubuntu/ bionic']),  # missing main restricted
    ])
    def test_add_invalid_sources(self, manager, sources):
        params = SourceParameters(sources=sources)
        with pytest.raises(SourceError):
            manager.add(params)

    def test_add_os_error(self, manager):
        # Mock the open function to raise an OSError
        with patch('builtins.open', mock_open()) as m:
            m.side_effect = OSError
            params = SourceParameters(sources=['deb http://archive.ubuntu.com/ubuntu/ bionic main restricted'])
            with pytest.raises(SourceError):
                manager.add(params)

#DO NOT DELETE THIS LINE - TestUbuntuOsSourceManagerList
'''
ADD HUMAN FEEDBACK BELOW:

'''
class TestUbuntuOsSourceManagerList:
    @pytest.mark.parametrize('file_content, expected_output', [
        # Normal scenario with one source line
        ("deb http://archive.ubuntu.com/ubuntu/ bionic main restricted\n", ["deb http://archive.ubuntu.com/ubuntu/ bionic main restricted"]),
        # Normal scenario with multiple source lines
        ("deb http://archive.ubuntu.com/ubuntu/ bionic main restricted\n" "deb-src http://archive.ubuntu.com/ubuntu/ bionic main restricted\n", ["deb http://archive.ubuntu.com/ubuntu/ bionic main restricted", "deb-src http://archive.ubuntu.com/ubuntu/ bionic main restricted"]),
        # Edge case scenario with no valid source lines
        ("# This is a comment\n", []),
        # Edge case scenario with invalid source lines
        ("invalid line\n", []),
        # Normal scenario with both valid and invalid source lines
        ("deb http://archive.ubuntu.com/ubuntu/ bionic main restricted\n" "invalid line\n", ["deb http://archive.ubuntu.com/ubuntu/ bionic main restricted"]),
    ])
    def test_list(self, file_content, expected_output):
        # Mock the open function to return the file content
        mock_file = mock_open(read_data=file_content)
        with patch("builtins.open", mock_file):
            manager = UbuntuOsSourceManager()
            assert manager.list() == expected_output

    @pytest.mark.parametrize('file_content, exception_message', [
        # Error scenario with non-existent file
        (None, "Error opening source file: [Errno 2] No such file or directory: '/etc/apt/sources.list'"),
    ])
    def test_list_error(self, file_content, exception_message):
        # Mock the open function to raise an OSError
        mock_file = mock_open()
        mock_file.side_effect = OSError("[Errno 2] No such file or directory: '/etc/apt/sources.list'")
        with patch("builtins.open", mock_file):
            manager = UbuntuOsSourceManager()
            with pytest.raises(SourceError) as e:
                manager.list()
            assert str(e.value) == exception_message

#DO NOT DELETE THIS LINE - TestUbuntuOsSourceManagerRemove
'''
ADD HUMAN FEEDBACK BELOW:

'''
class TestUbuntuOsSourceManagerRemove:
    @pytest.fixture
    def manager(self):
        return UbuntuOsSourceManager()

    @pytest.mark.parametrize('sources, file_content, expected_content', [
        (['deb http://archive.ubuntu.com/ubuntu/ bionic main restricted'], 
         'deb http://archive.ubuntu.com/ubuntu/ bionic main restricted\ndeb http://archive.ubuntu.com/ubuntu/ bionic universe', 
         'deb http://archive.ubuntu.com/ubuntu/ bionic universe\n'),
        (['deb http://archive.ubuntu.com/ubuntu/ bionic universe'], 
         'deb http://archive.ubuntu.com/ubuntu/ bionic main restricted\ndeb http://archive.ubuntu.com/ubuntu/ bionic universe', 
         'deb http://archive.ubuntu.com/ubuntu/ bionic main restricted\n'),
        (['deb http://archive.ubuntu.com/ubuntu/ bionic universe'], 
         'deb http://archive.ubuntu.com/ubuntu/ bionic main restricted', 
         'deb http://archive.ubuntu.com/ubuntu/ bionic main restricted\n'),
    ])
    def test_remove(self, manager, sources, file_content, expected_content):
        # Mocking the open function to simulate file read/write operations
        mock_file = mock_open(read_data=file_content)
        with patch('builtins.open', mock_file):
            manager.remove(SourceParameters(sources=sources))
            calls = [call(line) for line in expected_content.split('\n') if line]
            mock_file().write.assert_has_calls(calls, any_order=True)

    @pytest.mark.parametrize('sources, file_content', [
        (['deb http://archive.ubuntu.com/ubuntu/ bionic universe'], 
         'deb http://archive.ubuntu.com/ubuntu/ bionic main restricted'),
    ])
    def test_remove_source_not_found(self, manager, sources, file_content):
        # Mocking the open function to simulate file read/write operations
        mock_file = mock_open(read_data=file_content)
        with patch('builtins.open', mock_file):
            # Since the source to be removed is not in the file, it should not attempt to write to the file
            manager.remove(SourceParameters(sources=sources))
            calls = [call(line) for line in file_content.split('\n') if line]
            mock_file().write.assert_has_calls(calls, any_order=True)

    @pytest.mark.parametrize('sources, file_content', [
        (['deb http://archive.ubuntu.com/ubuntu/ bionic universe'], 
         'deb http://archive.ubuntu.com/ubuntu/ bionic main restricted'),
    ])
    def test_remove_os_error(self, manager, sources, file_content):
        # Mocking the open function to simulate an OSError
        mock_file = mock_open()
        mock_file.side_effect = OSError
        with patch('builtins.open', mock_file):
            with pytest.raises(SourceError):
                manager.remove(SourceParameters(sources=sources))

#DO NOT DELETE THIS LINE - TestUbuntuOsSourceManagerUpdate
'''
ADD HUMAN FEEDBACK BELOW:

'''
class TestUbuntuOsSourceManagerUpdate:
    @pytest.fixture
    def manager(self):
        return UbuntuOsSourceManager()

    @pytest.mark.parametrize('sources', [
        (['deb http://archive.ubuntu.com/ubuntu/ bionic main restricted']),
        (['deb http://archive.ubuntu.com/ubuntu/ bionic main restricted', 'deb-src http://archive.ubuntu.com/ubuntu/ bionic main restricted']),
    ])
    def test_update_valid_sources(self, manager, sources):
        # Mocking the built-in open function
        with patch('builtins.open', mock_open()) as m:
            manager.update(SourceParameters(sources=sources))
            m.assert_called_once_with('/etc/apt/sources.list', 'w')

    @pytest.mark.parametrize('sources', [
        (['invalid source']),
        (['deb http://archive.ubuntu.com/ubuntu/ bionic main restricted', 'invalid source']),
    ])
    def test_update_invalid_sources(self, manager, sources):
        # Mocking the built-in open function
        with patch('builtins.open', mock_open()) as m:
            with pytest.raises(SourceError):
                manager.update(SourceParameters(sources=sources))

    @pytest.mark.parametrize('sources', [
        ([]),
    ])
    def test_update_no_sources(self, manager, sources):
        # Mocking the built-in open function
        with patch('builtins.open', mock_open()) as m:
            manager.update(SourceParameters(sources=sources))
            m.assert_called_once_with('/etc/apt/sources.list', 'w')

    @pytest.mark.parametrize('sources', [
        (['deb http://archive.ubuntu.com/ubuntu/ bionic main restricted', 'deb http://archive.ubuntu.com/ubuntu/ bionic main restricted']),
    ])
    def test_update_duplicate_sources(self, manager, sources):
        # Mocking the built-in open function
        with patch('builtins.open', mock_open()) as m:
            manager.update(SourceParameters(sources=sources))
            m.assert_called_once_with('/etc/apt/sources.list', 'w')

    @pytest.mark.parametrize('sources', [
        (['deb http://archive.ubuntu.com/ubuntu/ bionic main restricted'*10000]),
    ])
    def test_update_large_sources(self, manager, sources):
        # Mocking the built-in open function
        with patch('builtins.open', mock_open()) as m:
            manager.update(SourceParameters(sources=sources))
            m.assert_called_once_with('/etc/apt/sources.list', 'w')

    @pytest.mark.parametrize('sources', [
        (['deb http://archive.ubuntu.com/ubuntu/ bionic main restricted\n']),
    ])
    def test_update_special_characters_in_sources(self, manager, sources):
        # Mocking the built-in open function
        with patch('builtins.open', mock_open()) as m:
            with pytest.raises(SourceError):
                manager.update(SourceParameters(sources=sources))

if __name__ == '__main__':
    pytest.main()