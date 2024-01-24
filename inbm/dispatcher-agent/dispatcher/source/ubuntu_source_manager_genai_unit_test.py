import sys
sys.path.insert(0, '../')
sys.path.insert(0, '../../../')
sys.path.insert(0, '../../')
sys.path.insert(0, '../../../../')
sys.path.insert(0, './')
sys.path.insert(0, '/home/runner/GITHUB_ACTION_RUNNERS/_work/intel-inb-manageability/intel-inb-manageability/inbm/dispatcher-agent/')
sys.path.insert(0, '/home/runner/GITHUB_ACTION_RUNNERS/_work/intel-inb-manageability/intel-inb-manageability/inbm-lib/')
sys.path.insert(0, '/home/runner/GITHUB_ACTION_RUNNERS/_work/intel-inb-manageability/intel-inb-manageability/inbm/dispatcher-agent/dispatcher/source/')
sys.path.insert(0, '/home/runner/GITHUB_ACTION_RUNNERS/_work/genai_ag_intel-inb-manageability/genai_ag_intel-inb-manageability/inbm/dispatcher-agent/')
sys.path.insert(0, '/home/runner/GITHUB_ACTION_RUNNERS/_work/genai_ag_intel-inb-manageability/genai_ag_intel-inb-manageability/inbm-lib/')
sys.path.insert(0, '/home/runner/GITHUB_ACTION_RUNNERS/_work/genai_ag_intel-inb-manageability/genai_ag_intel-inb-manageability/inbm/dispatcher-agent/dispatcher/source/')
import pytest
from unittest.mock import patch, MagicMock
from dispatcher.source.ubuntu_source_manager import UbuntuApplicationSourceManager, ApplicationAddSourceParameters
from unittest.mock import patch, mock_open
from dispatcher.source.ubuntu_source_manager import UbuntuApplicationSourceManager, ApplicationSourceList
from dispatcher.source.ubuntu_source_manager import UbuntuApplicationSourceManager, ApplicationRemoveSourceParameters, SourceError
from dispatcher.source.ubuntu_source_manager import UbuntuApplicationSourceManager, SourceError, ApplicationUpdateSourceParameters
from dispatcher.source.ubuntu_source_manager import UbuntuOsSourceManager, SourceParameters, SourceError
from dispatcher.source.ubuntu_source_manager import UbuntuOsSourceManager, SourceError

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
        ('test_key', 'http://test.com/key', 'test_file', ['deb http://test.com/ubuntu bionic main']),
        (None, None, 'test_file', ['deb http://test.com/ubuntu bionic main']),
        ('test_key', 'http://test.com/key', 'test_file', []),
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
            mock_verify_source.assert_called_once()
            mock_add_gpg_key.assert_called_once_with(gpg_key_uri, gpg_key_name)
        mock_create_file_with_contents.assert_called_once_with('/etc/apt/sources.list.d/' + source_list_file_name, sources)

#DO NOT DELETE THIS LINE - TestUbuntuApplicationSourceManagerList
'''
ADD HUMAN FEEDBACK BELOW:

'''
class TestUbuntuApplicationSourceManagerList:
    @pytest.mark.parametrize('file_content, expected_output', [
        # Test with one source
        (["deb http://archive.ubuntu.com/ubuntu/ focal universe"], 
         [ApplicationSourceList(name="sources.list", sources=["deb http://archive.ubuntu.com/ubuntu/ focal universe"])]),
        
        # Test with multiple sources
        (["deb http://archive.ubuntu.com/ubuntu/ focal universe", "deb-src http://archive.ubuntu.com/ubuntu/ focal universe"], 
         [ApplicationSourceList(name="sources.list", sources=["deb http://archive.ubuntu.com/ubuntu/ focal universe", "deb-src http://archive.ubuntu.com/ubuntu/ focal universe"])]),
        
        # Test with no sources
        ([], [ApplicationSourceList(name="sources.list", sources=[])]),  # Fixed this line
        
        # Test with comments and empty lines
        (["# This is a comment", "", "deb http://archive.ubuntu.com/ubuntu/ focal universe"], 
         [ApplicationSourceList(name="sources.list", sources=["deb http://archive.ubuntu.com/ubuntu/ focal universe"])]),
    ])
    @patch('glob.glob')
    @patch('builtins.open', new_callable=mock_open)
    def test_list(self, mock_open, mock_glob, file_content, expected_output):
        # Mock the glob.glob call to return a single file
        mock_glob.return_value = ["sources.list"]
        
        # Mock the open call to return the file content
        mock_open().readlines.return_value = file_content
        
        # Create an instance of the class under test
        manager = UbuntuApplicationSourceManager(None)
        
        # Call the method under test
        result = manager.list()
        
        # Assert that the result is as expected
        assert result == expected_output

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
        return ApplicationRemoveSourceParameters(source_list_file_name='test', gpg_key_name='test_key')

    @pytest.mark.parametrize('file_exists, key_exists, should_raise', [
        (True, True, False),  # Normal case
        (False, True, True),  # File does not exist
        (True, False, False),  # Key does not exist
        (False, False, True),  # Neither file nor key exist
    ])
    @patch('dispatcher.source.ubuntu_source_manager.remove_file')
    @patch('dispatcher.source.ubuntu_source_manager.get_canonical_representation_of_path')
    def test_remove(self, mock_get_path, mock_remove_file, manager, parameters, file_exists, key_exists, should_raise):
        # Mock the remove_file function to return whether the file/key exists
        mock_remove_file.side_effect = lambda path: file_exists if 'sources.list.d' in path else key_exists

        # Mock the get_canonical_representation_of_path function to return the same path
        mock_get_path.side_effect = lambda path: path

        if should_raise:
            with pytest.raises(SourceError):
                manager.remove(parameters)
        else:
            manager.remove(parameters)
            assert mock_remove_file.call_count == 2  # Both the file and the key should be removed

    @pytest.mark.parametrize('file_name, should_raise', [
        ('test', False),  # Normal case
        ('..', True),  # Invalid file name
        ('.', True),  # Invalid file name
        ('test/test', True),  # Invalid file name
    ])
    def test_remove_invalid_file_name(self, manager, file_name, should_raise):
        parameters = ApplicationRemoveSourceParameters(source_list_file_name=file_name, gpg_key_name='test_key')

        if should_raise:
            with pytest.raises(SourceError):
                manager.remove(parameters)
        else:
            manager.remove(parameters)  # Should not raise

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
        return ApplicationUpdateSourceParameters(source_list_file_name='test_file', sources=['test_source'])

    @pytest.mark.parametrize('exception, expected_exception', [
        (IOError('test error'), SourceError),
        (None, None)
    ])
    def test_update(self, manager, parameters, exception, expected_exception):
        # Mock the os.path.join function to return a dummy file path
        with patch('os.path.join', return_value='dummy_file_path'):
            # Mock the create_file_with_contents function
            with patch('inbm_common_lib.utility.create_file_with_contents') as mock_create:
                # Mock the open function to prevent actual file operations
                with patch('builtins.open', MagicMock()):
                    # If an exception is specified, configure the mock to raise it
                    if exception is not None:
                        mock_create.side_effect = exception

                    # Call the function
                    try:
                        manager.update(parameters)
                    except SourceError as e:
                        # If an expected exception is specified, assert that it is raised
                        if expected_exception is not None:
                            assert isinstance(e, expected_exception)
                    else:
                        # Otherwise, assert that the mock was called with the correct arguments
                        mock_create.assert_called_once_with('dummy_file_path', ['test_source'])

#DO NOT DELETE THIS LINE - TestUbuntuOsSourceManagerAdd
'''
ADD HUMAN FEEDBACK BELOW:

'''
class TestUbuntuOsSourceManagerAdd:
    @pytest.fixture
    def manager(self):
        return UbuntuOsSourceManager()

    @pytest.mark.parametrize('sources', [
        (['http://example.com']),
        (['http://example.com', 'http://example2.com']),
        (['http://example.com/path/to/repo']),
        (['http://example.com/path/to/repo', 'http://example2.com/path/to/another/repo']),
    ])
    def test_add_sources(self, manager, sources):
        # Mock the open function
        with patch('builtins.open', mock_open()) as m:
            params = SourceParameters(sources=sources)
            manager.add(params)
            m.assert_called_once_with('/etc/apt/sources.list', 'a')
            handle = m()
            for source in sources:
                handle.write.assert_any_call(f"{source}\n")

    @pytest.mark.parametrize('sources', [
        (['http://example.com']),
    ])
    def test_add_sources_os_error(self, manager, sources):
        # Mock the open function to raise an OSError
        with patch('builtins.open', mock_open()) as m:
            m.side_effect = OSError
            params = SourceParameters(sources=sources)
            with pytest.raises(SourceError):
                manager.add(params)

    @pytest.mark.parametrize('sources', [
        (['http://localhost/path/to/repo']),
        (['http://192.168.1.100/path/to/repo']),
        (['ftp://example.com/path/to/repo']),
        (['file:///path/to/repo']),
        (['http://user:password@example.com/path/to/repo']),
        (['http://example.com:8080/path/to/repo']),
        (['http://example.com/path/to/repo?query=string']),
        (['http://example.com/path/to/repo#fragment']),
    ])
    def test_add_sources_edge_cases(self, manager, sources):
        # Mock the open function
        with patch('builtins.open', mock_open()) as m:
            params = SourceParameters(sources=sources)
            manager.add(params)
            m.assert_called_once_with('/etc/apt/sources.list', 'a')
            handle = m()
            for source in sources:
                handle.write.assert_any_call(f"{source}\n")

#DO NOT DELETE THIS LINE - TestUbuntuOsSourceManagerList
'''
ADD HUMAN FEEDBACK BELOW:

'''
class TestUbuntuOsSourceManagerList:
    @pytest.fixture
    def manager(self):
        return UbuntuOsSourceManager()

    @pytest.mark.parametrize('file_content, expected_output', [
        # Normal scenario with multiple sources
        ("deb http://archive.ubuntu.com/ubuntu/ focal universe\ndeb-src http://archive.ubuntu.com/ubuntu/ focal universe\n", ["deb http://archive.ubuntu.com/ubuntu/ focal universe", "deb-src http://archive.ubuntu.com/ubuntu/ focal universe"]),
        # Normal scenario with single source
        ("deb http://archive.ubuntu.com/ubuntu/ focal universe\n", ["deb http://archive.ubuntu.com/ubuntu/ focal universe"]),
        # Edge case with empty file
        ("", []),
        # Edge case with invalid sources
        ("invalid source\n", []),
        # Edge case with duplicate sources
        ("deb http://archive.ubuntu.com/ubuntu/ focal universe\ndeb http://archive.ubuntu.com/ubuntu/ focal universe\n", ["deb http://archive.ubuntu.com/ubuntu/ focal universe", "deb http://archive.ubuntu.com/ubuntu/ focal universe"]),
    ])
    def test_list(self, manager, file_content, expected_output):
        with patch("builtins.open", mock_open(read_data=file_content)):
            assert manager.list() == expected_output

    @pytest.mark.parametrize('file_content, exception_message', [
        # Error scenario with non-existent file
        (FileNotFoundError, "Error opening source file: [Errno 2] No such file or directory: '/etc/apt/sources.list'"),
        # Error scenario with inaccessible file
        (PermissionError, "Error opening source file: [Errno 13] Permission denied: '/etc/apt/sources.list'"),
    ])
    def test_list_error(self, manager, file_content, exception_message):
        with patch("builtins.open", mock_open()) as mock_file:
            mock_file.side_effect = file_content
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
        (['deb http://archive.ubuntu.com/ubuntu/ bionic main'], 'deb http://archive.ubuntu.com/ubuntu/ bionic main\n', ''),
        (['deb http://archive.ubuntu.com/ubuntu/ bionic main'], 'deb http://archive.ubuntu.com/ubuntu/ bionic universe\n', 'deb http://archive.ubuntu.com/ubuntu/ bionic universe\n'),
        (['deb http://archive.ubuntu.com/ubuntu/ bionic main'], '', ''),
    ])
    def test_remove(self, manager, sources, file_content, expected_content):
        # Mocking the open function
        mock_file = mock_open(read_data=file_content)
        with patch('builtins.open', mock_file):
            manager.remove(SourceParameters(sources=sources))
            if expected_content:
                mock_file().write.assert_called_once_with(expected_content)
            else:
                mock_file().write.assert_not_called()

    @pytest.mark.parametrize('sources, file_content', [
        (['deb http://archive.ubuntu.com/ubuntu/ bionic main'], 'deb http://archive.ubuntu.com/ubuntu/ bionic main\n'),
        (['deb http://archive.ubuntu.com/ubuntu/ bionic main'], 'deb http://archive.ubuntu.com/ubuntu/ bionic universe\n'),
        (['deb http://archive.ubuntu.com/ubuntu/ bionic main'], ''),
    ])
    def test_remove_os_error(self, manager, sources, file_content):
        # Mocking the open function to raise an OSError
        mock_file = mock_open(read_data=file_content)
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

    @pytest.mark.parametrize('sources, file_contents, exception_expected', [
        # Test with normal sources
        (['deb http://archive.ubuntu.com/ubuntu/ focal universe', 'deb-src http://archive.ubuntu.com/ubuntu/ focal universe'], 
         ['deb http://archive.ubuntu.com/ubuntu/ focal universe\n', 'deb-src http://archive.ubuntu.com/ubuntu/ focal universe\n'], 
         False),
        # Test with empty sources
        ([], [], False),
        # Test with special characters in sources
        (['deb http://archive.ubuntu.com/ubuntu/ focal universe # special char', 'deb-src http://archive.ubuntu.com/ubuntu/ focal universe # special char'], 
         ['deb http://archive.ubuntu.com/ubuntu/ focal universe # special char\n', 'deb-src http://archive.ubuntu.com/ubuntu/ focal universe # special char\n'], 
         False),
        # Test with OSError when trying to open file
        (['deb http://archive.ubuntu.com/ubuntu/ focal universe'], ['deb http://archive.ubuntu.com/ubuntu/ focal universe\n'], True)
    ])
    def test_update(self, manager, sources, file_contents, exception_expected):
        parameters = SourceParameters(sources=sources)
        mock_file = mock_open()
        with patch('builtins.open', mock_file):
            if exception_expected:
                mock_file.side_effect = OSError('Mocked OSError')
                with pytest.raises(SourceError):
                    manager.update(parameters)
            else:
                manager.update(parameters)
                mock_file.assert_called_once_with('/etc/apt/sources.list', 'w')
                for file_content in file_contents:
                    mock_file().write.assert_any_call(file_content)

if __name__ == '__main__':
    pytest.main()