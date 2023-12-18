from unittest import mock
import pytest
from unittest.mock import mock_open, patch
from dispatcher.dispatcher_exception import DispatcherException
from dispatcher.source.constants import SourceParameters
from dispatcher.source.ubuntu_source_manager import UbuntuApplicationSourceManager, UbuntuOsSourceManager

@pytest.fixture
def sources_list_content():
    return (
        "# Comment line\n"
        "deb http://example.com/ubuntu focal main restricted\n"
        "deb-src http://example.com/ubuntu focal main restricted\n"
    )


@pytest.fixture
def sources_list_d_content():
    return (
        "# Another comment line\n"
        "deb http://example.com/ubuntu focal universe\n"
        "deb-src http://example.com/ubuntu focal universe\n"
    )

class TestUbuntuOSSourceManager:
    def test_list(self, sources_list_content):
        with patch('builtins.open', mock_open(read_data=sources_list_content)) as mock_file:
            command = UbuntuOsSourceManager()
            sources = command.list()
            mock_file.assert_called_once_with('/etc/apt/sources.list', 'r')
            assert sources == [
                'deb http://example.com/ubuntu focal main restricted',
                'deb-src http://example.com/ubuntu focal main restricted',
            ]


    def test_list_with_oserror_exception(self):
        with patch('builtins.open', side_effect=OSError):
            command = UbuntuOsSourceManager()
            with pytest.raises(DispatcherException) as exc_info:
                command.list()
            assert 'Error opening source file' in str(exc_info.value)

    def test_remove_single_source(self, sources_list_content):
        initial_content = sources_list_content
        sources_to_remove = SourceParameters(sources=["deb http://example.com/ubuntu focal main restricted"])
        
        # Expected content after removal:
        expected_content = ["# Comment line\n","deb-src http://example.com/ubuntu focal main restricted\n"]

        # Mocking open to simulate file read and write operations
        mo = mock_open(read_data=initial_content)
        with patch('builtins.open', mo):
            manager = UbuntuOsSourceManager()
            manager.remove(sources_to_remove)
        
        # Check that the file was opened twice ('r' and 'w')
        assert mo.call_count == 2
        write_calls = [mock.call(line) for line in expected_content]
        mo().write.assert_has_calls(write_calls, any_order=False)

    def test_remove_multiple_sources(self, sources_list_content):
        initial_content = sources_list_content
        sources_to_remove = SourceParameters(sources=["deb http://example.com/ubuntu focal main restricted", "deb http://example.com/ubuntu focal main restricted"])
        
        # Expected content after removal:
        expected_content = ["# Comment line\n"]

        # Mocking open to simulate file read and write operations
        mo = mock_open(read_data=initial_content)
        with patch('builtins.open', mo):
            manager = UbuntuOsSourceManager()
            manager.remove(sources_to_remove)
        
        # Check that the file was opened twice ('r' and 'w')
        assert mo.call_count == 2
        write_calls = [mock.call(line) for line in expected_content]
        mo().write.assert_has_calls(write_calls, any_order=False)

    def test_remove_nonexistent_source(self, sources_list_content):
        initial_content = sources_list_content
        sources_to_remove = SourceParameters(sources=["nonexistent source line"])

        mo = mock_open(read_data=initial_content)
        with patch('builtins.open', mo):
            manager = UbuntuOsSourceManager()
            manager.remove(sources_to_remove)
        
        # Check that the file was opened twice ('r' and 'w')
        assert mo.call_count == 2

        # Check that the file content hasn't changed since the source was not found
        write_calls = [mock.call(line+"\n") for line in initial_content.splitlines()]
        mo().write.assert_has_calls(write_calls, any_order=False)


    def test_remove_raises_dispatcher_exception_on_write_error(self, sources_list_content):
        sources_to_remove = SourceParameters(sources=["deb http://example.com/ubuntu focal main restricted"])

        mo = mock_open(read_data=sources_list_content)
        
        def write_side_effect(*args, **kwargs):
            raise OSError("Write error")

        mo.return_value.write.side_effect = write_side_effect

        with patch('builtins.open', mo), \
            pytest.raises(DispatcherException) as exc_info:
            manager = UbuntuOsSourceManager()
            manager.remove(sources_to_remove)
        
        assert "Error occurred while trying to remove sources" in str(exc_info.value)



class TestUbuntuApplicationSourceManager:
    def test_list(self, sources_list_d_content):
        with patch('glob.glob', return_value=['/etc/apt/sources.list.d/example.list']),\
                patch('builtins.open', mock_open(read_data=sources_list_d_content)):
            command = UbuntuApplicationSourceManager()
            sources = command.list()
            assert sources[0].name == 'example.list'
            assert sources[0].sources == [
                'deb http://example.com/ubuntu focal universe',
                'deb-src http://example.com/ubuntu focal universe',
            ]


    def test_list_raises_exception(self):
        with patch('glob.glob', return_value=['/etc/apt/sources.list.d/example.list']),\
                patch('builtins.open', side_effect=OSError):
            command = UbuntuApplicationSourceManager()
            with pytest.raises(DispatcherException) as exc_info:
                command.list()
            assert 'Error listing application sources' in str(exc_info.value)

