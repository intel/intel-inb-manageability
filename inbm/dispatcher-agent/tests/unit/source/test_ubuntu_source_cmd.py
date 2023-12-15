import pytest
from unittest.mock import mock_open, patch
from dispatcher.dispatcher_exception import DispatcherException
from dispatcher.source.ubuntu_source_cmd import UbuntuSourceApplicationCommand, UbuntuSourceOsCommand

MOCK_SOURCES_LIST = """\
# Comment line
deb http://example.com/ubuntu focal main restricted
deb-src http://example.com/ubuntu focal main restricted
"""

MOCK_SOURCES_LIST_D = """\
# Another comment line
deb http://example.com/ubuntu focal universe
deb-src http://example.com/ubuntu focal universe
"""


def test_ubuntu_source_os_command_list():
    with patch('builtins.open', mock_open(read_data=MOCK_SOURCES_LIST)) as mock_file:
        command = UbuntuSourceOsCommand()
        sources = command.list()
        mock_file.assert_called_once_with('/etc/apt/sources.list', 'r')
        assert sources == [
            'deb http://example.com/ubuntu focal main restricted',
            'deb-src http://example.com/ubuntu focal main restricted',
        ]


def test_ubuntu_source_os_command_list_exception():
    with patch('builtins.open', side_effect=OSError):
        command = UbuntuSourceOsCommand()
        with pytest.raises(DispatcherException) as exc_info:
            command.list()
        assert 'Error opening source file' in str(exc_info.value)


def test_ubuntu_source_application_command_list():
    with patch('glob.glob', return_value=['/etc/apt/sources.list.d/example.list']),\
            patch('builtins.open', mock_open(read_data=MOCK_SOURCES_LIST_D)):
        command = UbuntuSourceApplicationCommand()
        sources = command.list()
        assert sources[0].name == 'example.list'
        assert sources[0].sources == [
            'deb http://example.com/ubuntu focal universe',
            'deb-src http://example.com/ubuntu focal universe',
        ]


def test_ubuntu_source_application_command_list_exception():
    with patch('glob.glob', return_value=['/etc/apt/sources.list.d/example.list']),\
            patch('builtins.open', side_effect=OSError):
        command = UbuntuSourceApplicationCommand()
        with pytest.raises(DispatcherException) as exc_info:
            command.list()
        assert 'Error listing application sources' in str(exc_info.value)
