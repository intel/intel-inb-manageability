import pytest
from dispatcher.source.constants import OsType
from dispatcher.source.source_cmd_factory import create_source_application_command, create_source_os_command
from dispatcher.source.ubuntu_source_cmd import UbuntuSourceApplicationCommand, UbuntuSourceOsCommand


def test_create_source_os_command_ubuntu():
    command = create_source_os_command(OsType.Ubuntu)
    assert isinstance(command, UbuntuSourceOsCommand)


def test_create_source_os_command_unsupported():
    with pytest.raises(ValueError) as excinfo:
        create_source_os_command("UnsupportedOS")
    assert "Unsupported OS type" in str(excinfo.value)


def test_create_source_application_command_ubuntu():
    command = create_source_application_command(OsType.Ubuntu)
    assert isinstance(command, UbuntuSourceApplicationCommand)


def test_create_source_application_command_unsupported():
    with pytest.raises(ValueError) as excinfo:
        create_source_application_command("UnsupportedOS")
    assert "Unsupported OS type" in str(excinfo.value)
