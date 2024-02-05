import pytest
from dispatcher.source.constants import OsType
from ..common.mock_resources import MockDispatcherBroker
from dispatcher.source.source_manager_factory import (
    create_application_source_manager,
    create_os_source_manager,
)
from dispatcher.source.ubuntu_source_manager import (
    UbuntuApplicationSourceManager,
    UbuntuOsSourceManager,
)


def test_create_os_source_manager_ubuntu():
    command = create_os_source_manager(OsType.Ubuntu)
    assert isinstance(command, UbuntuOsSourceManager)


def test_create_os_source_manager_unsupported():
    with pytest.raises(ValueError) as excinfo:
        create_os_source_manager("UnsupportedOS")
    assert "Unsupported OS type" in str(excinfo.value)


def test_create_application_source_manager_ubuntu():
    mock_disp_broker_obj = MockDispatcherBroker.build_mock_dispatcher_broker()
    command = create_application_source_manager(OsType.Ubuntu, mock_disp_broker_obj)
    assert isinstance(command, UbuntuApplicationSourceManager)


def test_create_application_source_manager_unsupported():
    mock_disp_broker_obj = MockDispatcherBroker.build_mock_dispatcher_broker()
    with pytest.raises(ValueError) as excinfo:
        create_application_source_manager("UnsupportedOS", mock_disp_broker_obj)
    assert "Unsupported OS type" in str(excinfo.value)
