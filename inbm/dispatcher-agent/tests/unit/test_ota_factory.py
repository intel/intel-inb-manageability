import pytest

from unit.common.mock_resources import *
from dispatcher.ota_factory import *


@pytest.fixture
def mock_disp_obj():
    return MockDispatcher.build_mock_dispatcher()


@pytest.fixture
def mock_disp_broker():
    return MockDispatcherBroker.build_mock_dispatcher_broker()


@pytest.mark.parametrize("ota_type, expected_factory", [
    ("FOTA", FotaFactory),
    ("SOTA", SotaFactory),
    ("AOTA", AotaFactory),
])
def test_get_factory(ota_type, expected_factory, mock_disp_obj, mock_disp_broker) -> None:
    factory = OtaFactory.get_factory(
        ota_type,
        "remote",
        mock_disp_broker,
        True,
        None,
        MockInstallCheckService(),
        UpdateLogger(ota_type=ota_type, data="metadata"),
        ConfigDbs.ON
    )
    assert isinstance(factory, expected_factory)


def test_raise_error_unsupported_ota(mock_disp_obj, mock_disp_broker) -> None:
    with pytest.raises(ValueError):
        OtaFactory.get_factory(
            "IOTA",
            "remote",
            mock_disp_broker,
            True,
            None,
            MockInstallCheckService(),
            UpdateLogger(ota_type="IOTA", data="metadata"),
            ConfigDbs.OFF
        )


@pytest.mark.parametrize("ota_type, expected_parser", [
    ("FOTA", FotaParser),
    ("SOTA", SotaParser),
    ("AOTA", AotaParser),
])
def test_create_parser(ota_type, expected_parser, mock_disp_obj, mock_disp_broker) -> None:
    parser = OtaFactory.get_factory(
        ota_type,
        "remote",
        mock_disp_broker,
        True,
        None,
        MockInstallCheckService(),
        UpdateLogger(ota_type=ota_type, data="metadata"),
        ConfigDbs.ON
    ).create_parser()
    assert isinstance(parser, expected_parser)


@pytest.mark.parametrize("ota_type, expected_thread", [
    ("FOTA", FotaThread),
    ("SOTA", SotaThread),
    ("AOTA", AotaThread),
])
def test_create_thread(ota_type, expected_thread, mock_disp_obj, mock_disp_broker) -> None:
    thread = OtaFactory.get_factory(
        ota_type,
        "remote",
        mock_disp_broker,
        True,
        None,
        MockInstallCheckService(),
        UpdateLogger(ota_type=ota_type, data="metadata"),
        ConfigDbs.ON
    ).create_thread({'abc': 'def'})
    assert isinstance(thread, expected_thread)
