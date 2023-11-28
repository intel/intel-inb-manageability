import os
from unittest import TestCase

from dispatcher.fota.os_factory import OsFactory, LinuxFactory, LinuxUpgradeChecker, WindowsUpgradeChecker, \
    LinuxInstaller, WindowsInstaller, LinuxRebooter, WindowsRebooter, WindowsFactory
from ..common.mock_resources import *
from dispatcher.packagemanager.memory_repo import MemoryRepo

FW_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                  '..', '..', '..', 'fpm-template', 'usr', 'share',
                                  'dispatcher-agent', 'firmware_tool_config_schema.xsd')
FW_CONF_PATH = os.path.join(os.path.dirname(__file__),
                            '..', '..', '..', 'fpm-template', 'etc',
                                  'firmware_tool_info.conf')


class TestOsFactory(TestCase):

    def setUp(self) -> None:
        self.mock_disp_obj = MockDispatcher.build_mock_dispatcher()
        self.mock_disp_broker = MockDispatcherBroker.build_mock_dispatcher_broker()

    def test_get_factory_linux(self) -> None:
        assert type(OsFactory.get_factory("Linux", fake_ota_resource,
                                          self.mock_disp_broker)) is LinuxFactory

    def test_get_factory_windows(self) -> None:
        assert type(OsFactory.get_factory("Windows", fake_ota_resource,
                                          self.mock_disp_broker)) is WindowsFactory

    def test_raise_error_unsupported_os(self) -> None:
        self.assertRaises(ValueError, OsFactory.get_factory, "MacOS",
                          fake_ota_resource, self.mock_disp_broker)

    def test_create_linux_upgrade_checker(self) -> None:
        assert type(OsFactory.get_factory("Linux", fake_ota_resource, self.mock_disp_broker).create_upgrade_checker()) \
            is LinuxUpgradeChecker

    def test_create_windows_upgrade_checker(self) -> None:
        assert type(OsFactory.get_factory("Windows", fake_ota_resource, self.mock_disp_broker).create_upgrade_checker()) \
            is WindowsUpgradeChecker

    def test_create_linux_installer(self) -> None:
        assert type(OsFactory.get_factory("Linux", fake_ota_resource,
                                          self.mock_disp_broker).create_installer(MemoryRepo("test"),
                                                                                  FW_CONF_PATH, FW_SCHEMA_LOCATION)) \
            is LinuxInstaller

    def test_create_windows_installer(self) -> None:
        assert type(OsFactory.get_factory("Windows", fake_ota_resource,
                                          self.mock_disp_broker).create_installer(MemoryRepo("test"),
                                                                                  FW_CONF_PATH, FW_SCHEMA_LOCATION)) \
            is WindowsInstaller

    def test_create_linux_rebooter(self) -> None:
        assert type(OsFactory.get_factory("Linux", fake_ota_resource, self.mock_disp_broker).create_rebooter()) \
            is LinuxRebooter

    def test_create_windows_rebooter(self) -> None:
        assert type(OsFactory.get_factory("Windows", fake_ota_resource, self.mock_disp_broker).create_rebooter()) \
            is WindowsRebooter
