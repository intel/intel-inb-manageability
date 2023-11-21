import os
import unittest
from typing import Dict, Optional, List

from ..common.mock_resources import *
from dispatcher.dispatcher_callbacks import DispatcherCallbacks
from dispatcher.fota.fota import FOTA
from dispatcher.fota.fota_error import FotaError
from dispatcher.packagemanager.memory_repo import MemoryRepo
from inbm_lib.xmlhandler import XmlHandler
from dispatcher.fota.installer import LinuxInstaller
from mock import patch
import time

TEST_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                    '..', '..', '..', 'fpm-template', 'usr', 'share', 'dispatcher-agent',
                                    'manifest_schema.xsd')
FW_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                  '..', '..', '..', 'fpm-template', 'usr', 'share',
                                  'dispatcher-agent', 'firmware_tool_config_schema.xsd')
FW_CONF_PATH = os.path.join(os.path.dirname(__file__),
                            '..', '..', '..', 'fpm-template', 'etc',
                                  'firmware_tool_info.conf')


class TestFota(unittest.TestCase):
    mock_disp_obj = MockDispatcher.build_mock_dispatcher()
    resource = {'': ''}
    resource_2 = {'': '', 'holdReboot': True}
    _fota_instance: Optional[FOTA] = None
    _fota_instance_1: Optional[FOTA] = None
    _fota_local_instance: Optional[FOTA] = None
    invalid_parsed: Optional[XmlHandler] = None
    invalid_resource: Optional[Dict] = None
    mock_disp_callbacks = DispatcherCallbacks(broker_core=MockDispatcherBroker.build_mock_dispatcher_broker(),
                                              logger=mock_disp_obj.update_logger)

    @classmethod
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("", "", 0))
    def setUpClass(cls, mock_pseudoshellrunner):
        parsed = XmlHandler(fake_ota_success, is_file=False, schema_location=TEST_SCHEMA_LOCATION)
        cls.resource = parsed.get_children('ota/type/fota')
        parsed_manifest = {'resource': cls.resource,
                           'callback': cls.mock_disp_obj, 'signature': None, 'hash_algorithm': None,
                           'uri': mock_url.value, 'repo': "/cache/", 'username': username,
                           'password': password, 'deviceReboot': 'yes'}
        TestFota._fota_instance = FOTA(parsed_manifest, "remote", cls.mock_disp_callbacks)
        TestFota._fota_local_instance = FOTA(parsed_manifest, "local", cls.mock_disp_callbacks)
        parsed_manifest.update({'resource': cls.resource_2})
        TestFota._fota_instance_1 = FOTA(parsed_manifest, "remote", cls.mock_disp_callbacks)
        cls.invalid_parsed = XmlHandler(
            fake_ota_invalid, is_file=False, schema_location=TEST_SCHEMA_LOCATION)
        cls.invalid_resource = cls.invalid_parsed.get_children('ota/type/fota')

    @patch('dispatcher.common.dispatcher_state.write_dispatcher_state_to_state_file', autospec=True)
    @patch('dispatcher.fota.rebooter.LinuxRebooter.reboot')
    @patch('dispatcher.fota.installer.LinuxInstaller.install', return_value=True)
    @patch('dispatcher.fota.fota.download')
    @patch('dispatcher.fota.upgrade_checker.LinuxUpgradeChecker.check')
    @patch('dispatcher.fota.os_factory.LinuxFactory.create_installer')
    def test_does_not_download_with_local_repo(self, mock_create_installer, mock_upgrade_check, mock_downloader, mock_install, mock_rebooter, mock_dispatcher_state):
        mock_upgrade_check.return_value = 'abc', 'def'
        mock_dispatcher_state.return_value = True
        mock_create_installer.return_value = LinuxInstaller(self.mock_disp_callbacks,
                                                            TestFota._build_mock_repo(0), FW_CONF_PATH, FW_SCHEMA_LOCATION)
        assert TestFota._fota_local_instance
        TestFota._fota_local_instance.install()
        mock_upgrade_check.assert_called_once()
        mock_downloader.assert_not_called()
        mock_install.assert_called_once()
        time.sleep(0.12)
        mock_rebooter.assert_called_once()

    @patch("dispatcher.fota.fota.DirectoryRepo.delete")
    @patch('dispatcher.fota.fota.download', side_effect=FotaError('dispatcher.fota error'))
    @patch('dispatcher.fota.installer.LinuxInstaller.install', return_value=False)
    @patch('dispatcher.fota.upgrade_checker.LinuxUpgradeChecker.check')
    @patch('platform.system', return_value='Linux')
    def test_install_download_fails(self, mock_platform,
                                    mock_upgrade_check, mock_install, mock_downloader, mock_delete):
        mock_upgrade_check.return_value = 'abc', 'def'
        mock_downloader.return_value = 'fakepath'
        assert TestFota._fota_instance
        TestFota._fota_instance.install()
        mock_upgrade_check.assert_called_once()
        mock_downloader.assert_called_once()
        mock_install.assert_not_called()
        mock_delete.assert_called_once()

    @patch('dispatcher.fota.fota.download')
    @patch('dispatcher.fota.installer.LinuxInstaller.install')
    @patch('dispatcher.fota.upgrade_checker.LinuxUpgradeChecker.check', return_value=False)
    @patch('platform.system', return_value='Linux')
    def test_install_not_upgradable(self, mock_platform,
                                    mock_upgrade_check, mock_install, mock_downloader):
        mock_upgrade_check.return_value = "test", "test", False
        mock_install.return_value = False
        mock_downloader.return_value = 'fakepath'
        assert TestFota._fota_instance
        TestFota._fota_instance.install()
        mock_upgrade_check.assert_called_once()
        mock_downloader.assert_not_called()
        mock_install.assert_not_called()

    @patch('dispatcher.fota.manifest.parse_tool_options', return_value='/b /p')
    @patch('dispatcher.fota.rebooter.LinuxRebooter.reboot')
    @patch('dispatcher.fota.fota.download', return_value='fakepath')
    @patch('dispatcher.fota.installer.LinuxInstaller.install', return_value=True)
    @patch('dispatcher.fota.upgrade_checker.LinuxUpgradeChecker.check')
    @patch('platform.system', return_value='Linux')
    @patch('dispatcher.fota.os_factory.LinuxFactory.create_installer')
    @patch('dispatcher.common.dispatcher_state.write_dispatcher_state_to_state_file', autospec=True)
    def test_install_success(self, mock_dispatcher_state, mock_create_installer, mock_system, mock_upgrade_check, mock_install,
                             mock_downloader, mock_rebooter, mock_tool_options):
        mock_dispatcher_state.return_value = True
        mock_upgrade_check.return_value = 'abc', 'def'
        mock_create_installer.return_value = LinuxInstaller(self.mock_disp_callbacks,
                                                            TestFota._build_mock_repo(0), FW_CONF_PATH, FW_SCHEMA_LOCATION)
        assert TestFota._fota_instance
        TestFota._fota_instance.install()
        mock_upgrade_check.assert_called_once()
        mock_downloader.assert_called_once()
        mock_install.assert_called_once()
        time.sleep(0.15)
        mock_rebooter.assert_called_once()

    @patch('dispatcher.fota.manifest.parse_tool_options', return_value='/b /p')
    @patch('dispatcher.fota.upgrade_checker.LinuxUpgradeChecker.check', return_value=True)
    @patch('platform.system', return_value='Linux')
    @patch('dispatcher.fota.os_factory.LinuxFactory.create_installer')
    @patch('dispatcher.common.dispatcher_state.write_dispatcher_state_to_state_file', autospec=True)
    @patch('dispatcher.common.dispatcher_state.clear_dispatcher_state', autospec=True)
    def test_install_failure(self, mock_clear_disp_state, mock_dispatcher_state, mock_create_installer, mock_system, mock_upgrade_check,
                             mock_tool_options):
        mock_dispatcher_state.return_value = True
        mock_upgrade_check.return_value = False, '', 'abc', 'def'
        mock_create_installer.return_value = LinuxInstaller(self.mock_disp_callbacks,
                                                            TestFota._build_mock_repo(0), FW_CONF_PATH, FW_SCHEMA_LOCATION)
        assert TestFota._fota_instance
        TestFota._fota_instance.install()
        mock_upgrade_check.assert_called_once()
        time.sleep(0.15)
        mock_clear_disp_state.assert_called_once()

    @patch('dispatcher.fota.manifest.parse_tool_options', return_value='/b /p')
    @patch('dispatcher.fota.rebooter.LinuxRebooter.reboot')
    @patch('dispatcher.fota.fota.download', return_value='fakepath')
    @patch('dispatcher.fota.installer.LinuxInstaller.install', return_value=True)
    @patch('dispatcher.fota.upgrade_checker.LinuxUpgradeChecker.check')
    @patch('platform.system', return_value='Linux')
    @patch('dispatcher.fota.os_factory.LinuxFactory.create_installer')
    @patch('dispatcher.common.dispatcher_state.write_dispatcher_state_to_state_file', autospec=True)
    def test_does_not_download_with_remote_repo_hold_reboot(self, mock_dispatcher_state, mock_create_installer, mock_system, mock_upgrade_check, mock_install,
                                                            mock_downloader, mock_rebooter, mock_tool_options):
        mock_upgrade_check.return_value = 'abc', 'def'
        mock_dispatcher_state.return_value = True
        mock_create_installer.return_value = LinuxInstaller(self.mock_disp_callbacks,
                                                            TestFota._build_mock_repo(0), FW_CONF_PATH, FW_SCHEMA_LOCATION)
        assert TestFota._fota_instance_1
        TestFota._fota_instance_1.install()
        mock_upgrade_check.assert_called_once()
        mock_downloader.assert_called()
        mock_install.assert_called_once()
        time.sleep(0.12)
        mock_rebooter.assert_not_called()

    @patch('dispatcher.fota.fota.DirectoryRepo.delete')
    @patch('dispatcher.fota.upgrade_checker.UpgradeChecker.check')
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("", "", 0))
    def test_install_raises_exception(
            self, mock_pseudo_shell_runner, mock_upgrade_check, mock_delete):
        mock_upgrade_check.return_value = True
        assert TestFota._fota_instance
        TestFota._fota_instance.install()
        mock_upgrade_check.side_effect = FotaError('foo')
        mock_delete.assert_called_once()

    @staticmethod
    def _build_mock_repo(num_files=0):
        mem_repo = MemoryRepo("test")
        if num_files != 0:
            for i in range(0, num_files):
                mem_repo.add("test" + str(i + 1) + ".rpm", b"0123456789")
        return mem_repo

    @patch('dispatcher.fota.upgrade_checker.UpgradeChecker.check', side_effect=FotaError('dispatcher.fota error'))
    def test_check_raise_exception(self, mock_upgrade_check):
        assert TestFota._fota_instance
        with self.assertRaises(FotaError):
            TestFota._fota_instance.check()
