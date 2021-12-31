from unittest import TestCase

from inbm_lib.detect_os import detect_os
from unit.common.mock_resources import MockDispatcher
from mock import patch, mock_open
from dispatcher.sota.os_factory import *
from dispatcher.sota.os_updater import *
from dispatcher.sota.setup_helper import *
from dispatcher.sota.snapshot import *

sota_cmd = 'update'
log_to_file = 'N'


class TestOsFactory(TestCase):

    def setUp(self):
        self.mock_disp_obj = MockDispatcher.build_mock_dispatcher()

    def test_get_factory_ubuntu(self):
        assert type(SotaOsFactory(self.mock_disp_obj).get_os('Ubuntu')) is DebianBasedSotaOs

    def test_get_factory_yocto(self):
        assert type(SotaOsFactory(self.mock_disp_obj).get_os('YoctoX86_64')) is YoctoX86_64

    def test_get_factory_windows(self):
        assert type(SotaOsFactory(self.mock_disp_obj).get_os('Windows')) is Windows

    def test_raise_error_unsupported_OsFactory(self):
        factory = SotaOsFactory(self.mock_disp_obj)
        self.assertRaises(ValueError, factory.get_os, "MacOS")

    def test_create_ubuntu_upgrader_checker(self):
        assert type(SotaOsFactory(self.mock_disp_obj).get_os('Ubuntu').create_os_upgrader()) \
            is UbuntuUpgrader

    def test_create_yocto_upgrader_checker(self):
        assert type(SotaOsFactory(self.mock_disp_obj).get_os('YoctoX86_64').create_os_upgrader()) \
            is YoctoUpgrader

    def test_create_windows_upgrader_checker(self):
        assert type(SotaOsFactory(self.mock_disp_obj).get_os('Windows').create_os_upgrader()) \
            is WindowsUpgrader

    def test_create_ubuntu_snapshot_checker(self):
        assert type(SotaOsFactory(self.mock_disp_obj).get_os('Ubuntu').create_snapshotter('update', '1', False)) \
            is DebianBasedSnapshot

    def test_create_yocto_snapshot_checker(self):
        assert type(SotaOsFactory(self.mock_disp_obj).get_os('YoctoX86_64').create_snapshotter('update', '1', False)) \
            is YoctoSnapshot

    def test_create_windows_snapshot_checker(self):
        assert type(SotaOsFactory(self.mock_disp_obj).get_os('Windows').create_snapshotter('update', '1', False)) \
            is WindowsSnapshot

    def test_create_ubuntu_updater_checker(self):
        assert type(SotaOsFactory(self.mock_disp_obj).get_os('Ubuntu').create_os_updater()) \
            is DebianBasedUpdater

    def test_create_yocto_updater_checker(self):
        assert type(SotaOsFactory(self.mock_disp_obj).get_os('YoctoX86_64').create_os_updater()) \
            is YoctoX86_64Updater

    def test_create_ubuntu_setup_helper_checker(self):
        assert type(SotaOsFactory(self.mock_disp_obj).get_os('Ubuntu').create_setup_helper()) \
            is DebianBasedSetupHelper

    def test_create_yocto_setup_helper_checker(self):
        assert type(SotaOsFactory(self.mock_disp_obj).get_os('YoctoX86_64').create_setup_helper()) \
            is YoctoSetupHelper

    def test_create_windows_setup_helper_checker(self):
        assert type(SotaOsFactory(self.mock_disp_obj).get_os('Windows').create_setup_helper()) \
            is WindowsSetupHelper

    def test_create_ubuntu_downloader(self):
        assert type(SotaOsFactory(self.mock_disp_obj).get_os('Ubuntu').create_downloader()) \
            is DebianBasedDownloader

    def test_create_yocto_downloader(self):
        assert type(SotaOsFactory(self.mock_disp_obj).get_os('YoctoX86_64').create_downloader()) \
            is YoctoDownloader

    def test_create_windows_downloader(self):
        assert type(SotaOsFactory(self.mock_disp_obj).get_os('Windows').create_downloader()) \
            is WindowsDownloader

    @patch('platform.system')
    def test_verify_os_supported_success(self, mock_func):
        mock_func.return_value = 'Linux'
        ret = SotaOsFactory.verify_os_supported()
        self.assertEquals(ret, 'Linux')

    @patch('platform.system')
    def test_verify_os_supported_fail(self, mock_func):
        mock_func.return_value = 'MacOs'
        self.assertRaises(ValueError, SotaOsFactory.verify_os_supported)
