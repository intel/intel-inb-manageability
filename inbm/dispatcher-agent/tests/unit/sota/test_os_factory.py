from unittest import TestCase
from unittest.mock import patch

from unit.common.mock_resources import MockDispatcher, MockDispatcherBroker
from dispatcher.sota.os_factory import *
from dispatcher.sota.os_updater import *
from dispatcher.sota.setup_helper import *
from dispatcher.sota.snapshot import *

sota_cmd = 'update'
log_to_file = 'N'


class TestOsFactory(TestCase):

    def setUp(self) -> None:
        self.mock_disp_obj = MockDispatcher.build_mock_dispatcher()
        self.mock_disp_broker = MockDispatcherBroker.build_mock_dispatcher_broker()

    def test_get_factory_ubuntu(self) -> None:
        assert type(SotaOsFactory(self.mock_disp_broker, None, []
                                  ).get_os('Ubuntu')) is DebianBasedSotaOs

    def test_get_factory_yocto(self) -> None:
        assert type(SotaOsFactory(self.mock_disp_broker, None,
                    []).get_os('YoctoX86_64')) is YoctoX86_64

    def test_get_factory_windows(self) -> None:
        assert type(SotaOsFactory(self.mock_disp_broker).get_os('Windows')) is Windows

    def test_raise_error_unsupported_OsFactory(self) -> None:
        factory = SotaOsFactory(self.mock_disp_broker)
        with self.assertRaises(ValueError):
                factory.get_os("MacOS")

    def test_create_ubuntu_snapshot_checker(self) -> None:
        ubuntu_os = SotaOsFactory(self.mock_disp_broker).get_os('Ubuntu')
        snapshotter = ubuntu_os.create_snapshotter('update', '1', False, True)
        self.assertIsInstance(snapshotter, DebianBasedSnapshot)

    def test_create_yocto_snapshot_checker(self) -> None:
        yocto_os = SotaOsFactory(self.mock_disp_broker).get_os('YoctoX86_64')
        snapshotter = yocto_os.create_snapshotter('update', '1', False, True)
        self.assertIsInstance(snapshotter, YoctoSnapshot)

    def test_create_windows_snapshot_checker(self) -> None:
        windows_os = SotaOsFactory(self.mock_disp_broker).get_os('Windows')
        snapshotter = windows_os.create_snapshotter('update', '1', False, True)
        self.assertIsInstance(snapshotter, WindowsSnapshot)

    def test_create_ubuntu_updater_checker(self) -> None:
        updater = SotaOsFactory(self.mock_disp_broker, None, []).get_os('Ubuntu').create_os_updater()
        self.assertIsInstance(updater, DebianBasedUpdater)

    def test_create_yocto_updater_checker(self) -> None:
        assert type(SotaOsFactory(self.mock_disp_broker).get_os('YoctoX86_64').create_os_updater()) \
            is YoctoX86_64Updater

    def test_create_ubuntu_setup_helper_checker(self) -> None:
        assert type(SotaOsFactory(self.mock_disp_broker).get_os('Ubuntu').create_setup_helper()) \
            is DebianBasedSetupHelper

    def test_create_yocto_setup_helper_checker(self) -> None:
        assert type(SotaOsFactory(self.mock_disp_broker).get_os('YoctoX86_64').create_setup_helper()) \
            is YoctoSetupHelper

    def test_create_windows_setup_helper_checker(self) -> None:
        assert type(SotaOsFactory(self.mock_disp_broker).get_os('Windows').create_setup_helper()) \
            is WindowsSetupHelper

    def test_create_ubuntu_downloader(self) -> None:
        assert type(SotaOsFactory(self.mock_disp_broker).get_os('Ubuntu').create_downloader()) \
            is DebianBasedDownloader

    def test_create_yocto_downloader(self) -> None:
        assert type(SotaOsFactory(self.mock_disp_broker).get_os('YoctoX86_64').create_downloader()) \
            is YoctoDownloader

    def test_create_windows_downloader(self) -> None:
        assert type(SotaOsFactory(self.mock_disp_broker).get_os('Windows').create_downloader()) \
            is WindowsDownloader

    @patch('platform.system')
    def test_verify_os_supported_success(self, mock_func) -> None:
        mock_func.return_value = 'Linux'
        ret = SotaOsFactory.verify_os_supported()
        self.assertEqual(ret, 'Linux')

    @patch('platform.system')
    def test_verify_os_supported_fail(self, mock_func) -> None:
        mock_func.return_value = 'MacOs'
        self.assertRaises(ValueError, SotaOsFactory.verify_os_supported)
