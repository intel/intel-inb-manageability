import mock
from unittest import TestCase

from dispatcher.device_manager.device_manager import (
    get_device_manager, LinuxDeviceManager, WindowsDeviceManager
)
from dispatcher.device_manager.constants import (
    SUCCESS_RESTART, SUCCESS_SHUTDOWN, SUCCESS_DECOMMISSION
)


class TestDeviceManager(TestCase):

    def setUp(self) -> None:
        self.mock_linux_dm = LinuxDeviceManager()
        self.mock_win_dm = WindowsDeviceManager()

    @mock.patch('dispatcher.device_manager.device_manager.sys')
    def test_get_device_manager_linux_succeeds(self, mock_sys) -> None:
        mock_sys.platform.startswith = lambda x: x == "linux"
        dm = get_device_manager()
        assert isinstance(dm, LinuxDeviceManager)

    @mock.patch('dispatcher.device_manager.device_manager.sys')
    def test_get_device_manager_windows_succeeds(self, mock_sys) -> None:
        mock_sys.platform.startswith = lambda x: x == "win32"
        dm = get_device_manager()
        assert isinstance(dm, WindowsDeviceManager)

    @mock.patch('dispatcher.device_manager.device_manager.sys')
    def test_get_device_manager_invalid_fails(self, mock_sys) -> None:
        mock_sys.platform.startswith = lambda x: x == "darwin"
        failed = False
        try:
            get_device_manager()
        except NotImplementedError:
            failed = True
        assert failed

    @mock.patch('inbm_common_lib.shell_runner.PseudoShellRunner().run', return_value=("", "", 0))
    def test_linux_restart(self, mock_run) -> None:
        result = self.mock_linux_dm.restart()
        assert result == SUCCESS_RESTART

    @mock.patch('inbm_common_lib.shell_runner.PseudoShellRunner().run', return_value=("", "", 0))
    def test_linux_shutdown(self, mock_run) -> None:
        result = self.mock_linux_dm.shutdown()
        assert result == SUCCESS_SHUTDOWN

    @mock.patch('os.remove')
    @mock.patch('inbm_common_lib.shell_runner.PseudoShellRunner().run', return_value=("", "", 0))
    def test_linux_decommission(self, mock_run, mock_os_remove) -> None:
        result = self.mock_linux_dm.decommission()
        assert result == SUCCESS_DECOMMISSION

    @mock.patch('inbm_common_lib.shell_runner.PseudoShellRunner().run', return_value=("", "", 0))
    def test_win_restart(self, mock_run) -> None:
        result = self.mock_win_dm.restart()
        assert result == SUCCESS_RESTART

    @mock.patch('inbm_common_lib.shell_runner.PseudoShellRunner().run', return_value=("", "", 0))
    def test_win_shutdown(self, mock_run) -> None:
        result = self.mock_win_dm.shutdown()
        assert result == SUCCESS_SHUTDOWN
