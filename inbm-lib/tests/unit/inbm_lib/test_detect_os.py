from unittest import TestCase

from inbm_lib.constants import SYSTEM_IS_YOCTO_PATH, MENDER_FILE_PATH
from inbm_lib.detect_os import detect_os
from unittest.mock import patch, mock_open, Mock

sota_cmd = 'update'
log_to_file = 'N'


class TestDetectOs(TestCase):
    @patch('inbm_lib.detect_os.platform.system', return_value='Linux')
    @patch('inbm_lib.detect_os.os.uname')
    @patch('inbm_lib.detect_os.os.path.exists', side_effect={SYSTEM_IS_YOCTO_PATH: True, MENDER_FILE_PATH: True}.get)
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run')
    def test_get_os_success(self, mock_runner: Mock, mock_path_exists: Mock, mock_uname: Mock, mock_system: Mock) -> None:
        with patch('inbm_lib.detect_os.open', mock_open(read_data='bible'), create=True) as m1:
            mock_uname.return_value = ('Linux', 'abc', '4.14.22-yocto',
                                       '#1 SMP PREEMPT Wed Mar 7 16:03:28 UTC 2018', 'aarch64')
            mock_runner.return_value = ("InvalidOS", "", 0)

            ret = detect_os()
            self.assertEqual(ret, 'YoctoARM')

    @patch('inbm_lib.detect_os.platform.system', return_value='Linux')
    @patch('inbm_lib.detect_os.os.uname')
    @patch('inbm_lib.detect_os.os.path.exists', side_effect={SYSTEM_IS_YOCTO_PATH: True, MENDER_FILE_PATH: True}.get)
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run')
    def test_get_os_fail(self, mock_runner: Mock, mock_path_exists: Mock, mock_uname: Mock, mock_system: Mock) -> None:
        with patch('inbm_lib.detect_os.open', mock_open(read_data='bible'), create=True) as m1:
            mock_uname.return_value = ('Linux', 'abc', '4.14.22-Fedora',
                                       '#1 SMP PREEMPT Wed Mar 7 16:03:28 UTC 2018', 'badarch')
            mock_runner.return_value = ("InvalidOS", "", 0)

            with self.assertRaisesRegex(ValueError, "Unsupported architecture: badarch"):
                detect_os()

    @patch('inbm_lib.detect_os.platform.system', return_value='Linux')
    @patch('inbm_lib.detect_os.os.uname')
    @patch('inbm_lib.detect_os.os.path.exists', side_effect={SYSTEM_IS_YOCTO_PATH: True, MENDER_FILE_PATH: False}.get)
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run')
    def test_get_os_fail_no_mender(self, mock_runner: Mock, mock_path_exists: Mock, mock_uname: Mock, mock_system: Mock) -> None:
        with patch('inbm_lib.detect_os.open', mock_open(read_data='bible'), create=True) as m1:
            mock_uname.return_value = ('Linux', 'abc', '4.14.22-Fedora',
                                       '#1 SMP PREEMPT Wed Mar 7 16:03:28 UTC 2018', 'aarch64')
            mock_runner.return_value = ("InvalidOS", "", 0)

            with self.assertRaisesRegex(ValueError, "Yocto detected but unable to find Mender"):
                detect_os()

    @patch('inbm_lib.detect_os.platform.system', return_value='Linux')
    @patch('inbm_lib.detect_os.os.uname')
    @patch('inbm_lib.detect_os.os.path.exists', side_effect={SYSTEM_IS_YOCTO_PATH: False, MENDER_FILE_PATH: False}.get)
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run')
    def test_get_os_fail_no_yocto_no_mender(self, mock_runner: Mock, mock_path_exists: Mock, mock_uname: Mock, mock_system: Mock) -> None:
        with patch('inbm_lib.detect_os.open', mock_open(read_data='bible'), create=True) as m1:
            mock_uname.return_value = ('Linux', 'abc', '4.14.22-Fedora',
                                       '#1 SMP PREEMPT Wed Mar 7 16:03:28 UTC 2018', 'invalid_arch')
            mock_runner.return_value = ("InvalidOS", "", 0)

            with self.assertRaisesRegex(ValueError, "Unsupported OS type or unable to detect OS"):
                detect_os()
