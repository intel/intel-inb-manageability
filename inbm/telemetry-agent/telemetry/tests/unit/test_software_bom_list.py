from unittest import TestCase
import logging
from mock import patch, Mock
from telemetry.software_bom_list import *
from telemetry.software_bom_list import get_sw_bom_list, read_mender_file, publish_software_bom
from telemetry.constants import UNKNOWN
from inbm_lib.constants import SYSTEM_IS_YOCTO_PATH, MENDER_FILE_PATH

from future import standard_library
standard_library.install_aliases()


logger = logging.getLogger(__name__)


class TestSoftwareBomList(TestCase):

    @patch('inbm_lib.detect_os.platform.system', return_value='Linux')
    @patch('inbm_lib.detect_os.os.uname')
    @patch('inbm_lib.detect_os.os.path.exists', side_effect={SYSTEM_IS_YOCTO_PATH: False, MENDER_FILE_PATH: False}.get)
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run')
    @patch('inbm_lib.detect_os.get_lsb_release_name_host', return_value="Ubuntu")
    @patch('inbm_lib.detect_os.verify_os_supported', return_value='Linux')
    def test_get_sw_bom_list_pass(self, mock_os, mock_name, mock_runner, mock_path_exists, mock_uname, mock_system):
        mock_runner.return_value = ('xserver-xorg-video', "", 0)
        mock_uname.return_value = ('Linux', 'abc', '#1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20)',
                                   'Linux 4.19.0-6-amd64 x86_64', 'x86_64')
        self.assertEquals(get_sw_bom_list(), ['xserver-xorg-video'])

    @patch('inbm_lib.detect_os.platform.system', return_value='Linux')
    @patch('inbm_lib.detect_os.os.uname')
    @patch('inbm_lib.detect_os.os.path.exists', side_effect={SYSTEM_IS_YOCTO_PATH: False, MENDER_FILE_PATH: False}.get)
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run')
    @patch('inbm_lib.detect_os.get_lsb_release_name_host', return_value="Ubuntu")
    def test_get_sw_bom_list_fail(self, mock_name, mock_runner, mock_path_exists, mock_uname, mock_system):
        mock_runner.return_value = ("", "Error", -1)
        mock_uname.return_value = ('Linux', 'abc', '#1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20)',
                                   'Linux 4.19.0-6-amd64 x86_64', 'x86_64')
        try:
            get_sw_bom_list()
        except SoftwareBomError as e:
            self.assertEquals(['Error gathering software BOM information. Error'],
                              ['Error gathering software BOM information. ' + str(e)])

    @patch('inbm_lib.detect_os.platform.system', return_value='Linux')
    @patch('inbm_lib.detect_os.os.uname')
    @patch('inbm_lib.detect_os.os.path.exists', side_effect={SYSTEM_IS_YOCTO_PATH: True, MENDER_FILE_PATH: False}.get)
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run')
    @patch('inbm_lib.detect_os.get_lsb_release_name_host', return_value="YoctoX86_64")
    def test_get_sw_bom_list_fail2(self, mock_name, mock_runner, mock_path_exists, mock_uname, mock_system):
        mock_runner.return_value = ("", "Error", -1)
        mock_uname.return_value = ('Linux', 'abc', '#1 SMP PREEMPT Wed Mar 7 16:03:28 UTC 2021',
                                   '4.14.22-yocto', 'aarch64')
        try:
            get_sw_bom_list()
        except SoftwareBomError as e:
            self.assertEquals(['Error gathering software BOM information. Error'],
                              ['Error gathering software BOM information. ' + str(e)])

    @patch('inbm_lib.detect_os.platform.system', return_value='Linux')
    @patch('inbm_lib.detect_os.os.uname')
    @patch('inbm_lib.detect_os.os.path.exists', side_effect={SYSTEM_IS_YOCTO_PATH: True, MENDER_FILE_PATH: False}.get)
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run')
    @patch('inbm_lib.detect_os.get_lsb_release_name_host', return_value="YoctoX86_64")
    @patch('telemetry.software_bom_list.read_mender_file')
    def test_get_sw_bom_list_fail3(self, mock_read_file, mock_name, mock_runner, mock_path_exists, mock_uname, mock_system):
        mock_runner.return_value = ("", "", 0)
        mock_uname.return_value = ('Linux', 'abc', '#1 SMP PREEMPT Wed Mar 7 16:03:28 UTC 2021',
                                   '4.14.22-yocto', 'aarch64')
        mock_read_file.return_value = "Error on reading mender version file /etc/mender/artifact_info "
        self.assertEquals(get_sw_bom_list(), [
                          ' mender version: Error on reading mender version file /etc/mender/artifact_info '])

    @patch('inbm_lib.detect_os.platform.system', return_value='Linux')
    @patch('inbm_lib.detect_os.os.uname')
    @patch('inbm_lib.detect_os.os.path.exists', side_effect={SYSTEM_IS_YOCTO_PATH: True, MENDER_FILE_PATH: True}.get)
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run')
    @patch('inbm_lib.detect_os.get_lsb_release_name_host', return_value="YoctoX86_64")
    @patch('telemetry.software_bom_list.read_mender_file')
    def test_get_sw_bom_list_pass2(self, mock_read_file, mock_name, mock_runner, mock_path_exists, mock_uname, mock_system):
        mock_runner.return_value = ("", "", 0)
        mock_uname.return_value = ('Linux', 'abc', '#1 SMP PREEMPT Wed Mar 7 16:03:28 UTC 2021',
                                   '4.14.22-yocto', 'aarch64')
        mock_read_file.return_value = "artifact_name=Release-20200227142947"
        self.assertEquals(get_sw_bom_list(), [
                          ' mender version: artifact_name=Release-20200227142947'])

    def test_read_mender_file_fail(self):
        self.assertEquals(read_mender_file('/etc/test_info', UNKNOWN), UNKNOWN)

    @patch('inbm_lib.detect_os.platform.system', return_value='Linux')
    @patch('inbm_lib.detect_os.os.uname')
    @patch('inbm_lib.detect_os.os.path.exists', side_effect={SYSTEM_IS_YOCTO_PATH: True, MENDER_FILE_PATH: False}.get)
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run')
    @patch('inbm_lib.detect_os.get_lsb_release_name_host', return_value="YoctoARM")
    def test_get_sw_bom_list_fail4(self, mock_name, mock_runner, mock_path_exists, mock_uname, mock_system):
        mock_runner.return_value = ("", "", 0)
        mock_uname.return_value = ('Linux', 'abc', '#1 SMP PREEMPT Wed Mar 7 16:03:28 UTC 2021',
                                   '4.14.22-yocto', 'aarch64')
        self.assertEquals(get_sw_bom_list(), [' mender version: Unknown'])

    @patch('telemetry.telemetry_handling.publish_dynamic_telemetry')
    @patch('telemetry.software_bom_list.get_sw_bom_list', return_value=[])
    def test_publish_sw_bom_list_empty(self, mock_sw_bom, mock_publish):
        publish_software_bom(Mock(), False)
        assert mock_publish.call_count == 1
