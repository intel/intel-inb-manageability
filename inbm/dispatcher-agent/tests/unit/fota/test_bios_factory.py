from unittest import TestCase

import mock
from ..common.mock_resources import *
from dispatcher.fota.bios_factory import *
from dispatcher.fota.bios_factory import extract_ext, LinuxToolFirmware, LinuxFileFirmware, BiosFactory
from mock import patch
from dispatcher.packagemanager.memory_repo import MemoryRepo


class TestBiosFactory(TestCase):

    def setUp(self) -> None:
        self._path = 'fakepath/'
        self._repo_name = 'fakerepo/'
        self._uri = mock_url.value.split('/')[-1]
        self.mock_dispatcher_broker = MockDispatcherBroker.build_mock_dispatcher_broker()
        self._dummy_dict = {'abc': 'abc'}
        self._arm_dict = {'bios_vendor': 'Intel Corp.', 'operating_system': 'linux',
                          'firmware_tool': 'tool', 'firmware_tool_args': '-a', 'firmware_file_type': 'xx'}
        self._ami_dict = {'bios_vendor': 'American Megatrends Inc.', 'operating_system': 'linux',
                          'firmware_tool': 'tool', 'firmware_tool_args': '-a', 'firmware_file_type': 'xx'}
        self._ami_dict_tool = {'bios_vendor': 'American Megatrends Inc.', 'operating_system': 'linux',
                               'firmware_tool': '/opt/afulnx/afulnx_64', 'firmware_tool_args': '-a',
                               'firmware_file_type': 'xx'}
        self._apl_dict = {'bios_vendor': 'Intel Corp.', 'operating_system': 'linux', 'firmware_tool': 'tool',
                          'firmware_tool_args': '-a', 'firmware_file_type': 'xx', 'firmware_dest_path': '/boot/efi/'}
        self._lake_dict = {'bios_vendor': 'Intel Corp.', 'operating_system': 'linux', 'firmware_tool': 'fwupdate',
                           'firmware_tool_args': '--apply', 'firmware_tool_check_args': '-a',
                           'firmware_file_type': 'xx', 'guid': 'true'}
        self._nuc_dict = {'bios_vendor': 'Intel Corp.', 'operating_system': 'linux',
                          'firmware_tool': 'UpdateBIOS.sh', 'firmware_file_type': 'bio'}

    def test_get_factory_linux_tool_type(self) -> None:
        assert type(BiosFactory.get_factory("test", self._arm_dict,
                                            self.mock_dispatcher_broker, MemoryRepo("test"))) \
            is LinuxToolFirmware

    def test_get_factory_linux_file_type(self) -> None:
        assert type(
            BiosFactory.get_factory("test", {'firmware_dest_path': 'abc'},
                                    self.mock_dispatcher_broker, MemoryRepo("test"))) is LinuxFileFirmware

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner().run')
    @patch('dispatcher.packagemanager.memory_repo.MemoryRepo.delete')
    @patch('dispatcher.fota.bios_factory.BiosFactory.unpack')
    def test_linux_bios_nuc_install_success(self, mock_unpack, mock_delete_pkg, mock_runner) -> None:
        mock_unpack.return_value = ('capsule.bio', None)
        mock_runner.return_value = ('cert', '', 0)
        try:
            LinuxToolFirmware(self.mock_dispatcher_broker, MemoryRepo(self._repo_name),
                              self._nuc_dict).install(self._uri, self._repo_name, None)
        except FotaError as e:
            self.fail("raised FotaError unexpectedly! --> {}".format(str(e)))

        mock_runner.assert_called()
        mock_delete_pkg.assert_has_calls([mock.call(self._uri)])

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner().run')
    @patch('dispatcher.packagemanager.memory_repo.MemoryRepo.delete')
    def test_linux_bios_nuc_install_fail_no_tool(self, mock_delete_pkg, mock_runner) -> None:
        mock_runner.return_value = ('cert', 'some error', 127)
        try:
            LinuxToolFirmware(self.mock_dispatcher_broker, MemoryRepo(self._repo_name),
                              self._nuc_dict).install(self._uri, self._repo_name, None)
        except FotaError as e:
            self.assertRaises(FotaError)
            self.assertEqual(
                str(e), "Firmware Update Aborted: Invalid File sent. error: some error")
        mock_runner.assert_called_once()
        self.assertEqual(mock_delete_pkg.call_count, 1)

    @patch('dispatcher.packagemanager.memory_repo.MemoryRepo.delete')
    @patch('dispatcher.fota.bios_factory.BiosFactory.unpack')
    def test_linux_bios_nuc_install_unpack_fail(self, mock_unpack, mock_delete_pkg) -> None:
        mock_unpack.side_effect = FotaError(
            "Firmware Update Aborted: Invalid File sent. error: some error")

        try:
            LinuxToolFirmware(self.mock_dispatcher_broker, MemoryRepo(self._repo_name),
                              self._nuc_dict).install(self._uri, self._repo_name, None)
        except FotaError as e:
            self.assertRaises(FotaError)
            self.assertEqual(
                str(e), "Firmware Update Aborted: Invalid File sent. error: some error")

        self.assertEqual(mock_delete_pkg.call_count, 1)

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner().run')
    @patch('dispatcher.packagemanager.memory_repo.MemoryRepo.delete')
    @patch('dispatcher.fota.bios_factory.BiosFactory.unpack')
    def test_linux_bios_nuc_install_apply_fail(self, mock_unpack, mock_delete_pkg, mock_runner) -> None:
        mock_runner.side_effect = [('cert', 'some error', 127)]
        mock_unpack.return_value = ('capsule.bio', None)

        try:
            LinuxToolFirmware(self.mock_dispatcher_broker, MemoryRepo(self._repo_name),
                              self._nuc_dict).install(self._uri, self._repo_name, None)
        except FotaError as e:
            self.assertRaises(FotaError)
            self.assertEqual(
                str(e), "Error: some error")
        self.assertEqual(mock_runner.call_count, 1)
        mock_delete_pkg.assert_has_calls([mock.call(self._uri)])

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner().run')
    @patch('dispatcher.fota.bios_factory.move_file')
    @patch('dispatcher.packagemanager.memory_repo.MemoryRepo.delete')
    @patch('dispatcher.fota.bios_factory.BiosFactory.unpack', return_value=("fw_file", "cert_file"))
    def test_linux_bios_apollo_lake_install_success(self, mock_unpack, mock_delete_pkg, mock_shutil, mock_runner) -> None:
        mock_runner.return_value = ('cert', '', 0)

        try:
            LinuxFileFirmware(self.mock_dispatcher_broker, MemoryRepo(self._repo_name), self._apl_dict).install(
                self._uri, self._repo_name, '/p /b')
        except FotaError as e:
            self.fail("raised FotaError unexpectedly! --> {}".format(str(e)))

        mock_shutil.assert_called_once()
        mock_delete_pkg.assert_has_calls([mock.call(self._uri)])

    @patch('dispatcher.fota.bios_factory.extract_guid', return_value="6B29FC40-CA47-1067-B31D-00DD010662D")
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner().run')
    @patch('dispatcher.fota.bios_factory.BiosFactory.unpack')
    @patch('dispatcher.fota.bios_factory.BiosFactory.delete_files')
    def test_linux_bios_elh_install_success(self, mock_delete, mock_unpack, mock_runner, mock_guid) -> None:
        mock_runner.return_value = ('', '', 0)
        mock_unpack.return_value = ('capsule.efi', None)

        try:
            BiosFactory.get_factory("Elkhart Lake Embedded Platform",
                                    self._lake_dict,
                                    self.mock_dispatcher_broker,
                                    MemoryRepo(self._repo_name)).install(self._uri,
                                                                         self._repo_name, None,
                                                                         "6B29FC40-CA47-1067-B31D-00DD010662D")
        except FotaError as e:
            self.fail("raised FotaError unexpectedly! --> {}".format(str(e)))

        mock_delete.assert_called_once()

    @patch('dispatcher.fota.bios_factory.extract_guid', return_value="6B29FC40-CA47-1067-B31D-00DD010662D")
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner().run')
    @patch('dispatcher.fota.bios_factory.BiosFactory.unpack')
    @patch('dispatcher.fota.bios_factory.BiosFactory.delete_files')
    def test_linux_bios_lake_install_success_guid(self, mock_delete, mock_unpack, mock_runner,
                                                  mock_get_guid) -> None:
        mock_runner.return_value = ('', '', 0)
        mock_unpack.return_value = ('capsule.efi', None)

        try:
            BiosFactory.get_factory("Elkhart Lake Embedded Platform", self._lake_dict,
                                    self.mock_dispatcher_broker,
                                    MemoryRepo(self._repo_name)).install(self._uri,
                                                                         self._repo_name,
                                                                         "6B29FC40-CA47-1067-B31D-00DD010662D")
        except FotaError as e:
            self.fail("raised FotaError unexpectedly! --> {}".format(str(e)))

        mock_delete.assert_called_once()
        mock_get_guid.assert_called_once()
        self.assertEqual(mock_runner.call_count, 2)

    @patch('dispatcher.fota.bios_factory.BiosFactory.delete_files')
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner().run')
    def test_linux_bios_lake_install_fail_not_supported(self, mock_runner, mock_delete) -> None:
        mock_runner.return_value = ('', 'firmware update not supported', 1)

        try:
            BiosFactory.get_factory(
                "Tiger Lake Client Platform",
                self._lake_dict,
                self.mock_dispatcher_broker,
                MemoryRepo(self._repo_name)).install(self._uri,
                                                     self._repo_name,
                                                     "6B29FC40-CA47-1067-B31D-00DD010662D")
        except FotaError as e:
            self.assertRaises(FotaError)
            self.assertEqual(
                str(e), "Firmware Update Aborted: Firmware tool: firmware update not supported")

    @patch('dispatcher.fota.bios_factory.extract_guid', return_value="6B29FC40-CA47-1067-B31D-00DD010662D")
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner().run')
    @patch('dispatcher.fota.bios_factory.BiosFactory.unpack')
    @patch('dispatcher.fota.bios_factory.BiosFactory.delete_files')
    def test_linux_bios_elh_install_fail(self, mock_delete, mock_unpack, mock_runner, mock_get_guid) -> None:
        mock_runner.side_effect = [('', '', 0), ('', '', 0), ('firmware update failed', '', 1)]
        mock_unpack.return_value = ('capsule.efi', None)

        try:
            BiosFactory.get_factory("Elkhart Lake Embedded Platform", self._lake_dict,
                                    self.mock_dispatcher_broker,
                                    MemoryRepo(self._repo_name)).install(self._uri,
                                                                         self._repo_name,
                                                                         "6B29FC40-CA47-1067-B31D-00DD010662D")
        except FotaError as e:
            self.assertRaises(FotaError)
            self.assertEqual(
                str(e), "Error: Firmware command failed")

        self.assertEqual(mock_runner.call_count, 2)
        mock_delete.assert_called_once()

    @patch('dispatcher.fota.bios_factory.BiosFactory.unpack')
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner().run')
    def test_linux_bios_aarch_install_fail_no_fwup(self, mock_run, mock_unpack) -> None:
        mock_run.return_value = ('', 'some message', 127)
        mock_unpack.return_value = ('capsule.bin', None)
        try:
            BiosFactory.get_factory("test", self._arm_dict,
                                    self.mock_dispatcher_broker, MemoryRepo(self._repo_name)).install("a", "b", "c")
        except FotaError as e:
            self.assertRaises(FotaError)
            self.assertEqual(str(e), "Error: some message")

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner().run')
    @patch('dispatcher.fota.bios_factory.BiosFactory.unpack')
    @patch('dispatcher.fota.bios_factory.BiosFactory.delete_files')
    def test_linux_bios_aarch_install_success(self, mock_delete, mock_unpack, mock_runner) -> None:
        mock_runner.side_effect = [('', '', 0), ('', '', 0)]
        mock_unpack.return_value = ('capsule.bin', None)

        try:
            BiosFactory.get_factory("tes", self._arm_dict,
                                    self.mock_dispatcher_broker, MemoryRepo(self._repo_name)).install(self._uri,
                                                                                                      self._repo_name)
        except FotaError as e:
            self.fail("raised FotaError unexpectedly! --> {}".format(str(e)))

        mock_delete.assert_called_once()

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner().run')
    @patch('dispatcher.fota.bios_factory.BiosFactory.unpack')
    @patch('dispatcher.fota.bios_factory.BiosFactory.delete_files')
    def test_linux_bios_aarch_install_fail_apply(self, mock_delete, mock_unpack, mock_runner) -> None:
        mock_runner.side_effect = [('', '', 0), ('', '', 127)]
        mock_unpack.return_value = ('capsule.bin', None)
        try:
            BiosFactory.get_factory("tes", self._arm_dict,
                                    self.mock_dispatcher_broker, MemoryRepo(self._repo_name)).install(self._uri,
                                                                                                      self._repo_name)
        except FotaError as e:
            self.assertEqual("Firmware Update Aborted, failed to run apply cmd: error: ", str(e))
        mock_delete.assert_called_once()

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner().run')
    @patch('dispatcher.fota.bios_factory.BiosFactory.unpack')
    @patch('dispatcher.fota.bios_factory.BiosFactory.delete_files')
    def test_linux_bios_aarch_install_fail_unpack(self, mock_delete, mock_unpack, mock_runner) -> None:
        mock_runner.side_effect = [('', '', 0), ('', '', 127)]
        mock_unpack.side_effect = FotaError(
            "Firmware Update Aborted: Invalid File sent. error: some error")

        try:
            BiosFactory.get_factory("tes", self._arm_dict,
                                    self.mock_dispatcher_broker, MemoryRepo(self._repo_name)).install(self._uri,
                                                                                                      self._repo_name)
        except FotaError as e:
            self.assertEqual(
                "Firmware Update Aborted: Invalid File sent. error: some error", str(e))

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner().run')
    @patch('dispatcher.fota.bios_factory.BiosFactory.delete_files')
    def test_linux_bios_apollo_lake_unpack_status_fails(self, mock_delete, mock_runner) -> None:
        mock_runner.return_value = ('', 'some error', 2)
        try:
            LinuxFileFirmware(self.mock_dispatcher_broker, MemoryRepo(self._repo_name), self._apl_dict).install(
                self._uri, self._repo_name, '/p /b')
        except FotaError as e:
            self.assertEqual(
                "Firmware Update Aborted: Invalid File sent. error: some error", str(e))
        mock_delete.assert_called_once()

    @patch('os.path.isfile')
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner().run')
    @patch('dispatcher.packagemanager.memory_repo.MemoryRepo.delete')
    @patch('dispatcher.fota.bios_factory.BiosFactory.unpack', return_value=("fw_file", "cert_file"))
    def test_linux_bios_ami_install_success(self, mock_unpack, mock_delete_pkg, mock_runner, mock_isfile) -> None:
        mock_isfile.return_value = True
        mock_runner.return_value = ('bios', '', 0)
        try:
            LinuxToolFirmware(self.mock_dispatcher_broker, MemoryRepo(self._repo_name),
                              self._ami_dict).install(self._uri, self._repo_name, '/p /b')
        except FotaError as e:
            self.fail("raised FotaError unexpectedly! --> {}".format(str(e)))
        mock_runner.assert_called()
        mock_delete_pkg.assert_has_calls([mock.call(self._uri)])

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner().run')
    @patch('os.path.isfile')
    @patch('dispatcher.fota.bios_factory.BiosFactory.unpack', return_value=("fw_file", "cert_file"))
    def test_linux_bios_ami_install_raises_no_tool(self, mock_unpack, mock_isfile, mock_runner) -> None:
        mock_isfile.return_value = False
        try:
            LinuxToolFirmware(self.mock_dispatcher_broker, MemoryRepo(self._repo_name),
                              self._ami_dict_tool).install(self._uri, self._repo_name, '/p /b')
        except FotaError as e:
            self.assertRaises(FotaError)
            self.assertEqual(
                str(e), "Firmware Update Aborted:  Firmware tool does not exist at /opt/afulnx/afulnx_64")
        mock_runner.assert_not_called()

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner().run')
    @patch('os.path.isfile')
    def test_linux_bios_ami_install_raises_on_run_fails(self, mock_isfile, mock_runner) -> None:
        mock_isfile.return_value = True
        mock_runner.return_value = ('', 'some error', 2)
        try:
            LinuxToolFirmware(self.mock_dispatcher_broker, MemoryRepo(self._repo_name),
                              self._ami_dict).install(self._uri, self._repo_name, '/p /b')
        except FotaError as e:
            self.assertRaises(FotaError)
            self.assertEqual(
                str(e), "Firmware Update Aborted: Invalid File sent. error: some error")

    def test_extract_package_extension(self) -> None:
        self.assertEqual(extract_ext("test.fv"), "package")

    def test_extract_cert_extension(self) -> None:
        self.assertEqual(extract_ext("test.cert"), "cert")

    def test_extract_pem_extension(self) -> None:
        self.assertEqual(extract_ext("test.pem"), "cert")

    def test_extract_crt_extension(self) -> None:
        self.assertEqual(extract_ext("test.pem"), "cert")

    def test_extract_bin_extension(self) -> None:
        self.assertEqual(extract_ext("bios.bin"), "bios")

    def test_extract_unsupported_extension(self) -> None:
        self.assertEqual(extract_ext("test.bla"), None)

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner().run')
    @patch('dispatcher.fota.bios_factory.extract_ext')
    @patch('dispatcher.fota.bios_factory.BiosFactory.delete_files')
    def test_linux_bios_aach64_non_tar_format(self, mock_delete, mock_ext, mock_runner) -> None:
        mock_runner.side_effect = [('', '', 0), ('', '', 0)]
        mock_ext.return_value = 'bios'
        BiosFactory.get_factory("tes", self._arm_dict,
                                self.mock_dispatcher_broker, MemoryRepo(self._repo_name)).install('abc.bin',
                                                                                                  self._repo_name)
        mock_ext.assert_called_once()

    @patch('dispatcher.fota.bios_factory.extract_guid', return_value="6B29FC40-CA47-1067-B31D-00DD010662D")
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner().run')
    @patch('dispatcher.fota.bios_factory.BiosFactory.unpack')
    @patch('dispatcher.fota.bios_factory.BiosFactory.delete_files')
    def test_linux_bios_tgl_install_fail(self, mock_delete, mock_unpack, mock_runner, mock_get_guid) -> None:
        mock_runner.side_effect = [('', '', 0), ('', '', 0), ('firmware update failed', '', 1)]
        mock_unpack.return_value = ('capsule.efi', None)
        try:
            BiosFactory.get_factory("Tiger Lake Client Platform", self._lake_dict,
                                    self.mock_dispatcher_broker,
                                    MemoryRepo(self._repo_name)).install(self._uri,
                                                                         self._repo_name,
                                                                         "6B29FC40-CA47-1067-B31D-00DD010662D")
        except FotaError as e:
            self.assertRaises(FotaError)
            self.assertEqual(
                str(e), "Error: Firmware command failed")

    @patch('dispatcher.fota.bios_factory.extract_guid', return_value="6B29FC40-CA47-1067-B31D-00DD010662D")
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner().run', return_value=('', '', 0))
    @patch('dispatcher.fota.bios_factory.BiosFactory.unpack', return_value=('capsule.efi', None))
    @patch('dispatcher.fota.bios_factory.BiosFactory.delete_files')
    def test_linux_bios_tgl_install_success(self, mock_delete, mock_unpack, mock_runner, mock_guid) -> None:
        try:
            BiosFactory.get_factory("Tiger Lake Client Platform", self._lake_dict,
                                    self.mock_dispatcher_broker, MemoryRepo(self._repo_name)) \
                .install(self._uri, self._repo_name, None, guid="6B29FC40-CA47-1067-B31D-00DD010662D")
        except FotaError as e:
            self.fail("raised FotaError unexpectedly! --> {}".format(str(e)))
        mock_delete.assert_called_once()

    @staticmethod
    def _build_mock_repo(num_files=0):
        mem_repo = MemoryRepo("test")
        if num_files != 0:
            for i in range(0, num_files):
                mem_repo.add("test" + str(i + 1) + ".rpm", b"0123456789")
        return mem_repo
