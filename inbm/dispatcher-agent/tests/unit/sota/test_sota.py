import threading

import testtools
import os
import tempfile
from ..common.mock_resources import *
from ddt import data, ddt, unpack
from unittest.mock import patch, mock_open
from typing import Dict, List

from dispatcher.packagemanager.memory_repo import MemoryRepo
from dispatcher.sota.command_list import CommandList
from dispatcher.sota.os_factory import SotaError, SotaOsFactory
from dispatcher.sota.sota import SOTA, GranularLogHandler
from dispatcher.sota.sota import SOTAUtil
from dispatcher.sota.constants import *
from inbm_lib.xmlhandler import XmlHandler
from inbm_lib.constants import OTA_SUCCESS, OTA_PENDING, FAIL, ROLLBACK, GRANULAR_LOG_FILE


TEST_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                    '../../../fpm-template/usr/share/dispatcher-agent/'
                                    'manifest_schema.xsd')

class MockInstaller:

    def __init__(self, size_value) -> None:
        self._size_value = size_value

    def get_estimated_size(self):
        return self._size_value


@ddt
class TestSota(testtools.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.mock_disp_broker = MockDispatcherBroker.build_mock_dispatcher_broker()
        parsed = XmlHandler(fake_sota_success, is_file=False, schema_location=TEST_SCHEMA_LOCATION)
        cls.resource = parsed.get_children('ota/type/sota')
        parsed_manifest = {'resource': cls.resource,
                           'signature': None, 'hash_algorithm': None,
                           'uri': mock_url.value, 'repo': TestSota._build_mock_repo(0), 'username': username,
                           'password': password, 'sota_mode': 'full', 'deviceReboot': 'yes', 'package_list': ''}
        cls.sota_instance = SOTA(parsed_manifest, 'remote',
                                 cls.mock_disp_broker,
                                 UpdateLogger("SOTA", "metadata"),
                                 None,
                                 install_check_service=MockInstallCheckService(),
                                 cancel_event=threading.Event(),
                                 snapshot=1)
        cls.sota_local_instance = SOTA(parsed_manifest, 'local',
                                       cls.mock_disp_broker,
                                       UpdateLogger("SOTA", "metadata"),
                                       None,
                                       install_check_service=MockInstallCheckService(),
                                       cancel_event=threading.Event(),
                                       snapshot=1)
        cls.sota_util_instance = SOTAUtil()

    @data(0, 510000, 6500000)
    def test_check_diagnostic_disk(self, size_value) -> None:
        try:
            TestSota.sota_util_instance.check_diagnostic_disk(size_value,
                                                              MockDispatcherBroker.build_mock_dispatcher_broker(),
                                                              install_check_service=MockInstallCheckService())
        except SotaError:
            self.assertfail("SotaError raised when not expected.")

    @unpack
    @patch('dispatcher.sota.command_handler.open')
    @data(("update", "Y"), ("update", "N"))
    @patch('dispatcher.sota.sota.SOTAUtil.check_diagnostic_disk')
    @patch('dispatcher.sota.os_updater.DebianBasedUpdater.update_remote_source',
           return_value=CommandList(['abc']).cmd_list)
    @patch('dispatcher.sota.sota.open')
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run_with_log_path',
           side_effect=[('out', 'err', 0, '/home/fakepath/'), ('out', 'err', 0, '/home/fakepath/'),
                        ('out', 'err', 0, '/home/fakepath/'), ('out',
                                                               'err', 0, None),
                        ('out', 'err', 0, None),
                        ('out', 'err', 0, None), ('out', 'err', 0, '/home/fakepath/'),
                        ('out', 'err', 0, '/home/fakepath/'),
                        ('out', 'err', 0, '/home/fakepath/'),
                        ('out', 'err', 0, '/home/fakepath/')])
    def test_run_commands(self, sota_cmd, sota_logto,
                          mock_run, mock_shell_open, mock_update, mock_open_file, _) -> None:
        TestSota.sota_instance.sota_cmd = sota_cmd
        TestSota.sota_instance.log_to_file = sota_logto
        TestSota.sota_instance.factory = SotaOsFactory(
            TestSota.mock_disp_broker, None, []).get_os('Ubuntu')
        TestSota.sota_instance.calculate_and_execute_sota_upgrade(SOTA_CACHE)

        if sota_cmd != "update":
            self.force_failure("only update is valid")

        mock_open_file.assert_called_once()
        mock_update.assert_called_once()
        mock_shell_open.assert_not_called()

    @unpack
    @data(("update", "Y"))
    @patch('dispatcher.sota.sota.SOTAUtil.check_diagnostic_disk',
           side_effect=SotaError('Disk Space not sufficient for update'))
    @patch('dispatcher.sota.os_updater.DebianBasedUpdater.update_remote_source')
    def test_run_commands_raises(self, sota_cmd, sota_logto,
                                 mock_update, _) -> None:
        TestSota.sota_instance.sota_cmd = sota_cmd
        TestSota.sota_instance.logtofile = sota_logto
        TestSota.sota_instance.factory = SotaOsFactory(
            TestSota.mock_disp_broker, None, []).get_os('Ubuntu')
        self.assertRaises(BaseException, TestSota.sota_instance.calculate_and_execute_sota_upgrade)
        mock_update.assert_not_called()

    @patch("inbm_lib.detect_os.detect_os")
    @patch("dispatcher.sota.sota.print_execution_summary")
    @patch("dispatcher.sota.snapshot.DebianBasedSnapshot._rollback_and_delete_snap")
    @patch("dispatcher.sota.rebooter.LinuxRebooter.reboot")
    def test_run_raises(self, mock_reboot, mock_rollback_and_delete_snap, mock_print,
                        mock_detect_os) -> None:
        mock_detect_os.return_value = 'Ubuntu'
        parsed_manifest = {'log_to_file': 'Y', 'sota_cmd': 'update',
                           'sota_repos': None,
                           'uri': 'https://www.example.com/', 'signature': None, 'hash_algorithm': None,
                           'username': None, 'password': None, 'release_date': None, 'sota_mode': 'full',
                           'deviceReboot': "no", 'package_list': ''}
        mock_disp_broker = MockDispatcherBroker.build_mock_dispatcher_broker()
        try:
            sota_instance = SOTA(parsed_manifest, 'remote',
                                 mock_disp_broker,
                                 UpdateLogger("SOTA", "metadata"), None,
                                 MockInstallCheckService(), cancel_event=threading.Event(),
                                 snapshot=1)
            sota_instance.execute(proceed_without_rollback=False, skip_sleeps=True)
            mock_print.assert_called_once()
            if TestSota.sota_instance.proceed_without_rollback:
                mock_rollback_and_delete_snap.assert_called_once()
            mock_reboot.assert_called_once()
        except SotaError as e:
            assert (str(e) == "SOTA cache directory cannot be created" or
                    str(e) == "Final result in SOTA execution: SOTA fail")

    @patch("inbm_lib.detect_os.detect_os")
    @patch("dispatcher.sota.sota.print_execution_summary")
    @patch("dispatcher.sota.snapshot.DebianBasedSnapshot._rollback_and_delete_snap")
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=('200', "", 0))
    def test_run_pass(self, mock_run, mock_rollback_and_delete_snap, mock_print,
                      mock_detect_os) -> None:
        mock_detect_os.return_value = 'Ubuntu'
        parsed_manifest = {'log_to_file': 'Y', 'sota_cmd': 'update',
                           'sota_repos': None,
                           'uri': 'https://www.example.com/', 'signature': None, 'hash_algorithm': None,
                           'username': None, 'password': None, 'release_date': None, 'sota_mode': 'download-only',
                           'deviceReboot': "no"}
        mock_disp_broker = MockDispatcherBroker.build_mock_dispatcher_broker()
        try:
            sota_instance = SOTA(parsed_manifest, 'remote', mock_disp_broker,
                                 UpdateLogger("SOTA", "metadata"), None, MockInstallCheckService(),
                                 cancel_event=threading.Event(),snapshot=1)
            sota_instance.execute(proceed_without_rollback=False, skip_sleeps=True)
            mock_print.assert_called_once()
            if TestSota.sota_instance.proceed_without_rollback:
                mock_rollback_and_delete_snap.assert_called_once()
            mock_run.assert_called_once()
        except SotaError as e:
            assert (str(e) == "SOTA cache directory cannot be created" or
                    str(e) == "Invalid OS or unable to detect OS for SOTA: Unsupported OS type or unable to detect OS")

    @patch("dispatcher.sota.downloader.Downloader.is_valid_release_date")
    @patch("dispatcher.sota.snapshot.YoctoSnapshot.recover")
    @patch("dispatcher.sota.setup_helper.YoctoSetupHelper.pre_processing")
    @patch("dispatcher.sota.setup_helper.YoctoSetupHelper")
    def test_no_reboot_on_fail(self, mock_create_helper, mock_helper, mock_recover, mock_release_date) -> None:
        mock_release_date.return_value = False
        mock_helper.return_value = True
        TestSota.sota_instance.factory = SotaOsFactory(
            TestSota.mock_disp_broker,
            None, []).get_os('YoctoX86_64')
        try:
            TestSota.sota_instance.execute_from_manifest(setup_helper=mock_create_helper,
                                                         sota_cache_repo=MemoryRepo("test"), snapshotter=None,
                                                         rebooter=None,
                                                         time_to_wait_before_reboot=1, release_date="2008-11-11")
        except SotaError as e:
            self.assertEqual(str(e), 'Final result in SOTA execution: SOTA fail')
            mock_recover.assert_not_called()

    @unpack
    @data(("upgrade", "Y"))
    @patch("dispatcher.sota.downloader.Downloader.is_valid_release_date")
    @patch("dispatcher.sota.setup_helper.YoctoSetupHelper.pre_processing")
    @patch("dispatcher.sota.setup_helper.YoctoSetupHelper")
    @patch('dispatcher.sota.sota.SOTAUtil.check_diagnostic_disk',
           side_effect=SotaError('Disk Space not sufficient for update'))
    @patch('dispatcher.sota.sota.SOTA._clean_local_repo_file', side_effect=SotaError("error"))
    def test_local_file_cleanup_called(self, sota_cmd, sota_logto,
                                       mock_cleanup, mock_diagnostic_check, mock_create_helper, mock_helper,
                                       mock_release_date) -> None:
        mock_release_date.return_value = False
        mock_helper.return_value = True
        TestSota.sota_local_instance.sota_cmd = sota_cmd
        TestSota.sota_local_instance.logtofile = sota_logto
        TestSota.sota_local_instance.factory = SotaOsFactory(
            TestSota.mock_disp_broker, None, []).get_os('YoctoX86_64')
        try:
            TestSota.sota_instance.execute_from_manifest(setup_helper=mock_create_helper,
                                                         sota_cache_repo=MemoryRepo("test"), snapshotter=None,
                                                         rebooter=None,
                                                         time_to_wait_before_reboot=1, release_date="2008-11-11")
            mock_cleanup.assert_called_once()
        except SotaError as e:
            self.assertEqual(str(e), 'Final result in SOTA execution: SOTA fail')

    def tearDown(self) -> None:
        super().tearDown()
        TestSota.sota_instance.log_to_file = None
        TestSota.sota_instance.sota_cmd = None
        TestSota.sota_instance.factory = None
        TestSota.sota_instance.installer = None

    @staticmethod
    def _build_mock_repo(num_files=0):
        mem_repo = MemoryRepo("test")
        if num_files != 0:
            for i in range(0, num_files):
                mem_repo.add("test" + str(i + 1) + ".rpm", b"0123456789")
        return mem_repo

    @patch("dispatcher.sota.sota.detect_os")
    def test_check_do_not_raise_exception(self, mock_detect_os) -> None:
        parsed_manifest = {'release_date': "1970-01-01"}
        mock_detect_os.return_value = 'Ubuntu'
        TestSota.sota_instance._parsed_manifest = parsed_manifest
        try:
            TestSota.sota_instance.check()
        except SotaError:
            self.fail("Sota check() method raised exception unexpectedly")

    def test_is_ota_no_update_available_return_true(self) -> None:
        cmd = "apt-get -yq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold --with-new-pkgs upgrade"
        cmd_list = CommandList([cmd]).cmd_list
        cmd_list[0].out = """
Reading package lists...
Building dependency tree...
Reading state information...
Calculating upgrade...
The following packages were automatically installed and are no longer required:
  gir1.2-goa-1.0 libfwupdplugin1 libxmlb1
Use 'sudo apt autoremove' to remove them.
0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
        """
        self.assertTrue(TestSota.sota_instance._is_ota_no_update_available(cmd_list))

    def test_is_ota_no_update_available_return_false(self) -> None:
        cmd = "apt-get -yq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold --with-new-pkgs upgrade"
        cmd_list = CommandList([cmd]).cmd_list
        cmd_list[0].out = """
Reading package lists...
Building dependency tree...
Reading state information...
Calculating upgrade...
The following packages were automatically installed and are no longer required:
  gir1.2-goa-1.0 libfwupdplugin1 libxmlb1
Use 'sudo apt autoremove' to remove them.
The following packages will be upgraded:
  openvpn
Preconfiguring packages ...
1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
Need to get 0 B/483 kB of archives.
After this operation, 8,192 B of additional disk space will be used.
(Reading database ... 198685 files and directories currently installed.)
Preparing to unpack .../openvpn_2.4.12-0ubuntu0.20.04.2_amd64.deb ...
Unpacking openvpn (2.4.12-0ubuntu0.20.04.2) over (2.4.7-1ubuntu2) ...
Setting up openvpn (2.4.12-0ubuntu0.20.04.2) ...
 * Restarting virtual private network daemon.                            [ OK ]
Processing triggers for man-db (2.9.1-1) ...
Processing triggers for systemd (245.4-4ubuntu3.23) ...
        """
        self.assertFalse(TestSota.sota_instance._is_ota_no_update_available(cmd_list))
