import os
from unittest import TestCase

from ..common.mock_resources import mock_url, MockDispatcherBroker
from dispatcher.fota.installer import Installer, LinuxInstaller
from mock import patch
from dispatcher.packagemanager.memory_repo import MemoryRepo
from dispatcher.fota.fota_error import FotaError

FW_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                  '..', '..', '..', 'fpm-template', 'usr', 'share',
                                  'dispatcher-agent', 'firmware_tool_config_schema.xsd')
FW_CONF_PATH = os.path.join(os.path.dirname(__file__),
                            '..', '..', '..', 'fpm-template', 'etc',
                                  'firmware_tool_info.conf')


class TestInstaller(TestCase):

    def setUp(self) -> None:
        self.mock_disp_broker_obj = MockDispatcherBroker.build_mock_dispatcher_broker()

    @patch('dispatcher.fota.bios_factory.LinuxFileFirmware.install')
    def test_linux_install_successful(self, mock_install) -> None:
        mock_install.return_value = True
        uri = mock_url.value.split('/')[-1]
        try:
            LinuxInstaller(self.mock_disp_broker_obj, TestInstaller._build_mock_repo(), FW_CONF_PATH, FW_SCHEMA_LOCATION).install(guid=None,
                                                                                                                                  tool_options=None,
                                                                                                                                  pkg_filename=uri,
                                                                                                                                  signature="testsig",
                                                                                                                                  hash_algorithm=1,
                                                                                                                                  bios_vendor="CRB",
                                                                                                                                  platform_product="Broxton P")
        except FotaError:
            self.fail("raised FotaError unexpectedly!")

    @patch('dispatcher.fota.bios_factory.LinuxToolFirmware.install')
    def test_linux_ami_install_successful(self, mock_install) -> None:
        mock_install.return_value = True
        uri = mock_url.value.split('/')[-1]
        try:
            LinuxInstaller(self.mock_disp_broker_obj,
                           TestInstaller._build_mock_repo(), FW_CONF_PATH, FW_SCHEMA_LOCATION).install(guid=None,
                                                                                                       tool_options='/b /p',
                                                                                                       pkg_filename=uri,
                                                                                                       signature="testsig",
                                                                                                       hash_algorithm=1,
                                                                                                       bios_vendor="American Megatrends Inc.",
                                                                                                       platform_product="Default string")
        except FotaError as e:
            self.fail(f"raised FotaError unexpectedly! {e}")

    @patch('dispatcher.fota.bios_factory.LinuxToolFirmware.install')
    def test_linux_elkhart_install_successful(self, mock_install) -> None:
        mock_install.return_value = True
        uri = mock_url.value.split('/')[-1]
        try:
            LinuxInstaller(self.mock_disp_broker_obj, TestInstaller._build_mock_repo(), FW_CONF_PATH, FW_SCHEMA_LOCATION).install(guid=None,
                                                                                                                                  tool_options=None,
                                                                                                                                  pkg_filename=uri,
                                                                                                                                  signature="testsig",
                                                                                                                                  hash_algorithm=1,
                                                                                                                                  bios_vendor="Intel Corp.",
                                                                                                                                  platform_product="Elkhart Lake Embedded Platform")
        except FotaError as e:
            self.fail(f"raised FotaError unexpectedly! {e}")

    @patch('dispatcher.fota.bios_factory.LinuxToolFirmware.install')
    def test_linux_elkhart_install_fail_due_to_toolOptions(self, mock_install) -> None:
        mock_install.return_value = True
        uri = mock_url.value.split('/')[-1]
        try:
            LinuxInstaller(self.mock_disp_broker_obj, TestInstaller._build_mock_repo(), FW_CONF_PATH, FW_SCHEMA_LOCATION).install(guid=None,
                                                                                                                                  tool_options='123',
                                                                                                                                  pkg_filename=uri,
                                                                                                                                  signature="testsig",
                                                                                                                                  hash_algorithm=1,
                                                                                                                                  bios_vendor="Intel Corp.",
                                                                                                                                  platform_product="Elkhart Lake Embedded Platform")
        except FotaError as e:
            self.assertRaises(FotaError)
            self.assertEqual(
                str(e), "Tool options are not supported by the platform. Please check the firmware configuration.")

    @patch('dispatcher.fota.bios_factory.LinuxToolFirmware.install')
    def test_linux_elkhart_install_fail(self, mock_install) -> None:
        mock_install.return_value = True
        uri = mock_url.value.split('/')[-1]
        try:
            LinuxInstaller(self.mock_disp_broker_obj, TestInstaller._build_mock_repo(), FW_CONF_PATH, FW_SCHEMA_LOCATION).install(guid=None,
                                                                                                                                  tool_options='1234',
                                                                                                                                  pkg_filename=uri,
                                                                                                                                  signature="testsig",
                                                                                                                                  hash_algorithm=1,
                                                                                                                                  bios_vendor="Intel Corp.",
                                                                                                                                  platform_product="Dummy Platform")
        except FotaError as e:
            self.assertRaises(FotaError)
            self.assertEqual(str(e), "The current platform is unsupported - Dummy Platform")

    @patch('dispatcher.fota.bios_factory.LinuxToolFirmware.install')
    def test_linux_check_install_params(self, mock_install) -> None:
        mock_install.return_value = True
        try:
            val = LinuxInstaller(self.mock_disp_broker_obj, TestInstaller._build_mock_repo(
            ), FW_CONF_PATH, FW_SCHEMA_LOCATION).get_product_params(platform_product="Elkhart Lake Embedded Platform")
            self.assertEqual(val, {'bios_vendor': 'Intel Corporation', 'operating_system': 'linux', 'firmware_tool': 'fwupdate', 'firmware_tool_args': '--apply',
                                   'firmware_tool_check_args': '-s', 'firmware_file_type': 'xx', 'guid': 'true', 'firmware_product': 'Elkhart Lake Embedded Platform'})
        except FotaError as e:
            self.fail(f"raised FotaError unexpectedly! {e}")

    @patch('dispatcher.fota.bios_factory.LinuxToolFirmware.install')
    def test_linux_bios_ami_install_no_options(self, mock_install) -> None:
        mock_install.return_value = True
        uri = mock_url.value.split('/')[-1]
        try:
            LinuxInstaller(self.mock_disp_broker_obj, TestInstaller._build_mock_repo(), FW_CONF_PATH, FW_SCHEMA_LOCATION).install(guid=None,
                                                                                                                                  tool_options=None,
                                                                                                                                  pkg_filename=uri,
                                                                                                                                  signature="testsig",
                                                                                                                                  hash_algorithm=1,
                                                                                                                                  bios_vendor="American Megatrends Inc.",
                                                                                                                                  platform_product="Default string")
        except FotaError as e:
            self.assertRaises(FotaError)
            self.assertEqual(str(
                e), "Tool options are mandatory for the platform's firmware update tool, please check firmware documentation for the parameters.")

    @staticmethod
    def _build_mock_repo(num_files=0):
        mem_repo = MemoryRepo("test")
        if num_files != 0:
            for i in range(0, num_files):
                mem_repo.add("test" + str(i + 1) + ".rpm", b"0123456789")
        return mem_repo
