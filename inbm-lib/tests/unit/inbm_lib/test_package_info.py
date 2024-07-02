from unittest import TestCase
from inbm_lib.package_info import get_package_start_date, extract_package_names_and_versions, check_package_status, \
    check_package_version
from inbm_lib.constants import PACKAGE_SUCCESS, PACKAGE_PENDING, PACKAGE_FAIL, PACKAGE_UNKNOWN

from unittest.mock import patch, Mock


class TestPackageInfo(TestCase):

    def test_get_package_start_date_pass(self) -> None:
        text = """
        Start-Date: 2024-07-03  02:56:24
        Commandline: apt-get -yq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold --with-new-pkgs upgrade
        Requested-By: lab_phe3223 (1002)
        Upgrade: openvpn:amd64 (2.4.7-1ubuntu2, 2.4.12-0ubuntu0.20.04.2)
        End-Date: 2024-07-03  02:56:25
        """
        self.assertEqual("2024-07-03T02:56:24", get_package_start_date(text))

    def test_get_package_start_date_return_empty(self) -> None:
        text = """
        Commandline: apt-get -yq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold --with-new-pkgs upgrade
        Requested-By: lab_phe3223 (1002)
        Upgrade: openvpn:amd64 (2.4.7-1ubuntu2, 2.4.12-0ubuntu0.20.04.2)
        """
        self.assertEqual("", get_package_start_date(text))

    def test_extract_package_names_and_versions_pass(self) -> None:
        text = """
        Start-Date: 2024-07-02  17:41:28
        Commandline: /bin/apt-get -yq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold --with-new-pkgs upgrade
        Upgrade: libcdio18:amd64 (2.0.0-2, 2.0.0-2ubuntu0.2), docker-ce-rootless-extras:amd64 (5:27.0.1-1~ubuntu.20.04~focal, 5:27.0.2-1~ubuntu.20.04~focal)
        End-Date: 2024-07-02  17:41:41
        """

        expected_dict = {
            "libcdio18:amd64": "2.0.0-2, 2.0.0-2ubuntu0.2",
            "docker-ce-rootless-extras:amd64": "5:27.0.1-1~ubuntu.20.04~focal, 5:27.0.2-1~ubuntu.20.04~focal"
        }

        package_dict = extract_package_names_and_versions(text)
        self.assertEqual(expected_dict, package_dict)


    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("install ok installed", "", 0))
    def test_check_package_status_return_success(self, mock_run: Mock) -> None:
        self.assertEqual(check_package_status("mock_package"), PACKAGE_SUCCESS)

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("unknown ok not-installed", "", 0))
    def test_check_package_status_return_pending_1(self, mock_run: Mock) -> None:
        self.assertEqual(check_package_status("mock_package"), PACKAGE_PENDING)

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("deinstall ok config-files", "", 0))
    def test_check_package_status_return_pending_2(self, mock_run: Mock) -> None:
        self.assertEqual(check_package_status("mock_package"), PACKAGE_PENDING)

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("", "error", 0))
    def test_check_package_status_error_return_fail(self, mock_run: Mock) -> None:
        self.assertEqual(check_package_status("mock_package"), PACKAGE_FAIL)

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("2.4.12-0ubuntu0.20.04.2", "", 0))
    def test_check_package_version_pass(self, mock_run: Mock) -> None:
        self.assertEqual(check_package_version("mock_package"), "2.4.12-0ubuntu0.20.04.2")

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("", "error", 0))
    def test_check_package_version_fail(self, mock_run: Mock) -> None:
        self.assertEqual(check_package_version("mock_package"), PACKAGE_UNKNOWN)
