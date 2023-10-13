from mock import patch
import telemetry.software_checker
from unittest import TestCase




class TestSoftwareChecker(TestCase):

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("", "", 0))
    @patch('os.path.exists', return_value=True)
    def test_return_true_when_docker_present(self, mock_path, mock_run):
        self.assertTrue(telemetry.software_checker.are_docker_and_trtl_on_system())

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("", "", 1))
    @patch('os.path.exists', return_value=True)
    def test_return_false_when_docker_not_present(self, mock_path, mock_run):
        self.assertFalse(telemetry.software_checker.are_docker_and_trtl_on_system())

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("", "", 0))
    @patch('os.path.exists', return_value=False)
    def test_return_false_when_trtl_not_present(self, mock_path, mock_run):
        self.assertFalse(telemetry.software_checker.are_docker_and_trtl_on_system())
