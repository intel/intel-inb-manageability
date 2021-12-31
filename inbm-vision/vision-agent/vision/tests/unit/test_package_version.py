from unittest import TestCase
from vision.package_version import get_version
from mock import patch


class TestPackageVersion(TestCase):

    @patch("inbm_vision_lib.shell_runner.PseudoShellRunner.run", return_value=("vision-agent     1.7.1-1", '', 0))
    def test_get_version(self, mock_run):
        self.assertEqual(get_version(), '1.7.1-1')

    @patch("inbm_vision_lib.shell_runner.PseudoShellRunner.run", return_value=("permission denied", '', 2))
    def test_get_version_not_found(self, mock_run):
        self.assertEqual(get_version(), None)
