from unittest import TestCase
from node.package_version import get_version
from mock import patch, mock_open


class TestPackageVersion(TestCase):

    def test_get_version(self):
        with patch("builtins.open", mock_open(read_data="2.16.0")) as mock_file:
            self.assertEqual(get_version(), '2.16.0')

    def test_get_version_not_found(self):
        with patch("builtins.open", mock_open(read_data="2.16.0")) as mock_file:
            mock_file.side_effect = PermissionError()
            self.assertEqual(get_version(), "UNKNOWN")
