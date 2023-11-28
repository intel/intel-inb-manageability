import os
import tempfile
import unittest
import fixtures
from mock import patch, mock_open
from dispatcher.sota.mender_util import *


class TestMenderUtil(unittest.TestCase):

    def test_read_current_mender_version_error(self) -> None:
        with self.assertRaises(SotaError):
            read_current_mender_version()

    @patch('dispatcher.sota.mender_util.read_current_mender_version')
    def test_read_current_mender_version(self, mock_file) -> None:
        expected_version = mock_file.return_value = "1.2"
        actual_version = "1.2"

        self.assertEqual(expected_version, actual_version)
