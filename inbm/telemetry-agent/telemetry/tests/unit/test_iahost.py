from mock import patch
from telemetry.iahost import *
from unittest import TestCase
import unittest


class TestIahost(TestCase):

    @patch('platform.system')
    def test_is_iahost(self, mock_platform):
        mock_platform.return_value = ''
        res = is_iahost()
        self.assertEqual(res, False)

    @patch('platform.system')
    @patch('os.uname')
    def test_is_iahost_success(self, mock_os, mock_platform):
        mock_platform.return_value = 'Linux'
        mock_os.return_value = ("", "", "", "", "x86_64")
        res = is_iahost()
        self.assertEqual(res, True)

    @patch('platform.system')
    @patch('os.uname')
    def test_is_iahost_failure(self, mock_os, mock_platform):
        mock_platform.return_value = 'Linux'
        mock_os.return_value = ("", "", "", "", "")
        res = is_iahost()
        self.assertEqual(res, False)

    @patch('os.path.exists')
    def test_rm_service_active(self, mock_path):
        mock_path.return_value = True
        res = rm_service_active()
        self.assertEqual(res, True)

    @patch('os.path.exists')
    def test_rm_service_active_failure(self, mock_path):
        mock_path.return_value = False
        res = rm_service_active()
        self.assertEqual(res, False)


if __name__ == '__main__':
    unittest.main()
