from mock import patch
from telemetry.lsblk import parse_lsblk, get_lsblk_output
from unittest import TestCase
import unittest
from future import standard_library
standard_library.install_aliases()


class TestLsblk(TestCase):

    def test_no_lines(self):
        self.assertEqual(parse_lsblk(''), None)

    def test_three_drives(self):
        lsblk_output = \
            """NAME          SIZE ROTA
sdb   480103981056    0
sr0     1073741312    1
sda  2000398934016    1
"""
        expected = [{"NAME": "sdb", "SIZE": "480103981056", "SSD": "True"},
                    {"NAME": "sr0", "SIZE": "1073741312", "SSD": "False"},
                    {"NAME": "sda", "SIZE": "2000398934016", "SSD": "False"}]
        self.assertEqual(parse_lsblk(lsblk_output), expected)

    def test_one_drive(self):
        lsblk_output = \
            """NAME    SIZE ROTA
sda   123456    1
"""

        expected = [{"NAME": "sda", "SIZE": "123456", "SSD": "False"}]
        self.assertEqual(parse_lsblk(lsblk_output), expected)

    def test_different_header(self):
        lsblk_output = \
            """ABC DEF GHI
            qrs tuv wxy"""

        expected = None
        self.assertEqual(parse_lsblk(lsblk_output), expected)

    @patch('platform.system')
    def test_get_lsblk_ouput_different_platform(self, mock_platform):
        mock_platform.return_value = 'Windows'
        res = get_lsblk_output()
        self.assertIsNone(res)

    @patch('platform.system')
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run')
    def test_get_lsblk_ouput_fail(self, mock_runner, mock_platform):
        mock_runner.return_value = ('', 'ERROR', 1)
        mock_platform.return_value = 'Linux'
        res = get_lsblk_output()
        self.assertIsNone(res)

    @patch('platform.system')
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run')
    def test_get_lsblk_ouput_success(self, mock_runner, mock_platform):
        lsblk_output = \
            """NAME    SIZE ROTA
            sda   123456    1
            """
        mock_runner.return_value = (lsblk_output, "", 0)
        mock_platform.return_value = 'Linux'
        res = get_lsblk_output()
        self.assertEquals(lsblk_output, res)


if __name__ == '__main__':
    unittest.main()
