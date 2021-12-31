from node.flashless_checker import is_flashless
from mock import patch, mock_open
from unittest import TestCase


class TestFlashlessChecker(TestCase):

    def test_return_false(self):
        with patch("builtins.open", mock_open(read_data="sysfs /sys sysfs rw,relatime 0 0")) as mock_file:
            self.assertFalse(is_flashless())

    def test_return_true(self):
        with patch("builtins.open", mock_open(read_data="rootfs / rootfs rw,size=748636k,nr_inodes=187159 0 0")) as mock_file:
            self.assertTrue(is_flashless())
