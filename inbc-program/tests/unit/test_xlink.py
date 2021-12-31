
from unittest import TestCase

from inbc.xlink import Xlink
from inbc.constants import MAX_STATUS_NUM


class TestXlink(TestCase):
    def setUp(self):
        mock_id = 12345
        self.xlink = Xlink(mock_id)

    def test_update_device_status(self):
        self.xlink.update_device_status(0)
        self.assertEqual(len(self.xlink.device_status), 1)

    def test_update_device_status_pop(self):
        for i in range(MAX_STATUS_NUM):
            self.xlink.update_device_status(0)
        self.xlink.update_device_status(1)
        self.assertEqual(len(self.xlink.device_status), MAX_STATUS_NUM)

    def test_check_device_status_only_one_status_in_list(self):
        self.xlink.update_device_status(1)
        self.assertEqual(self.xlink.check_device_status(), 4)

    def test_check_device_status_error_status(self):
        for i in range(MAX_STATUS_NUM):
            self.xlink.update_device_status(-1)
        self.assertEqual(self.xlink.check_device_status(), -1)

    def test_get_device_id(self):
        self.assertEqual(self.xlink.get_device_id(), 12345)
