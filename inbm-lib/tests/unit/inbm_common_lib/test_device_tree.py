from inbm_common_lib.device_tree import is_device_tree_exists, get_device_tree_cpu_id, \
    _parse_bios_date, get_device_tree_system_info
from testtools import TestCase
import datetime


class TestDeviceTree(TestCase):

    def test_get_device_tree_system_info(self) -> None:
        if is_device_tree_exists():
            actual = get_device_tree_system_info()
            expected = devicetree_parsed_1
            self.assertEqual(actual, expected)
            self.assertEqual(5, DeviceTree.read_file.call_count)  # type: ignore

    def test_get_device_tree_cpu_id(self) -> None:
        if is_device_tree_exists():
            actual = get_device_tree_cpu_id()
            expected = devicetree_cpu_id
            self.assertEqual(actual, expected)

    def test_parse_release_date(self) -> None:
        actual = _parse_bios_date('Jun 27 2019 16:04:32')
        expected = devicetree_date
        self.assertEqual(actual, expected)


devicetree_date = datetime.datetime(2019, 6, 27, 16, 4, 32)

devicetree_cpu_id = 'HiSilicon Poplar Development Board (Keem Bay)'

devicetree_system_info = ''

DEVICE_TREE_PATH = '/proc/device-tree/'

devicetree_parsed_1 = (datetime.datetime(2006, 12, 1, 0, 0),
                       'innotek GmbH',
                       'VirtualBox',
                       'innotek GmbH',
                       'VirtualBox',
                       True)
