import json
from telemetry.static_attributes import get_total_physical_memory, get_disk_information, get_os_information
from mock import patch
from unittest import TestCase
from collections import namedtuple
from future import standard_library
standard_library.install_aliases()


svmem = namedtuple(
    'svmem', ['total', 'available', 'percent', 'used', 'free',
              'active', 'inactive', 'buffers', 'cached', 'shared'])
svmem(10, 5, 50, 5, 5, 2, 3, 5, 5, 5)


class TestStaticAttributes(TestCase):

    @patch('psutil.virtual_memory')
    def test_get_total_physical_memory(self, mock_virtual_memory):
        mock_virtual_memory.return_value = svmem
        res = get_total_physical_memory()
        mock_virtual_memory.assert_called_once()
        self.assertEquals(res, svmem.total)

    @patch('telemetry.lsblk.get_lsblk_output')
    def test_disk_information_fail(self, mock_lsblk):
        mock_lsblk.return_value = None
        res = get_disk_information()
        self.assertEquals(res, 'Unknown')
        mock_lsblk.assert_called_once()

    @patch('telemetry.lsblk.get_lsblk_output')
    def test_disk_information_success(self, mock_lsblk):
        mock_lsblk.return_value = "NAME          SIZE ROTA\n loop1     33554432    1\n sr0     1073741312    1" \
                                  "\n loop2     33554432    1\n loop0     33554432    1\nsda   250059350016    1"
        res = get_disk_information()

        # normalize JSON representation
        self.assertEquals(json.dumps(json.loads(res)),
                          json.dumps(json.loads('[{"NAME": "loop1", "SIZE": "33554432", "SSD": "False"}, {"NAME": "sr0", "SIZE": "1073741312", "SSD": "False"}, {"NAME": "loop2", "SIZE": "33554432", "SSD": "False"}, {"NAME": "loop0", "SIZE": "33554432", "SSD": "False"}, {"NAME": "sda", "SIZE": "250059350016", "SSD": "False"}]')))
        mock_lsblk.assert_called_once()

    @patch('telemetry.lsblk.get_lsblk_output')
    @patch('telemetry.lsblk.parse_lsblk')
    def test_disk_information_parse_fail(self, mock_parse, mock_lsblk):
        mock_lsblk.return_value = "abc"
        mock_parse.return_value = None
        res = get_disk_information()
        self.assertEquals(res, 'Unknown')
        mock_lsblk.assert_called_once()
        mock_parse.assert_called_once()

    @patch('platform.uname')
    def test_os_information(self, mock_platform):
        mock_platform.return_value = ('Linux', '16.04')
        res = get_os_information()
        self.assertEquals(res, "Linux 16.04")
