from telemetry.dynamic_attributes import get_percent_disk_used, get_available_memory, get_cpu_percent, \
    get_core_temp_celsius
from mock import patch
from unittest import TestCase
from collections import namedtuple


svmem = namedtuple(
    'svmem', ['total', 'available', 'percent', 'used', 'free',
              'active', 'inactive', 'buffers', 'cached', 'shared'])
svmem(10, 5, 50, 5, 5, 2, 3, 5, 5, 5)


class TestDynamicAttributes(TestCase):

    @patch('psutil.disk_usage')
    def test_disk_usage(self, mock_disk_usage):
        get_percent_disk_used()
        mock_disk_usage.assert_called_once()

    @patch('psutil.virtual_memory')
    def test_get_available_memory(self, mock_virtual_memory):
        mock_virtual_memory.return_value = svmem
        res = get_available_memory()
        mock_virtual_memory.assert_called_once()
        self.assertEqual(res, svmem.available)

    @patch('psutil.cpu_percent')
    def test_cpu_percent(self, mock_cpu_percent):
        get_cpu_percent()
        mock_cpu_percent.assert_called_once()

    @patch('psutil.sensors_temperatures')
    def test_get_core_temp_celsius_unknown(self, mock_temp):
        mock_temp.return_value = {}
        res = get_core_temp_celsius()
        self.assertEqual(res, 'Unknown')

    @patch('psutil.sensors_temperatures')
    def test_get_core_temp_celsius_success(self, mock_temp):
        shwtemp = namedtuple(
            'shwtemp', ['label', 'current', 'high', 'critical'])
        mock_temp.return_value = {'coretemp': [
            shwtemp(label='Package id 0', current=44.0, high=80.0, critical=98.0)]}
        res = get_core_temp_celsius()
        self.assertEqual(res, 44.0)

    @patch('psutil.sensors_temperatures')
    def test_get_core_temp_celsius_TBH_success(self, mock_temp):
        shwtemp = namedtuple(
            'shwtemp', ['label', 'current', 'high', 'critical'])
        mock_temp.return_value = {'cpu_s': [
            shwtemp(label='Package id 0', current=44.0, high=80.0, critical=98.0)], 'cpu_n': [
            shwtemp(label='Package id 0', current=45.0, high=80.0, critical=98.0)]}
        res = get_core_temp_celsius()
        self.assertEqual(res, 45.0)

    @patch('psutil.sensors_temperatures')
    def test_get_core_temp_celsius_kmb_success(self, mock_temp):
        shwtemp = namedtuple(
            'shwtemp', ['label', 'current', 'high', 'critical'])
        mock_temp.return_value = {'soc': [
            shwtemp(label='Package id 0', current=44.0, high=80.0, critical=98.0)]}
        res = get_core_temp_celsius()
        self.assertEqual(res, 44.0)

    @patch('psutil.sensors_temperatures')
    def test_get_core_temp_celsius_fail(self, mock_temp):
        shwtemp = namedtuple(
            'shwtemp', ['label', 'current', 'high', 'critical'])
        mock_temp.return_value = {'abc': [
            shwtemp(label='Package id 0', current=44.0, high=80.0, critical=98.0)]}
        self.assertEqual(get_core_temp_celsius(), 'Unknown')

    @patch('platform.system', return_value="Windows")
    def test_return_unknown_for_windows(self, mock_os):
        self.assertEqual(get_core_temp_celsius(), 'Unknown')
