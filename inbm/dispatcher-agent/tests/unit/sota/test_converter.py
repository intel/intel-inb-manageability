import unittest
from ddt import ddt, data, unpack

from dispatcher.sota.converter import size_to_bytes


@ddt
class TestConverter(unittest.TestCase):

    @unpack
    @data((1, "5 kB"), (2, "5 mB"), (3, "5 B"), (4, "5 gB"), (5, "12.3 gB"),
          (6, "5 kB"), (7, "5 MB"), (8, "5 GB"), (9, "12.3 GB"))
    def test_size_to_bytes(self, order, test_data):
        size = size_to_bytes(test_data)
        if order in (1, 6):
            self.assertEqual(size, 5000.0)
        elif order in (2, 7):
            self.assertEqual(size, 5000000.0)
        elif order == 3:
            self.assertEqual(size, 5.0)
        elif order in (4, 8):
            self.assertEqual(size, 5000000000)
        elif order == (5, 9):
            self.assertEqual(size, 12300000000.0)

    @unpack
    @data((1, "5 Kb"), (2, "5 a"), (3, "12,3,3 kB"), (4, ""))
    def test_size_to_bytes_raises(self, order, test_data):
        if order in (1, 2):
            self.assertRaises(
                KeyError, size_to_bytes, test_data)
        elif order == 3:
            self.assertRaises(
                ValueError, size_to_bytes, test_data)
        elif order == 4:
            self.assertRaises(
                IndexError, size_to_bytes, test_data)
