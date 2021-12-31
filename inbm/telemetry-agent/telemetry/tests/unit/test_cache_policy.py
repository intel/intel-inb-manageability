from telemetry.cache_policy import trim_cache
from unittest import TestCase
import unittest
from future import standard_library
standard_library.install_aliases()


class TestCachePolicy(TestCase):

    def test_trim_collection_five_elements_to_three_elements(self):
        self.assertEqual(trim_cache([1, 2, 3, 4, 5], 3), [3, 4, 5])

    def test_trim_collection_zero_elements_to_three_elements(self):
        self.assertEqual(trim_cache([], 3), [])

    def test_trim_collection_two_elements_to_two_elements(self):
        self.assertEqual(trim_cache([2, 3], 2), [2, 3])

    def test_trim_collection_four_element_to_one_element(self):
        self.assertEqual(trim_cache([4, 3, 2, 1], 1), [1])

    def test_invalid_max_cache_size(self):
        input_collection = [1, 2]
        max_cache_size = -1

        with self.assertRaises(ValueError) as _:
            trim_cache(input_collection, max_cache_size)


if __name__ == '__main__':
    unittest.main()
