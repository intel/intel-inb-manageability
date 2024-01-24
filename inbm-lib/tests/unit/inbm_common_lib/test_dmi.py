from inbm_common_lib.dmi import _parse_release_date, manufacturer_check
from unittest import TestCase
import datetime


class TestDmi(TestCase):

    def test_parse_release_date(self) -> None:
        actual = _parse_release_date('10/15/2018')
        expected = dmi_date
        self.assertEqual(actual, expected)

    def test_manufacturer_check_return_true(self) -> None:
        actual = manufacturer_check('Intel', 'Intel', 'kmb', 'kmb')
        expected = True
        self.assertEqual(actual, expected)

    def test_manufacturer_check_return_false(self) -> None:
        actual = manufacturer_check(
            'Intel', 'Intel corp ', 'kmb', 'kmb-on-poplar')
        expected = False
        self.assertEqual(actual, expected)


dmi_date = datetime.datetime(2018, 10, 15, 0, 0)
