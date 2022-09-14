from unittest import TestCase
from inbm_common_lib.validater import ConfigurationItem, configuration_bounds_check, validate_guid
import argparse

class TestValidater(TestCase):

    def setUp(self):
        self.item = ConfigurationItem('RegistrationRetry Timer Secs', 1, 60, 20)

    def test_return_value_when_within_limits(self):
        self.assertEquals(30, configuration_bounds_check(self.item, 30))

    def test_return_default_when_below_lower_limit(self):
        self.assertEquals(20, configuration_bounds_check(self.item, 0))

    def test_return_default_when_above_upper_limit(self):
        self.assertEquals(20, configuration_bounds_check(self.item, 61))

    def test_return_value_when_on_upper_limit(self):
        self.assertEquals(60, configuration_bounds_check(self.item, 60))

    def test_return_value_when_on_lower_limit(self):
        self.assertEquals(1, configuration_bounds_check(self.item, 1))

    def test_check_validate_guid_format(self):
        self.assertEquals('6c8e136f-d3e6-4131-ac32-4687cb4abd27', validate_guid('6c8e136f-d3e6-4131-ac32-4687cb4abd27'))
    def test_check_validate_guid_first_8charactersposition_when_at_lessthan_8characters(self):
        with self.assertRaisesRegex(argparse.ArgumentTypeError,"GUID should be 36 characters displayed in five groups separated by a dash in the format XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX and Hexdigits are allowed"):
            validate_guid('6c8e13-d3e6-4131-ac32-4687cb4abd27')
    def test_check_validate_guid_first_8charactersposition_when_at_greaterthan_8characters(self):
        with self.assertRaisesRegex(argparse.ArgumentTypeError,"GUID should be 36 characters displayed in five groups separated by a dash in the format XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX and Hexdigits are allowed"):
            validate_guid('6c8e136f2b-d3e6-4131-ac32-4687cb4abd27')
    def test_check_validate_guid_second_4charactersposition_when_at_lessthan_4characters(self):
        with self.assertRaisesRegex(argparse.ArgumentTypeError,"GUID should be 36 characters displayed in five groups separated by a dash in the format XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX and Hexdigits are allowed"):
            validate_guid('6c8e136f-d3e-4131-ac32-4687cb4abd27')
    def test_check_validate_guid_second_4charactersposition_when_at_greaterthan_4characters(self):
        with self.assertRaisesRegex(argparse.ArgumentTypeError,"GUID should be 36 characters displayed in five groups separated by a dash in the format XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX and Hexdigits are allowed"):
            validate_guid('6c8e136f-d3e6aa-4131-ac32-4687cb4abd27')
    def test_check_validate_guid_third_4charactersposition_when_at_lessthan_4characters(self):
        with self.assertRaisesRegex(argparse.ArgumentTypeError,"GUID should be 36 characters displayed in five groups separated by a dash in the format XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX and Hexdigits are allowed"):
            validate_guid('6c8e136f-d3e6-41-ac32-4687cb4abd27')
    def test_check_validate_guid_third_4charactersposition_when_at_greaterthan_4characters(self):
        with self.assertRaisesRegex(argparse.ArgumentTypeError,"GUID should be 36 characters displayed in five groups separated by a dash in the format XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX and Hexdigits are allowed"):
            validate_guid('6c8e136f-d3e6-413156-ac32-4687cb4abd27')
    def test_check_validate_guid_fourth_4charactersposition_when_at_lessthan_4characters(self):
        with self.assertRaisesRegex(argparse.ArgumentTypeError,"GUID should be 36 characters displayed in five groups separated by a dash in the format XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX and Hexdigits are allowed"):
            validate_guid('6c8e136f-d3e6-4131-a-4687cb4abd27')
    def test_check_validate_guid_fourth_4charactersposition_when_at_greaterthan_4characters(self):
        with self.assertRaisesRegex(argparse.ArgumentTypeError,"GUID should be 36 characters displayed in five groups separated by a dash in the format XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX and Hexdigits are allowed"):
            validate_guid('6c8e136f-d3e6-4131-ac32def-4687cb4abd27')
    def test_check_validate_guid_fifth_12charactersposition_when_at_lessthan_12characters(self):
        with self.assertRaisesRegex(argparse.ArgumentTypeError,"GUID should be 36 characters displayed in five groups separated by a dash in the format XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX and Hexdigits are allowed"):
            validate_guid('6c8e136f-d3e6-4131-ac32-4687cb4ab')
    def test_check_validate_guid_fifth_12charactersposition_when_at_greaterthan_12characters(self):
        with self.assertRaisesRegex(argparse.ArgumentTypeError,"GUID should be 36 characters displayed in five groups separated by a dash in the format XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX and Hexdigits are allowed"):
            validate_guid('6c8e136f-d3e6-4131-ac32-4687cb4abd27ef89')
