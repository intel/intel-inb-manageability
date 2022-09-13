from unittest import TestCase
from inbm_common_lib.validater import ConfigurationItem, configuration_bounds_check
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

    def test_check_validate_guid_pass(self):
        self.assertEquals('6c8e136f-d3e6-4131-ac32-4687cb4abd27', validate_guid('6c8e136f-d3e6-4131-ac32-4687cb4abd27', 'guid',50))

    def test_check_validate_guid_fail(self):
        with self.assertRaisesRegex(argparse.ArgumentTypeError, 'guid does not support characters other than hexdigits and dash'):
            validate_guid('6c8e136f-d3e6-4131-ac32-4687cb4abd2@', 'guid',50)
