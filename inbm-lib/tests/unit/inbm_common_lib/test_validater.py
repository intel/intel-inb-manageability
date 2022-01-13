from unittest import TestCase
from inbm_common_lib.validater import ConfigurationItem, configuration_bounds_check


class TestValidater(TestCase):

    def setUp(self):
        self.item = ConfigurationItem('RegistrationRetry Timer Secs', 1, 60, 20)

    def test_return_value_when_within_limits(self) -> None:
        self.assertEquals(30, configuration_bounds_check(self.item, 30))

    def test_return_default_when_below_lower_limit(self) -> None:
        self.assertEquals(20, configuration_bounds_check(self.item, 0))

    def test_return_default_when_above_upper_limit(self) -> None:
        self.assertEquals(20, configuration_bounds_check(self.item, 61))
