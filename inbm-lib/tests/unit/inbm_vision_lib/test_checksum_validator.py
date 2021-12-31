from unittest import TestCase
import hashlib
from inbm_vision_lib.checksum_validator import validate_message
from inbm_vision_lib.constants import SecurityException


class TestCheckSumValidator(TestCase):
    def test_successfully_validate_good_message(self):
        try:
            expected_hash = hashlib.sha384(b"Hello").hexdigest()
            validate_message(expected_hash, "Hello")
        except SecurityException:
            self.fail("Raised exception when not expected.")

    def test_raise_on_invalid_message(self):
        with self.assertRaises(SecurityException):
            expected_hash = hashlib.sha384(b"Hello Bit Creek!").hexdigest()
            validate_message(expected_hash, "Hello")
