import os
from unittest import TestCase
from vision.constant import VisionException
from vision.validater import validate_key, validate_xlink_message

HEARTBEAT_MESSAGE_FAIL = '<?xml version="1.0" encoding="utf-8"?><message>    <heartbeat>/></message>'


class TestValidater(TestCase):
    def test_validate_key_successful(self):
        try:
            validate_key('heartbeatRetryLimit')
        except VisionException:
            self.fail("Raised exception when not expected.")

    def test_validate_key_raises_invalid_key(self):
        with self.assertRaises(VisionException):
            validate_key('invalid')

    def test_validate_xlink_message_fail(self):
        with self.assertRaises(VisionException):
            validate_xlink_message(HEARTBEAT_MESSAGE_FAIL)
