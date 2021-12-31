from unittest import TestCase
from mock import Mock

from vision.data_handler.query import _create_query_response
from vision.constant import HEARTBEAT_ACTIVE_STATE, VisionException


class TestQuery(TestCase):
    def test_raises_unsupported_query_type(self):
        with self.assertRaises(VisionException):
            _create_query_response('invalid', Mock())
