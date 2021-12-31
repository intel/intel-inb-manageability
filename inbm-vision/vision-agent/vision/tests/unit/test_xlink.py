
from unittest import TestCase

from vision.node_communicator.xlink import Xlink, XlinkSecured
from mock import Mock


class TestXlink(TestCase):
    def setUp(self):
        self.mock_xlink_wrapper = Mock()

    def test_create_registry_success(self):
        new_xlink = Xlink(self.mock_xlink_wrapper, 0x501, "389C0A")
        self.assertIsNotNone(new_xlink)

    def test_create_secure_registry_success(self):
        new_xlink = XlinkSecured(Mock(), 0x501, "389C0A")
        self.assertIsNotNone(new_xlink)

    def test_create_registry_fail(self):
        self.assertRaises(TypeError, Xlink,
                          (self.mock_xlink_wrapper, 0x501, "False", "123ABC"))
