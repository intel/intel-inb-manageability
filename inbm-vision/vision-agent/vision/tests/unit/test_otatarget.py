
from unittest import TestCase

from vision.ota_target import OtaTarget, RequestStatus, Target


class TestOtaTarget(TestCase):

    def setUp(self):
        self.ota_target = OtaTarget("123ABC")
        self.target = Target("345DEF")

    def test_get_node_id(self):
        self.assertEqual(self.ota_target.get_node_id(), "123ABC")
        self.assertEqual(self.target.get_node_id(), "345DEF")

    def test_get_error(self):
        self.assertEqual(self.ota_target.get_error(), "None")

    def test_get_status(self):
        self.assertEqual(self.ota_target.get_status(), RequestStatus.NoneState)

    def test_set_error(self):
        self.ota_target.set_error("Error 400")
        self.assertEqual(self.ota_target.get_error(), "Error 400")

    def test_update_status(self):
        self.ota_target.update_status(RequestStatus.SendFile)
        self.assertEqual(self.ota_target.get_status(), RequestStatus.SendFile)

    def test_get_correct_is_done_state(self):
        self.assertFalse(self.target.is_done())
        self.target.set_done()
        self.assertTrue(self.target.is_done())
