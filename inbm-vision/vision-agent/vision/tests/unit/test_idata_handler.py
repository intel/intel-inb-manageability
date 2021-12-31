from unittest import TestCase
from mock import patch, Mock
from vision.data_handler.idata_handler import IDataHandler


class TestiDataHandler(TestCase):

    @patch.multiple(IDataHandler, __abstractmethods__=set())
    def setUp(self):
        self.idata_handler = IDataHandler()  # type: ignore

    def test_all_method_no_error_return(self):
        self.assertIsNone(self.idata_handler.receive_restart_request(Mock()))
        self.assertIsNone(self.idata_handler.receive_mqtt_message(Mock()))
        self.assertIsNone(self.idata_handler.manage_configuration_request(Mock()))
        self.assertIsNone(self.idata_handler.manage_configuration_update(Mock()))
        self.assertIsNone(self.idata_handler.receive_xlink_message(Mock()))
        self.assertIsNone(self.idata_handler.send_node_register_response(Mock()))
        self.assertIsNone(self.idata_handler.create_telemetry_event(Mock(), Mock()))
        self.assertIsNone(self.idata_handler.send_is_alive(Mock()))
        self.assertIsNone(self.idata_handler.send_reregister_request(Mock()))
        self.assertIsNone(self.idata_handler.create_download_request(Mock(), Mock()))
        self.assertIsNone(self.idata_handler.send_file(Mock(), Mock()))
        self.assertIsNone(self.idata_handler.send_telemetry_response(Mock(), Mock()))
        self.assertIsNone(self.idata_handler.send_ota_manifest(Mock(), Mock()))
        self.assertIsNone(self.idata_handler.send_config_load_manifest(Mock(), Mock(), Mock()))
        self.assertIsNone(self.idata_handler.stop())
        self.assertIsNone(self.idata_handler.load_config_file(Mock()))
        self.assertIsNone(self.idata_handler.receive_command_request(Mock()))
        self.assertIsNone(self.idata_handler.publish_xlink_status(Mock(), Mock()))
        self.assertIsNone(self.idata_handler.reset_device(Mock()))
