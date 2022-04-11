from unittest import TestCase

from vision.data_handler.data_handler import DataHandler
from vision.updater import Updater, FotaUpdater, SotaUpdater, PotaUpdater, ConfigurationLoader, RequestStatus, \
    get_updater_factory
from vision.constant import VisionException
from mock import patch, Mock

fota_parsed_manifest = {'biosversion': '5.12',
                        'product': 'Default string',
                        'vendor': 'American Megatrends Inc.',
                        'ota': 'fota',
                        'repo': 'local',
                        'manufacturer': 'Default string',
                        'path': '/var/cache/manageability/X041_BIOS.tar',
                        'releasedate': '2018-03-30',
                        'signature': 'fota_signature',
                        'node_id0': '123ABC'}

sota_parsed_manifest = {'cmd': 'update',
                        'signature': 'Default string',
                        'path': '/var/cache/manageability/file.mender',
                        'release_date': '2018-03-30'}

pota_parsed_manifest = {'biosversion': '5.12',
                        'product': 'Default string',
                        'vendor': 'American Megatrends Inc.',
                        'ota': 'fota',
                        'repo': 'local',
                        'manufacturer': 'Default string',
                        'fota_signature': 'fota_signature',
                        'sota_signature': 'sota_signature',
                        'fota_path': '/var/cache/manageability/X041_BIOS.tar',
                        'sota_path': '/var/cache/manageability/file.mender',
                        'release_date': '2018-03-30',
                        'cmd': 'update',
                        'signature': 'Default string',
                        'releasedate': '2018-03-30',
                        'node_id0': '123ABC'}

config_parsed_manifest = {'path': '/var/cache/manageability/node.conf'}

revised_fota_manifest = '            <manifest>                <type>ota</type>                <ota>                    <header>                        <type>fota</type>                        <repo>local</repo>                    </header>                    <type>                        <fota name="sample">                            <path>/var/cache/manageability/X041_BIOS.tar</path>                            <biosversion>5.12</biosversion>                            <vendor>American Megatrends Inc.</vendor>                            <manufacturer>Default string</manufacturer>                            <product>Default string</product>                            <releasedate>2018-03-30</releasedate>                            <signature>fota_signature</signature>                        </fota>                    </type>                </ota>            </manifest>'
revised_sota_manifest = '            <manifest>                <type>ota</type>                <ota>                    <header>                        <type>sota</type>                        <repo>local</repo>                    </header>                    <type>                        <sota>                            <cmd logtofile="y">update</cmd>                            <signature>Default string</signature>                            <path>/var/cache/manageability/file.mender</path>                            <release_date>2018-03-30</release_date>                        </sota>                    </type>                </ota>            </manifest>'
revised_pota_manifest = '            <manifest>                <type>ota</type>                <ota>                    <header>                        <type>pota</type>                        <repo>local</repo>                    </header>                    <type>                        <pota>                            <fota name="sample">                                <path>/var/cache/manageability/X041_BIOS.tar</path>                                <biosversion>5.12</biosversion>                                <vendor>American Megatrends Inc.</vendor>                                <manufacturer>Default string</manufacturer>                                <product>Default string</product>                                <releasedate>2018-03-30</releasedate>                                <signature>fota_signature</signature>                            </fota>                            <sota>                                <cmd logtofile="y">update</cmd>                                <path>/var/cache/manageability/file.mender</path>                                <release_date>2018-03-30</release_date>                                <signature>sota_signature</signature>                            </sota>                        </pota>                    </type>                </ota>            </manifest>'
revised_config_manifest = '            <path>/var/cache/manageability/node.conf</path>'

target_id = ["123ABC"]
config_file_name = "/var/cache/manageability/node.conf"


class TestUpdater(TestCase):  # type: ignore
    @patch('inbm_vision_lib.xlink.xlink_library.XLinkLibrary.__init__', return_value=None)
    @patch('vision.data_handler.data_handler.DataHandler.load_config_file')
    @patch('inbm_vision_lib.timer.Timer.start')
    @patch('inbm_vision_lib.invoker.Invoker.__init__', return_value=None)
    @patch('vision.registry_manager.RegistryManager.__init__', return_value=None)
    @patch('os.path.getsize', return_value=16000)
    @patch('os.path.exists', return_value=True)
    def setUp(self, os_path_exist, os_get_size, mgr_init, invoker_init, mock_timer, load_file, mock_xlink_lib):
        self.maxDiff = None
        self.mock_data_handler = DataHandler(Mock(), Mock())
        self.fota_updater = FotaUpdater(
            target_id, self.mock_data_handler, ["file_name"], fota_parsed_manifest, 100)
        self.sota_updater = SotaUpdater(
            target_id, self.mock_data_handler, ["file_name"], sota_parsed_manifest, 100)
        self.pota_updater = PotaUpdater(
            target_id, self.mock_data_handler, ["fota_file_name", "sota_file_name"], pota_parsed_manifest, 100)
        self.config_updater = ConfigurationLoader(target_id, self.mock_data_handler, ["file_name"],
                                                  {'path': config_file_name}, 100, 'node')
        self.assertEqual(os_path_exist.call_count, 5)
        mgr_init.assert_called_once()
        invoker_init.assert_called_once()
        self.assertEqual(mock_timer.call_count, 4)
        load_file.assert_called_once()

    @patch('inbm_vision_lib.timer.Timer.start')
    @patch('inbm_vision_lib.invoker.Invoker.__init__', return_value=None)
    @patch('vision.registry_manager.RegistryManager.__init__', return_value=None)
    @patch('os.path.getsize', return_value=16000)
    @patch('os.path.exists', return_value=True)
    def test_get_fota_updater_from_factory(self, os_path_exist, os_get_size, mock_reg, mock_invoker, mock_timer):
        assert type(get_updater_factory('fota', target_id, self.mock_data_handler, ["file_name"],
                                        fota_parsed_manifest, 100)) is FotaUpdater

    @patch('inbm_vision_lib.timer.Timer.start')
    @patch('inbm_vision_lib.invoker.Invoker.__init__', return_value=None)
    @patch('vision.registry_manager.RegistryManager.__init__', return_value=None)
    @patch('os.path.getsize', return_value=16000)
    @patch('os.path.exists', return_value=True)
    def test_get_sota_updater_from_factory(self, os_path_exist, os_get_size, mock_reg, mock_invoker, mock_timer):
        assert type(get_updater_factory('sota', target_id, self.mock_data_handler, ["file_name"],
                                        sota_parsed_manifest, 100)) is SotaUpdater

    @patch('inbm_vision_lib.timer.Timer.start')
    @patch('inbm_vision_lib.invoker.Invoker.__init__', return_value=None)
    @patch('vision.registry_manager.RegistryManager.__init__', return_value=None)
    @patch('os.path.getsize', return_value=16000)
    @patch('os.path.exists', return_value=True)
    def test_get_pota_updater_from_factory(self, os_path_exist, os_get_size, mock_reg, mock_invoker, mock_timer):
        assert type(get_updater_factory('pota', target_id, self.mock_data_handler, ["fota_file_name", "sota_file_name"],
                                        pota_parsed_manifest, 100)) is PotaUpdater

    def test_raise_error_unsupported_ota(self):
        self.assertRaises(VisionException, get_updater_factory, 'iota', target_id, self.mock_data_handler,
                          ["file_name"], pota_parsed_manifest, 100)

    def test_revise_fota_manifest_correctly(self):
        self.assertEqual(self.fota_updater._revised_manifest, revised_fota_manifest)
        test_target = self.fota_updater._get_target("123ABC")
        self.assertIsNotNone(test_target)
        self.assertEqual(len(self.fota_updater._targets), 1)

    def test_revise_sota_manifest_correctly(self):
        self.assertEqual(self.sota_updater._revised_manifest, revised_sota_manifest)
        test_target = self.sota_updater._get_target("123ABC")
        self.assertIsNotNone(test_target)
        self.assertEqual(len(self.sota_updater._targets), 1)

    def test_revise_pota_manifest_correctly(self):
        self.assertEqual(self.pota_updater._revised_manifest, revised_pota_manifest)
        test_target = self.sota_updater._get_target("123ABC")
        self.assertIsNotNone(test_target)
        self.assertEqual(len(self.sota_updater._targets), 1)

    def test_revise_config_load_manifest_correctly(self):
        self.assertEqual(self.config_updater._revised_manifest, revised_config_manifest)
        self.assertEqual(len(self.config_updater._targets), 1)

    def test_update_ota_target_status(self):
        self.fota_updater._update_target_status("123ABC", RequestStatus.SendFile)
        self.assertEquals(self.fota_updater._targets[0].get_status(), RequestStatus.SendFile)

    @patch('vision.updater.Updater._updater_timer_expired')
    def test_set_ota_target_error(self, mock_timer_expired):
        self.fota_updater.set_target_error("123ABC", "Send file fail.")
        self.assertEquals(self.fota_updater._targets[0].get_error(), "Send file fail.")

    def test_revise_manifest(self):
        manifest = self.fota_updater.revise_manifest(fota_parsed_manifest)
        self.assertEquals(manifest, revised_fota_manifest)

    def test_create_ota_target(self):
        targets_list = self.fota_updater._create_target(["456DEF"])
        self.assertEquals(len(targets_list), 1)

    @patch('vision.ota_target.OtaTarget.update_status')
    @patch('vision.data_handler.data_handler.DataHandler.create_download_request')
    def test_send_request_to_send_file(self, dh_dwReq, update_status):
        self.fota_updater.send_request_to_send_file()
        self.assertEquals(len(self.fota_updater._targets), 1)
        dh_dwReq.assert_called_once()
        update_status.assert_called_once()

    @patch('vision.data_handler.data_handler.DataHandler.send_file')
    @patch('vision.updater.Updater._update_target_status')
    def test_update_download_request_status_pass(self, update_status, send_file):
        self.fota_updater.update_download_request_status("123ABC", True)
        update_status.assert_called_once()
        send_file.assert_called_once()

    @patch('vision.data_handler.data_handler.DataHandler.send_telemetry_response')
    @patch('vision.updater.Updater.set_target_error')
    def test_update_download_request_status_fail(self, set_error, send_response):
        self.fota_updater.update_download_request_status("123ABC", False)
        set_error.assert_called_once()
        send_response.assert_called_once()

    @patch('vision.data_handler.data_handler.DataHandler.send_telemetry_response')
    @patch('vision.updater.Updater.set_target_error')
    def test_update_download_request_status_device_not_found(self, set_error, send_response):
        self.fota_updater.update_download_request_status("456DEF", True)
        set_error.assert_called_once()
        send_response.assert_called_once()

    @patch('vision.data_handler.data_handler.DataHandler.send_ota_manifest')
    @patch('vision.updater.Updater._update_target_status')
    def test_update_download_status_pass(self, update_status, send_file):
        self.fota_updater.update_download_status("123ABC", True)
        update_status.assert_called_once()
        send_file.assert_called_once()

    @patch('vision.data_handler.data_handler.DataHandler.send_telemetry_response')
    @patch('vision.updater.Updater.set_target_error')
    def test_update_download_status_fail(self, set_error, send_response):
        self.fota_updater.update_download_status("123ABC", False)
        set_error.assert_called_once()
        send_response.assert_called_once()

    @patch('vision.data_handler.data_handler.DataHandler.send_telemetry_response')
    @patch('vision.updater.Updater.set_target_error')
    def test_update_download_status_device_not_found(self, set_error, send_response):
        self.fota_updater.update_download_status("456DEF", True)
        set_error.assert_called_once()
        send_response.assert_called_once()

    @patch('vision.data_handler.data_handler.DataHandler.send_telemetry_response')
    @patch('vision.ota_target.OtaTarget.get_status')
    @patch('vision.ota_target.OtaTarget.get_error')
    @patch('vision.ota_target.OtaTarget.get_node_id')
    def test_updater_collect_result_pass(self, get_node_id, get_error, get_status, send_response):
        self.fota_updater._collect_result()
        get_node_id.assert_called_once()
        assert get_error.call_count == 2
        get_status.assert_called_once()
        send_response.assert_called_once()

    @patch('vision.ota_target.OtaTarget.get_status')
    @patch('vision.ota_target.OtaTarget.get_error')
    @patch('vision.ota_target.OtaTarget.get_node_id')
    def test_updater_collect_result_fail(self, get_node_id, get_error, get_status):
        self.fota_updater._targets = []
        self.fota_updater._collect_result()
        get_node_id.assert_not_called()
        get_error.assert_not_called()
        get_status.assert_not_called()

    @patch('vision.data_handler.data_handler.DataHandler.send_config_load_manifest')
    @patch('vision.updater.Updater._update_target_status')
    def test_config_update_download_status_pass(self, update_status, send_file):
        self.config_updater.update_download_status("123ABC", True)
        update_status.assert_called_once()
        send_file.assert_called_once()

    @patch('vision.data_handler.data_handler.DataHandler.send_telemetry_response')
    @patch('vision.updater.Updater.set_target_error')
    def test_config_update_download_status_fail(self, set_error, send_response):
        self.config_updater.update_download_status("123ABC", False)
        set_error.assert_called_once()
        send_response.assert_called_once()

    @patch('vision.data_handler.data_handler.DataHandler.send_telemetry_response')
    @patch('vision.updater.Updater.set_target_error')
    def test_config_update_download_status_device_not_found(self, set_error, send_response):
        self.config_updater.update_download_status("456DEF", True)
        set_error.assert_called_once()
        send_response.assert_called_once()

    @patch('os.remove')
    @patch('os.path.exists', return_value=True)
    @patch('vision.data_handler.data_handler.DataHandler.send_telemetry_response')
    @patch('vision.ota_target.OtaTarget.get_status')
    @patch('vision.ota_target.OtaTarget.get_error')
    @patch('vision.ota_target.OtaTarget.get_node_id')
    def test_config_updater_collect_result_pass(self, get_node_id, get_error, get_status, send_response,
                                                mock_exists, mock_remove):
        self.config_updater._collect_result()
        get_node_id.assert_called_once()
        assert get_error.call_count == 2
        get_status.assert_called_once()
        send_response.assert_called_once()

    @patch('vision.ota_target.OtaTarget.get_status')
    @patch('vision.ota_target.OtaTarget.get_error')
    @patch('vision.ota_target.OtaTarget.get_node_id')
    def test_config_updater_collect_result_fail(self, get_node_id, get_error, get_status):
        self.fota_updater._targets = []
        self.fota_updater._collect_result()
        get_node_id.assert_not_called()
        get_error.assert_not_called()
        get_status.assert_not_called()

    @patch('os.path.exists', return_value=False)
    def test_get_file_size_fail(self, os_path):
        self.assertRaises(VisionException, self.fota_updater._get_file_size)
        os_path.assert_called_once()

    @patch('vision.updater.Updater._updater_timer_expired', return_value=True)
    @patch('inbm_vision_lib.timer.Timer.stop', return_value=True)
    @patch('vision.ota_target.Target.is_done', return_value=True)
    def test_is_all_targets_done_return_true(self, is_done, timer_stop, timer_expired) -> None:
        self.assertTrue(self.fota_updater.is_all_targets_done())
        is_done.assert_called_once()
        timer_stop.assert_called_once()
        timer_expired.assert_called_once()

    @patch('vision.ota_target.Target.is_done', return_value=False)
    def test_is_all_targets_done_return_False(self, is_done) -> None:
        self.assertFalse(self.fota_updater.is_all_targets_done())
        is_done.assert_called_once()

    @patch('vision.data_handler.data_handler.DataHandler.send_telemetry_response')
    def test_set_done(self, send_response) -> None:
        self.fota_updater.set_done("123ABC")
        self.assertTrue(self.fota_updater._targets[0].is_done())
        send_response.assert_called_once()
