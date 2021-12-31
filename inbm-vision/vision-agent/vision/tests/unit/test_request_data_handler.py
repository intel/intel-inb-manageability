from unittest import TestCase
from datetime import datetime

from mock import Mock, patch, MagicMock

from vision.data_handler.request_data_handler import FotaDataHandler, SotaDataHandler, PotaDataHandler, \
    GeneralDataHandler, RequestDataHandler, get_dh_factory
from vision.constant import VisionException

PARSED_VALUE = {'repo': 'local', 'ota': 'fota', 'path': '/var/cache/manageability/X041_BIOS.tar',
                'biosversion': '5.12', 'vendor': 'Intel', 'manufacturer': 'Intel',
                'product': 'intel', 'releasedate': '2020-7-20', 'release_date': None,
                'cmd': None, 'logtofile': None, 'signature': None, 'node_id0': '123ABC'}


def _create_registry_manager(mock_manifest):
    mock_node = Mock()
    mock_node.hardware.manufacturer = mock_manifest["manufacturer"]
    mock_node.firmware.boot_fw_vendor = mock_manifest["vendor"]
    mock_node.hardware.platform_product = mock_manifest['intel']
    mock_node.firmware.boot_fw_date = datetime(year=2020, month=7, day=19, second=0)
    mock_node.os.os_type = "Yocto"
    mock_node.os.os_release_date = datetime(year=2020, month=7, day=19, second=0)

    mock_registry_mgr = Mock()
    mock_registry_mgr.get_device = MagicMock(return_value=(mock_node, 1))
    return mock_registry_mgr


def _create_mock_ota_manifest():
    mock_manifest_info = MagicMock()
    mock_manifest_info["manufacturer"] = "Intel"
    mock_manifest_info["vendor"] = "Intel"
    mock_manifest_info["releasedate"] = "2020-10-26"
    mock_manifest_info["release_date"] = "20220-10-26"
    return mock_manifest_info


class TestRequestDataHandler(TestCase):

    def setUp(self):
        self._mock_manifest = _create_mock_ota_manifest()
        self._mock_registry_mgr = _create_registry_manager(self._mock_manifest)

    def test_get_fota_dh_from_factory(self):
        assert type(get_dh_factory('fota', self._mock_registry_mgr, self._mock_manifest, ["mock_id"])) \
            is FotaDataHandler

    def test_get_sota_dh_from_factory(self):
        assert type(get_dh_factory('sota', self._mock_registry_mgr, self._mock_manifest, ["mock_id"])) \
            is SotaDataHandler

    def test_get_pota_dh_from_factory(self):
        assert type(get_dh_factory('pota', self._mock_registry_mgr, self._mock_manifest, ["mock_id"])) \
            is PotaDataHandler

    def test_raise_error_unsupported_ota(self):
        self.assertRaises(VisionException, get_dh_factory, 'iota', self._mock_registry_mgr,
                          self._mock_manifest, ["mock_id"])

    @patch('vision.parser.XLinkParser.create_date_time_from_string',
           return_value=datetime(year=2020, month=10, day=20, second=0))
    @patch('os.remove')
    @patch('vision.data_handler.request_data_handler.RequestDataHandler._check_active_node', return_value=["mock_id"])
    def test_validate_fota_node_pass(self, mock_nodes, mock_remove, mock_date):
        mock_manifest = _create_mock_ota_manifest()
        mock_registry_mgr = _create_registry_manager(mock_manifest)

        dh = FotaDataHandler(mock_registry_mgr, mock_manifest, ["mock_id"])

        self.assertEqual(["mock_id"], dh.get_validated_node_ids())
        mock_remove.assert_not_called()

    @patch('os.remove')
    @patch('vision.data_handler.request_data_handler.RequestDataHandler._check_active_node', return_value=["mock_id"])
    def test_fail_validate_fota_manufacturer_mismatch(self, get_device, mock_remove):
        mock_manifest = _create_mock_ota_manifest()

        mock_node = Mock()
        mock_node.manufacturer = "ABC"
        mock_node.boot_fw_vendor = mock_manifest["vendor"]

        mock_register_manager = Mock()
        mock_register_manager.get_device = MagicMock(return_value=(mock_node, 1))

        dh = FotaDataHandler(mock_register_manager, PARSED_VALUE, ["mock_id"])
        self.assertEqual(dh.get_validated_node_ids(), [])

    @patch('vision.parser.XLinkParser.create_date_time_from_string',
           return_value=datetime(year=2020, month=10, day=20, second=0))
    @patch('os.remove')
    @patch('vision.data_handler.request_data_handler.RequestDataHandler._check_active_node', return_value=["mock_id"])
    def test_fail_validate_fota_release_date_issue(self, get_device, mock_remove, mock_date):
        mock_manifest = _create_mock_ota_manifest()

        mock_node = Mock()
        mock_node.manufacturer = mock_manifest["manufacturer"]
        mock_node.boot_fw_vendor = mock_manifest["vendor"]
        mock_node.boot_fw_date = datetime(year=2020, month=10, day=31, second=0)

        mock_registry_mgr = Mock()
        mock_registry_mgr.get_device = MagicMock(return_value=(mock_node, 1))

        dh = FotaDataHandler(mock_registry_mgr, PARSED_VALUE, ["mock_id"])
        self.assertEqual(dh.get_validated_node_ids(), [])

    @patch('vision.parser.XLinkParser.create_date_time_from_string', return_value=datetime(year=2020, month=7, day=20, second=0))
    @patch('os.remove')
    @patch('vision.data_handler.request_data_handler.RequestDataHandler._check_active_node', return_value=["mock_id"])
    def test_validate_sota_node_pass(self, mock_nodes, mock_remove, mock_date):
        mock_manifest = _create_mock_ota_manifest()
        mock_registry_manager = _create_registry_manager(mock_manifest)

        dh = SotaDataHandler(mock_registry_manager, PARSED_VALUE, ["mock_id"])
        nodes = dh.get_validated_node_ids()

        self.assertEqual(["mock_id"], nodes)
        mock_remove.assert_not_called()

    @patch('os.path.exists', return_value=True)
    @patch('os.path.isfile', return_value=True)
    @patch('os.remove')
    @patch('vision.data_handler.request_data_handler.RequestDataHandler._check_active_node', return_value=["mock_id"])
    def test_sota_validate_fails_os_mismatch(self, get_device, mock_remove, mock_is_file, mock_exists) -> None:
        mock_node = Mock()
        mock_node.os_type = "Windows"

        mock_register_manager = Mock()
        mock_register_manager.get_device = MagicMock(return_value=(mock_node, 1))

        dh = SotaDataHandler(mock_register_manager, PARSED_VALUE, ["mock_id"])

        self.assertEqual([], dh.get_validated_node_ids())
        mock_remove.assert_called_once()

    @patch('vision.parser.XLinkParser.create_date_time_from_string', return_value=datetime(year=2020, month=10, day=20,
                                                                                           second=0))
    @patch('os.remove')
    @patch('vision.data_handler.request_data_handler.RequestDataHandler._check_active_node', return_value=["mock_id"])
    def test_validate_pota_node_pass(self, mock_nodes, mock_remove, mock_date):
        mock_manifest = _create_mock_ota_manifest()
        mock_registry_mgr = _create_registry_manager(mock_manifest)

        dh = PotaDataHandler(mock_registry_mgr, mock_manifest, ["mock_id"])
        nodes = dh.get_validated_node_ids()

        self.assertEqual(["mock_id"], nodes)
        mock_remove.assert_not_called()

    @patch('os.path.exists', return_value=True)
    @patch('os.path.isfile', return_value=True)
    @patch('os.remove')
    @patch('vision.data_handler.request_data_handler.RequestDataHandler._check_active_node', return_value=["mock_id"])
    def test_pota_validate_fails_os_mismatch(self, get_device, mock_remove, mock_is_file, mock_exists) -> None:
        mock_node = Mock()
        mock_node.os_type = "Windows"

        mock_register_manager = Mock()
        mock_register_manager.get_device = MagicMock(return_value=(mock_node, 1))

        dh = PotaDataHandler(mock_register_manager, PARSED_VALUE, ["mock_id"])

        self.assertEqual([], dh.get_validated_node_ids())
        mock_remove.assert_called_once()

    @patch('os.remove')
    @patch('vision.data_handler.request_data_handler.RequestDataHandler._check_active_node', return_value=["mock_id"])
    def test_fail_validate_pota_manufacturer_mismatch(self, get_device, mock_remove):
        mock_manifest = _create_mock_ota_manifest()

        mock_node = Mock()
        mock_node.manufacturer = "ABC"
        mock_node.boot_fw_vendor = mock_manifest["vendor"]

        mock_register_manager = Mock()
        mock_register_manager.get_device = MagicMock(return_value=(mock_node, 1))

        dh = PotaDataHandler(mock_register_manager, PARSED_VALUE, ["mock_id"])
        self.assertEqual(dh.get_validated_node_ids(), [])
