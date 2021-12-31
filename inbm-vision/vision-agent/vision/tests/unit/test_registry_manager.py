
from datetime import datetime
from unittest import TestCase

from vision.constant import *
from vision.data_handler.idata_handler import IDataHandler
from vision.registry_manager import RegistryManager
from mock import Mock, patch

mock_node_info = {'bootFwDate': "2018-10-9", 'bootFwVersion': '1.5.9',
                  'bootFwVendor': 'Dell Inc.', 'osType': 'Linux',
                  'osVersion': 'Ubuntu 16.04.6 LTS',
                  'osReleaseDate': '2020-7-9',
                  'manufacturer': 'Dell Inc.',
                  'dmVerityEnabled': False,
                  'measuredBootEnabled': None,
                  'flashless': 'false',
                  'is_xlink_secure': False,
                  'stepping': 'A0',
                  'sku': '3400VE',
                  'model': 'Intel Keem Bay HDDL2',
                  'product': 'intel',
                  'serialNumber': 'c0428202080d709',
                  'version': 'bit-creek-2.13.2-r1.aarch64',
                  'guid': None,
                  'is_provisioned': False}

mock_node_id_one = '000732767ffb-17629184'
mock_node_id_two = '000732767ffb-17825792'
mock_guid = 12345


class TestRegistryManager(TestCase):

    @patch('inbm_vision_lib.timer.Timer.start')
    def setUp(self, mock_start):
        mock_data_handler: IDataHandler = Mock()
        self.new_registry_manager = RegistryManager(data_handler=mock_data_handler)

        self.mock_heartbeat_timestamp = Mock()

        self.mock_registry = Mock()
        self.mock_registry.device_id = "example_deviceID"
        self.mock_registry.status.heartbeat_retries = 0
        self.mock_registry.status.heartbeat_timestamp = self.mock_heartbeat_timestamp

        self.mock_vision = Mock()
        self.mock_vision.send_node_register_response
        self.mock_vision.create_telemetry_event

        self.assertEqual(mock_start.call_count, 2)

    def test_init(self):
        self.assertIsNotNone(self.new_registry_manager)

    @patch('vision.registry_manager.RegistryManager.get_device', return_value=(None, None))
    @patch('inbm_vision_lib.timer.Timer.start')
    def test_add(self, t_start, g_device):
        new_registry_manager = RegistryManager(data_handler=self.mock_vision)
        new_registry_manager.add(mock_node_info, mock_node_id_one)
        self.assertEqual(t_start.call_count, 2)
        g_device.assert_called_once()
        self.mock_vision.send_node_register_response.assert_called_once()
        self.mock_vision.create_telemetry_event.assert_called_once()
        self.assertIsNotNone(new_registry_manager)
        self.assertEquals(len(new_registry_manager._registries), 1)

    def test_get_all_active_nodes(self):
        self.new_registry_manager.add(mock_node_info, mock_node_id_one)
        self.new_registry_manager.add(mock_node_info, mock_node_id_two)
        targets = self.new_registry_manager._get_all_active_nodes()
        self.assertEqual(len(targets), 2)

    def test_get_target_ids(self):
        self.new_registry_manager.add(mock_node_info, mock_node_id_one)
        self.new_registry_manager.add(mock_node_info, mock_node_id_two)
        targets = ['000732767ffb-17629184', '000732767ffb-17825792']
        self.assertEqual(self.new_registry_manager.get_target_ids(targets), targets)

    @patch('vision.registry_manager.RegistryManager.get_device', return_value=(None, None))
    @patch('inbm_vision_lib.timer.Timer.start')
    def test_add_registry_success(self, t_start, g_device):
        new_registry_manager = RegistryManager(data_handler=self.mock_vision)
        new_registry_manager._add_registry(self.mock_registry)
        self.assertEqual(t_start.call_count, 2)
        g_device.assert_called_once()
        self.mock_vision.send_node_register_response.assert_called_once()
        self.mock_vision.create_telemetry_event.assert_called_once()
        self.assertIsNotNone(new_registry_manager)
        self.assertEquals(len(new_registry_manager._registries), 1)

    @patch('vision.registry_manager.RegistryManager.delete_registry')
    @patch('vision.registry_manager.RegistryManager.get_device', return_value=(Mock(), 0))
    @patch('inbm_vision_lib.timer.Timer.start')
    def test_add_registry_node_exist_in_list(self, t_start, g_device, delete_reg):
        new_registry_manager = RegistryManager(data_handler=self.mock_vision)
        new_registry_manager._add_registry(self.mock_registry)
        self.assertEqual(t_start.call_count, 2)
        g_device.assert_called_once()
        delete_reg.assert_called_once()
        self.assertIsNotNone(new_registry_manager)
        self.assertEquals(len(new_registry_manager._registries), 1)

    @patch('vision.registry_manager.RegistryManager.get_device', return_value=(Mock(), 0))
    @patch('inbm_vision_lib.timer.Timer.start')
    def test_add_registry_with_different_boot_fw_date_replace_node_exist_in_list(self, t_start, g_device):
        self.mock_registry.boot_fw_date = datetime(year=1, month=1, day=1, second=0)
        new_registry_manager = RegistryManager(data_handler=self.mock_vision)
        new_registry_manager._registries.append(self.mock_registry)
        self.mock_registry.boot_fw_date = datetime(year=2, month=2, day=2, second=0)
        new_registry_manager._add_registry(self.mock_registry)
        self.assertEqual(t_start.call_count, 2)
        g_device.assert_called_once()
        assert self.mock_vision.create_telemetry_event.call_count == 2
        self.assertIsNotNone(new_registry_manager)
        self.assertEquals(len(new_registry_manager._registries), 1)

    @patch('vision.registry_manager.RegistryManager.get_device', return_value=(Mock(), 0))
    @patch('inbm_vision_lib.timer.Timer.start')
    def test_add_registry_with_different_boot_fw_version_replace_node_exist_in_list(self, t_start, g_device):
        self.mock_registry.boot_fw_version = "KMB-BETA"
        new_registry_manager = RegistryManager(data_handler=self.mock_vision)
        new_registry_manager._registries.append(self.mock_registry)
        self.mock_registry.boot_fw_version = "KMB-GOLD2"
        new_registry_manager._add_registry(self.mock_registry)
        self.assertEqual(t_start.call_count, 2)
        g_device.assert_called_once()
        assert self.mock_vision.create_telemetry_event.call_count == 2
        self.assertIsNotNone(new_registry_manager)
        self.assertEquals(len(new_registry_manager._registries), 1)

    @patch('vision.registry_manager.RegistryManager.get_device', return_value=(Mock(), 0))
    @patch('inbm_vision_lib.timer.Timer.start')
    def test_add_registry_with_different_os_version_replace_node_exist_in_list(self, t_start, g_device):
        self.mock_registry.os_version = "1"
        new_registry_manager = RegistryManager(data_handler=self.mock_vision)
        new_registry_manager._registries.append(self.mock_registry)
        self.mock_registry.os_version = "2"
        new_registry_manager._add_registry(self.mock_registry)
        self.assertEqual(t_start.call_count, 2)
        g_device.assert_called_once()
        assert self.mock_vision.create_telemetry_event.call_count == 2
        self.assertIsNotNone(new_registry_manager)
        self.assertEquals(len(new_registry_manager._registries), 1)

    @patch('vision.registry_manager.RegistryManager.get_device', return_value=(Mock(), 0))
    @patch('inbm_vision_lib.timer.Timer.start')
    def test_add_registry_with_different_os_release_date_replace_node_exist_in_list(self, t_start, g_device):
        self.mock_registry.os_release_date = datetime(year=1, month=1, day=1, second=0)
        new_registry_manager = RegistryManager(data_handler=self.mock_vision)
        new_registry_manager._registries.append(self.mock_registry)
        self.mock_registry.os_release_date = datetime(year=2, month=2, day=2, second=0)
        new_registry_manager._add_registry(self.mock_registry)
        self.assertEqual(t_start.call_count, 2)
        g_device.assert_called_once()
        assert self.mock_vision.create_telemetry_event.call_count == 2
        self.assertIsNotNone(new_registry_manager)
        self.assertEquals(len(new_registry_manager._registries), 1)

    def test_delete_registry_success(self):
        self.new_registry_manager._registries = [self.mock_registry]
        self.new_registry_manager.delete_registry(self.mock_registry, 0)
        self.assertIsNotNone(self.new_registry_manager)
        self.assertEquals(len(self.new_registry_manager._registries), 0)

    def test_get_device_success(self):
        self.new_registry_manager._registries = [self.mock_registry]
        return_device, device_index = self.new_registry_manager.get_device("example_deviceID")
        self.assertIsNotNone(self.new_registry_manager, device_index)
        self.assertEquals(len(self.new_registry_manager._registries), 1)
        self.assertIsNotNone(return_device)
        self.assertEquals(self.mock_registry, return_device)

    def test_get_device_fail(self):
        self.new_registry_manager._registries = [self.mock_registry]
        return_device, device_index = self.new_registry_manager.get_device("example_deviceID123")
        self.assertIsNotNone(self.new_registry_manager)
        self.assertEquals(len(self.new_registry_manager._registries), 1)
        self.assertIsNone(return_device, device_index)

    @patch('inbm_vision_lib.timer.Timer.start')
    def test_calculate_time_interval(self, t_start):
        previous_datetime = datetime(year=1, month=1, day=1, second=0)
        current_datetime = datetime(year=1, month=1, day=1, second=10)
        time_interval = self.new_registry_manager._calculate_time_interval(
            previous_datetime, current_datetime)
        self.assertIsNotNone(self.new_registry_manager)
        self.assertEquals(time_interval, 10)

    @patch('vision.registry_manager.RegistryManager._calculate_time_interval',
           return_value=HEARTBEAT_CHECK_INTERVAL - 1)
    def test_is_heartbeat_status_active(self, cal):
        self.assertIsNotNone(self.new_registry_manager)
        self.assertTrue(self.new_registry_manager._is_heartbeat_active(Mock()))

    @patch('vision.registry_manager.RegistryManager._calculate_time_interval',
           return_value=HEARTBEAT_CHECK_INTERVAL + 1)
    def test_is_heartbeat_status_idle(self, cal):
        self.assertIsNotNone(self.new_registry_manager)
        self.assertFalse(self.new_registry_manager._is_heartbeat_active(Mock()))

    @patch('vision.registry_manager.RegistryManager._update_heartbeat_status')
    @patch('vision.registry_manager.RegistryManager._is_heartbeat_active',
           return_value=True)
    def test_check_heartbeat_active(self, is_hb, upd_hb):
        self.new_registry_manager._registries = [self.mock_registry]
        self.new_registry_manager.check_heartbeat()
        is_hb.assert_called_once()
        upd_hb.assert_called_once()
        self.assertIsNotNone(self.new_registry_manager)

    @patch('vision.registry_manager.RegistryManager._handle_inactive_heartbeat')
    @patch('vision.registry_manager.RegistryManager._is_heartbeat_active', return_value=False)
    def test_check_heartbeat_inactive(self, is_hb, handle_hb):
        self.new_registry_manager._registries = [self.mock_registry]
        self.new_registry_manager.check_heartbeat()
        is_hb.assert_called_once()
        handle_hb.assert_called_once()
        self.assertIsNotNone(self.new_registry_manager)

    @patch('vision.registry_manager.RegistryManager._update_heartbeat_status')
    def test_handle_inactive_heartbeat_add_retries(self, upd_hb):
        self.new_registry_manager._registries = [self.mock_registry]
        self.new_registry_manager._handle_inactive_heartbeat(self.mock_registry)
        upd_hb.assert_called_once()
        self.assertEquals(self.mock_registry.status.heartbeat_retries, 1)
        self.assertIsNotNone(self.new_registry_manager)

    @patch('vision.registry_manager.RegistryManager._update_heartbeat_status')
    @patch('inbm_vision_lib.timer.Timer.start')
    def test_handle_inactive_heartbeat_send_is_alive(self, t_start, upd_hb):
        self.mock_registry.status.heartbeat_retries = 2
        self.mock_vision.send_is_alive
        new_registry_manager = RegistryManager(data_handler=self.mock_vision)
        new_registry_manager._registries = [self.mock_registry]
        new_registry_manager._handle_inactive_heartbeat(self.mock_registry)
        self.assertEqual(t_start.call_count, 3)
        upd_hb.assert_called_once()
        self.mock_vision.send_is_alive.assert_called_once()
        self.assertEquals(self.mock_registry.status.heartbeat_retries, 3)
        self.assertIsNotNone(new_registry_manager)

    def test_check_heartbeat_skip(self):
        self.new_registry_manager.check_heartbeat()
        self.assertEquals(len(self.new_registry_manager._registries), 0)

    @patch('vision.registry_manager.RegistryManager.check_heartbeat')
    @patch('inbm_vision_lib.timer.Timer.start')
    def test_start_heartbeat_timer(self, t_start, manager_check_heartbeat):
        mock_data_handler: IDataHandler = Mock()
        new_registry_manager = RegistryManager(data_handler=mock_data_handler)
        new_registry_manager._start_heartbeat_timer()
        self.assertEqual(t_start.call_count, 3)
        manager_check_heartbeat.assert_called_once()

    @patch('inbm_vision_lib.timer.Timer.stop')
    def test_stop(self, t_stop) -> None:
        self.new_registry_manager.stop()
        self.assertEqual(t_stop.call_count, 2)

    def test_update_heartbeat_status(self):
        self.mock_registry.status.heartbeat_status = "Idle"
        self.new_registry_manager._registries = [self.mock_registry]
        self.new_registry_manager._update_heartbeat_status(self.mock_registry, "Active")
        self.assertEquals(self.mock_registry.status.heartbeat_status, "Active")

    def test_update_heartbeat_timestamp_pass(self):
        self.new_registry_manager._registries = [self.mock_registry]
        self.new_registry_manager.update_heartbeat_timestamp("example_deviceID")

    @patch('inbm_vision_lib.timer.Timer.start')
    def test_update_heartbeat_timestamp_send_reregister_request(self, t_start):
        mock_data_handler: IDataHandler = Mock()
        mock_data_handler.create_telemetry_event
        mock_data_handler.send_reregister_request
        new_registry_manager = RegistryManager(data_handler=mock_data_handler)
        new_registry_manager.update_heartbeat_timestamp("example_deviceID")
        mock_data_handler.create_telemetry_event.assert_called_once()  # type: ignore
        mock_data_handler.send_reregister_request.assert_called_once()  # type: ignore
        self.assertEqual(t_start.call_count, 2)

    @patch('vision.registry_manager.RegistryManager.delete_registry')
    def test_manage_is_alive_response_delete_device(self, del_dv):
        self.mock_registry.status.heartbeat_retries = 4
        self.mock_registry.status.heartbeat_status = HEARTBEAT_IDLE_STATE
        self.new_registry_manager._registries = [self.mock_registry]
        self.new_registry_manager.manage_is_alive_response(self.mock_registry.device_id)
        del_dv.assert_called_once()
        self.assertIsNotNone(self.new_registry_manager)

    @patch('vision.registry_manager.RegistryManager.delete_registry')
    def test_manage_is_alive_response_device_not_found(self, del_dv):
        self.mock_registry.status.heartbeat_retries = 4
        self.mock_registry.status.heartbeat_status = HEARTBEAT_IDLE_STATE
        self.new_registry_manager._registries = [self.mock_registry]
        self.new_registry_manager.manage_is_alive_response("example_deviceID_123")
        del_dv.assert_not_called()
        self.assertIsNotNone(self.new_registry_manager)
