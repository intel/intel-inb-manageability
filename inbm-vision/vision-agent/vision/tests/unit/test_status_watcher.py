import datetime
from unittest import TestCase

from vision.status_watcher import StatusWatcher
from vision.data_handler.data_handler import DataHandler
from vision.registry_manager import Registry, Firmware, Hardware, Status, Security, OperatingSystem
from mock import Mock, patch


class TestStatusWatcher(TestCase):

    def setUp(self):
        self.mock_datetime = Mock()
        dt = datetime.datetime(2020, 10, 9)
        new_firmware = Firmware(boot_fw_date=self.mock_datetime,
                                boot_fw_vendor="American Megatrends Inc.",
                                boot_fw_version="1.0")
        new_os = OperatingSystem(os_type="Yocto",
                                 os_version="2.5",
                                 os_release_date=dt)
        new_hardware = Hardware(flashless=False,
                                manufacturer="AMI",
                                platform_type="KEEMBAY",
                                stepping="A0",
                                sku="3400VE",
                                model="Intel Keem Bay HDDL2",
                                serial_num="c0428202080d709",
                                platform_product='intel',
                                version="bit-creek-2.13.2-r1.aarch64")
        new_security = Security(dm_verity_enabled=False,
                                measured_boot_enabled=False,
                                is_provisioned=False,
                                is_xlink_secured=False,
                                guid=12345)
        new_status = Status(heartbeat_timestamp=self.mock_datetime)

        self.r1 = Registry(device_id="123ABC",
                           firmware=new_firmware,
                           hardware=new_hardware,
                           os=new_os,
                           security=new_security,
                           status=new_status)

        self.r2 = Registry(device_id="345DEF",
                           firmware=new_firmware,
                           hardware=new_hardware,
                           os=new_os,
                           security=new_security,
                           status=new_status)

    @patch('inbm_vision_lib.xlink.xlink_library.XLinkLibrary.__init__', return_value=None)
    @patch('inbm_vision_lib.timer.Timer.start')
    @patch('inbm_vision_lib.invoker.Invoker.__init__', return_value=None)
    @patch('vision.registry_manager.RegistryManager.__init__', return_value=None)
    @patch('vision.data_handler.data_handler.DataHandler.send_telemetry_response')
    @patch('vision.data_handler.data_handler.DataHandler.load_config_file')
    def test_get_done_status(self, mock_load, mock_response, mock_registry, mock_invoker, mock_timer, mock_xlink_lib):
        mock_data_handler = DataHandler(Mock(), Mock())
        s = StatusWatcher([self.r1, self.r2], mock_data_handler, 10)
        self.assertFalse(s.is_all_targets_done())
        s.set_done('123ABC')
        s.set_done('345DEF')
        self.assertTrue(s.is_all_targets_done())
        mock_registry.assert_called_once()
        mock_invoker.assert_called_once()
        self.assertEquals(len(s._targets), 2)
