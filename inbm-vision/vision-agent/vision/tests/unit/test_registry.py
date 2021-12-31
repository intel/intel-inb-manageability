import datetime
from unittest import TestCase

from vision.registry_manager import Registry, Firmware, Hardware, Status, Security, OperatingSystem
from mock import Mock


class TestRegistry(TestCase):
    def setUp(self):
        self.mock_datetime = Mock()

    def test_create_registry_success(self):
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
                                platform_product="intel",
                                serial_num="c0428202080d709",
                                version="bit-creek-2.13.2-r1.aarch64")
        new_security = Security(dm_verity_enabled=False,
                                measured_boot_enabled=False,
                                is_provisioned=False,
                                is_xlink_secured=False,
                                guid=12345)
        new_status = Status(heartbeat_timestamp=self.mock_datetime)
        new_registry = Registry(device_id="123ABC",
                                firmware=new_firmware,
                                hardware=new_hardware,
                                os=new_os,
                                security=new_security,
                                status=new_status)
        self.assertIsNotNone(new_registry)

    def test_create_registry_fail(self):
        self.assertRaises(TypeError, Registry,
                          (self.mock_datetime, "American Megatrends Inc.", "1.0", "123ABC",
                           self.mock_datetime, "Yocto", "2.5"))
