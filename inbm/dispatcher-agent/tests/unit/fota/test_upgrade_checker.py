from unittest import TestCase

from ddt import data, ddt, unpack

from ..common import mock_resources
from inbm_lib.xmlhandler import XmlHandler
from dispatcher.fota.os_factory import LinuxFactory
from dispatcher.fota.fota_error import FotaError
from mock import patch
import os

import datetime

TEST_SCHEMA_LOCATION = os.path.join(
    os.path.dirname(__file__),
    '../../../fpm-template/usr/share/dispatcher-agent/'
    'manifest_schema.xsd')


@ddt
class TestOsFactory(TestCase):

    def setUp(self) -> None:
        self.mock_disp_broker_obj = mock_resources.MockDispatcherBroker.build_mock_dispatcher_broker()
        parsed = XmlHandler(
            mock_resources.fake_ota_success,
            is_file=False,
            schema_location=TEST_SCHEMA_LOCATION)
        self.resource = parsed.get_children('ota/type/fota')

    def check_bios_success(self, factory) -> None:
        self.assertEqual('test', factory._platform_info.bios_vendor)
        self.assertEqual('A.B.C.D.E.F', factory._platform_info.bios_version)
        self.assertEqual(
            datetime.datetime.strptime(
                '06/12/2010',
                "%m/%d/%Y"),
            factory._platform_info.bios_release_date)
        self.assertEqual('testmanufacturer', factory._platform_info.platform_mfg)
        self.assertEqual('testproduct', factory._platform_info.platform_product)

    def check_manifest_success(self, factory) -> None:
        self.assertEqual('test', factory._manifest_platform_info.bios_vendor)
        self.assertEqual('A.B.D.E.F', factory._manifest_platform_info.bios_version)
        self.assertEqual(datetime.datetime.strptime('06/12/2017', "%m/%d/%Y"),
                         factory._manifest_platform_info.bios_release_date)
        self.assertEqual('testmanufacturer', factory._manifest_platform_info.platform_mfg)
        self.assertEqual('testproduct', factory._manifest_platform_info.platform_product)

    def check_bios_default(self, factory) -> None:
        self.assertEqual('Unknown', factory._platform_info.bios_vendor)
        self.assertEqual('Unknown', factory._platform_info.bios_version)
        self.assertEqual('Unknown', factory._platform_info.bios_release_date)
        self.assertEqual("", factory._platform_info.platform_mfg)
        self.assertEqual("", factory._platform_info.platform_product)

    def check_manifest_default(self, factory) -> None:
        self.assertEqual('Unknown', factory._manifest_platform_info.bios_vendor)
        self.assertEqual('Unknown', factory._manifest_platform_info.bios_version)
        self.assertEqual('Unknown', factory._manifest_platform_info.bios_release_date)
        self.assertEqual('', factory._manifest_platform_info.platform_mfg)
        self.assertEqual('', factory._manifest_platform_info.platform_product)

    @patch('dispatcher.fota.upgrade_checker.is_dmi_path_exists', return_value=True)
    @patch('dispatcher.fota.upgrade_checker.get_dmi_system_info', return_value=mock_resources.parsed_dmi_unknown_version)
    def test_returns_false_parse_dmi_fails(self, mock_dmi, mock_dmi_exists) -> None:
        factory = LinuxFactory(self.resource,
                               self.mock_disp_broker_obj).create_upgrade_checker()
        self.check_bios_default(factory)
        self.check_manifest_default(factory)

    @patch('distutils.spawn.find_executable', return_value=True)
    @patch('dispatcher.fota.upgrade_checker.is_dmi_path_exists', return_value=True)
    @patch('dispatcher.fota.upgrade_checker.get_dmi_system_info', return_value=mock_resources.parsed_dmi_current)
    def test_fails_when_manifest_parse_fails_and_no_devicetree(self, mock_dmi, mock_dmi_path, mock_find) -> None:
        parsed = XmlHandler(
            mock_resources.fake_ota_invalid,
            is_file=False,
            schema_location=TEST_SCHEMA_LOCATION)
        resource = parsed.get_children('ota/type/fota')

        factory = LinuxFactory(
            resource, self.mock_disp_broker_obj).create_upgrade_checker()
        with self.assertRaisesRegex(FotaError, 'Firmware Update Aborted: either capsule release date is lower than '
                                               'the one on the platform or Manifest vendor name does not match the one '
                                               'on the platform'):
            factory.check()

    @patch('dispatcher.fota.upgrade_checker.is_dmi_path_exists', return_value=True)
    @patch('dispatcher.fota.upgrade_checker.get_dmi_system_info', return_value=mock_resources.parsed_dmi_current)
    def test_fail_with_dmi_manifest_mismatch(self, mock_dmi, mock_dmi_exists) -> None:
        parsed = XmlHandler(mock_resources.fake_ota_fail3, is_file=False,
                            schema_location=TEST_SCHEMA_LOCATION)
        resource = parsed.get_children('ota/type/fota')
        factory = LinuxFactory(
            resource, self.mock_disp_broker_obj).create_upgrade_checker()
        with self.assertRaisesRegex(FotaError, 'Firmware Update Aborted: either capsule release date is lower than '
                                               'the one on the platform or Manifest vendor name does not match the one '
                                               'on the platform'):
            factory.check()

    @patch('dispatcher.fota.upgrade_checker.get_dmi_system_info.is_dmi_path_exists', return_value=True)
    @patch('dispatcher.fota.upgrade_checker.get_dmi_system_info',
           return_value=mock_resources.parsed_dmi_mismatch_product)
    def test_raise_mismatched_product(self, mock_dmi, mock_dmi_exists) -> None:
        parsed = XmlHandler(mock_resources.fake_fota_mismatch_product, is_file=False,
                            schema_location=TEST_SCHEMA_LOCATION)
        resource = parsed.get_children('ota/type/fota')
        factory = LinuxFactory(
            resource, self.mock_disp_broker_obj).create_upgrade_checker()
        with self.assertRaisesRegex(FotaError, 'BIOS is not upgradable. Reason: DMI manufacturer/product check failed'):
            factory.check()

    @patch('dispatcher.fota.upgrade_checker.get_dmi_system_info.is_dmi_path_exists', return_value=True)
    @patch('dispatcher.fota.upgrade_checker.get_dmi_system_info',
           return_value=mock_resources.parsed_dmi_unknown_version)
    def test_fail_with_dmi_error(self, mock_dmi, mock_dmi_exists) -> None:
        parsed = XmlHandler(mock_resources.fake_ota_fail3, is_file=False,
                            schema_location=TEST_SCHEMA_LOCATION)
        resource = parsed.get_children('ota/type/fota')
        factory = LinuxFactory(
            resource, self.mock_disp_broker_obj).create_upgrade_checker()
        with self.assertRaisesRegex(FotaError, 'BIOS is not upgradable. Reason: DMI manufacturer/product check failed'):
            factory.check()

    @patch('dispatcher.fota.upgrade_checker.get_device_tree_system_info',
           return_value=mock_resources.parsed_dmi_unknown_version)
    @patch('dispatcher.fota.upgrade_checker.is_dmi_path_exists', return_value=False)
    def test_use_devicetree_for_check(self, mock_path, mock_devicetree) -> None:
        parsed = XmlHandler(mock_resources.fake_ota_fail3, is_file=False,
                            schema_location=TEST_SCHEMA_LOCATION)
        resource = parsed.get_children('ota/type/fota')
        factory = LinuxFactory(
            resource, self.mock_disp_broker_obj).create_upgrade_checker()
        with self.assertRaisesRegex(FotaError,
                                    "BIOS is not upgradable. Reason: Manufacturer and/or product name check failed"):
            factory.check()
        mock_devicetree.assert_called_once()

    @patch('dispatcher.fota.upgrade_checker.is_dmi_path_exists', return_value=True)
    @patch('dispatcher.fota.upgrade_checker.get_dmi_system_info', return_value=mock_resources.parsed_dmi_current)
    def test_fail_with_different_manufacturer(self, mock_dmi, mock_dmi_path) -> None:
        parsed = XmlHandler(mock_resources.fake_ota_fail3, is_file=False,
                            schema_location=TEST_SCHEMA_LOCATION)
        resource = parsed.get_children('ota/type/fota')

        factory = LinuxFactory(
            resource, self.mock_disp_broker_obj).create_upgrade_checker()
        with self.assertRaisesRegex(FotaError, 'Firmware Update Aborted: either capsule release date is lower than '
                                               'the one on the platform or Manifest vendor name does not match the one '
                                               'on the platform'):
            factory.check()

    @patch('dispatcher.fota.upgrade_checker.is_dmi_path_exists', return_value=True)
    @patch('dispatcher.fota.upgrade_checker.get_dmi_system_info', return_value=mock_resources.parsed_dmi_current)
    def test_fail_with_same_release_date(self, mock_dmi, mock_dmi_exists) -> None:
        parsed = XmlHandler(mock_resources.fake_ota_fail1, is_file=False,
                            schema_location=TEST_SCHEMA_LOCATION)
        resource = parsed.get_children('ota/type/fota')

        factory = LinuxFactory(
            resource, self.mock_disp_broker_obj).create_upgrade_checker()

        with self.assertRaisesRegex(FotaError, "Firmware Update Aborted as this package has already been applied."):
            factory.check()

    @patch('dispatcher.fota.upgrade_checker.is_dmi_path_exists', return_value=True)
    @patch('dispatcher.fota.upgrade_checker.get_dmi_system_info', return_value=mock_resources.parsed_dmi_current)
    def test_fail_with_lower_release_date(self, mock_dmi, mock_dmi_exists) -> None:
        parsed = XmlHandler(mock_resources.fake_ota_fail2, is_file=False,
                            schema_location=TEST_SCHEMA_LOCATION)
        resource = parsed.get_children('ota/type/fota')

        factory = LinuxFactory(
            resource, self.mock_disp_broker_obj).create_upgrade_checker()
        with self.assertRaisesRegex(FotaError, 'Firmware Update Aborted: either capsule release date is lower than '
                                               'the one on the platform or Manifest vendor name does not match the one '
                                               'on the platform'):
            factory.check()

    @patch('dispatcher.fota.upgrade_checker.is_dmi_path_exists', return_value=True)
    @patch('dispatcher.fota.upgrade_checker.get_dmi_system_info', return_value=mock_resources.parsed_dmi_current)
    def test_fail_when_vendor_name_mismatch(self, mock_dmi, mock_dmi_exists) -> None:
        parsed = XmlHandler(mock_resources.fake_ota_fail3, is_file=False,
                            schema_location=TEST_SCHEMA_LOCATION)
        resource = parsed.get_children('ota/type/fota')

        factory = LinuxFactory(
            resource, self.mock_disp_broker_obj).create_upgrade_checker()

        with self.assertRaisesRegex(FotaError, 'Firmware Update Aborted: either capsule release date is lower than '
                                               'the one on the platform or Manifest vendor name does not match the one '
                                               'on the platform'):
            factory.check()

    @patch('dispatcher.fota.upgrade_checker.is_dmi_path_exists', return_value=True)
    @patch('dispatcher.fota.upgrade_checker.get_dmi_system_info', return_value=mock_resources.parsed_dmi_current)
    def test_fail_when_vendor_name_mismatch_and_lower_release_date(self, mock_dmi, mock_dmi_exists) -> None:
        parsed = XmlHandler(mock_resources.fake_ota_fail4, is_file=False,
                            schema_location=TEST_SCHEMA_LOCATION)
        resource = parsed.get_children('ota/type/fota')

        factory = LinuxFactory(
            resource, self.mock_disp_broker_obj).create_upgrade_checker()

        with self.assertRaisesRegex(FotaError, 'Firmware Update Aborted: either capsule release date is lower than '
                                               'the one on the platform or Manifest vendor name does not match the one '
                                               'on the platform'):
            factory.check()

    @patch('dispatcher.fota.upgrade_checker.is_dmi_path_exists', return_value=True)
    @patch('dispatcher.fota.upgrade_checker.get_dmi_system_info', return_value=mock_resources.parsed_dmi_current)
    @patch('dispatcher.common.dispatcher_state.write_dispatcher_state_to_state_file', autospec=True)
    def test_returns_true_upgradable(self, mock_disp_state, mock_dmi, mock_is_dmi) -> None:
        mock_disp_state.return_value = True

        factory = LinuxFactory(self.resource,
                               self.mock_disp_broker_obj).create_upgrade_checker()
        bios_vendor, platform_product = factory.check()
        self.assertEqual(bios_vendor, 'test')
        self.assertEqual(platform_product, 'testproduct')
        self.check_bios_success(factory)
        self.check_manifest_success(factory)
