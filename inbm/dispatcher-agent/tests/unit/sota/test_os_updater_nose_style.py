import unittest
from typing import Optional
import os
import threading

from ..common.mock_resources import *
from dispatcher.sota.os_factory import SotaOsFactory
from dispatcher.sota.os_updater import DebianBasedUpdater
from dispatcher.sota.sota import SOTA
from dispatcher.packagemanager.memory_repo import MemoryRepo
from dispatcher.sota.command_list import CommandList
from dispatcher.sota.constants import *
from unittest.mock import patch
from inbm_lib.xmlhandler import XmlHandler
from unit.common.mock_resources import *
from dispatcher.sota.constants import *

TEST_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                    '../../../fpm-template/usr/share/dispatcher-agent/'
                                    'manifest_schema.xsd')

# OLD NOSE STYLE TESTS


class TestOsUpdater(unittest.TestCase):
    sota_instance: Optional[SOTA] = None
    sota_instance_packages: Optional[SOTA] = None
    resource = {'': ''}
    mock_disp_obj: Optional[MockDispatcher] = None
    mock_disp_broker: DispatcherBroker = MockDispatcherBroker.build_mock_dispatcher_broker()

    @classmethod
    def setUpClass(cls) -> None:
        cls.mock_disp_obj = MockDispatcher.build_mock_dispatcher()

        assert cls.mock_disp_obj is not None
        parsed = XmlHandler(fake_sota_success, is_file=False, schema_location=TEST_SCHEMA_LOCATION)
        cls.resource = parsed.get_children('ota/type/sota')
        parsed_manifest = {'resource': cls.resource,
                           'callback': cls.mock_disp_obj, 'signature': None, 'hash_algorithm': None,
                           'uri': mock_url, 'repo': TestOsUpdater._build_mock_repo(0), 'username': username,
                           'password': password, 'sota_mode': 'full', 'package_list': '', 'deviceReboot': "no"}
        cls.sota_instance = SOTA(parsed_manifest,
                                 "remote",
                                 cls.mock_disp_broker,
                                 cls.mock_disp_obj._update_logger,
                                 None,
                                 MockInstallCheckService(),
                                 cancel_event=threading.Event(),
                                 snapshot=1)

        parsed_manifest_packages = {'resource': cls.resource,
                                    'callback': cls.mock_disp_obj, 'signature': None, 'hash_algorithm': None,
                                    'uri': mock_url, 'repo': TestOsUpdater._build_mock_repo(0), 'username': username,
                                    'password': password, 'sota_mode': 'full', 'package_list': 'package1,package2', 'deviceReboot': "no"}
        cls.sota_instance_packages = SOTA(parsed_manifest_packages,
                                          "remote",
                                          cls.mock_disp_broker,
                                          cls.mock_disp_obj._update_logger,
                                          None,
                                          MockInstallCheckService(),
                                          cancel_event=threading.Event(),
                                          snapshot=1)

    def test_create_no_download_cmd_with_no_package_list(self) -> None:
        expectedCmd = CommandList(["dpkg --configure -a --force-confdef --force-confold",
                "apt-get -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' -yq -f install",
                "apt-get -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' --with-new-pkgs --no-download --fix-missing -yq upgrade"]).cmd_list
        output = DebianBasedUpdater(package_list=[]).no_download()
 
        assert str(output) == str(expectedCmd)
        
    def test_create_no_download_cmd_with_package_list(self) -> None:
        expectedCmd = CommandList(["dpkg --configure -a --force-confdef --force-confold",
                "apt-get -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' -yq -f install",
                "apt-get -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' --no-download --fix-missing -yq install ubuntu"]).cmd_list
        output = DebianBasedUpdater(package_list=['ubuntu']).no_download()
 
        assert str(output) == str(expectedCmd)
        

    def test_Ubuntu_update(self) -> None:
        assert TestOsUpdater.sota_instance
        TestOsUpdater.sota_instance.factory = SotaOsFactory(
            TestOsUpdater.mock_disp_broker, None, []).get_os('Ubuntu')

        factory = TestOsUpdater.sota_instance.factory
        assert factory
        installer = factory.create_os_updater()

        cmd_list = ["apt-get update",
                    "dpkg-query -f '${binary:Package}\\n' -W",
                    "dpkg --configure -a --force-confdef --force-confold",
                    "apt-get -yq -f -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' install",
                    "apt-get -yq -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' --with-new-pkgs upgrade"]
        x_cmd_list = installer.update_remote_source(mock_url, mock_signature, TestOsUpdater._build_mock_repo(0))

        for (each, expected) in zip(x_cmd_list, cmd_list):
            assert str(each) == str(expected)

    def test_Ubuntu_install(self) -> None:
        assert TestOsUpdater.sota_instance_packages
        TestOsUpdater.sota_instance_packages.factory = SotaOsFactory(
            TestOsUpdater.mock_disp_broker, None, ['package1', 'package2']).get_os('Ubuntu')

        factory = TestOsUpdater.sota_instance_packages.factory
        assert factory
        installer = factory.create_os_updater()

        cmd_list = ["apt-get update",
                    "dpkg-query -f '${binary:Package}\\n' -W",
                    "dpkg --configure -a --force-confdef --force-confold",
                    "apt-get -yq -f -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' install",
                    "apt-get -yq -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' install package1 package2"]
        x_cmd_list = installer.update_remote_source(
            mock_url, mock_signature, TestOsUpdater._build_mock_repo(0))

        for (each, expected) in zip(x_cmd_list, cmd_list):
            assert str(each) == str(expected)

    def test_33_2_kB_used(self) -> None:
        assert TestOsUpdater.sota_instance
        TestOsUpdater.sota_instance.factory = SotaOsFactory(
            TestOsUpdater.mock_disp_broker, None, []).get_os('Ubuntu')
        factory = TestOsUpdater.sota_instance.factory
        assert factory
        TestOsUpdater.sota_instance.installer = factory.create_os_updater()
        actual = DebianBasedUpdater._get_estimated_size_from_apt_get_upgrade(
            "foo\nbar=\nAfter this operation ... 33.2 kB ... used\nbaz")
        expected = 33200.0
        self.assertEqual(actual, expected, '')

    def test_33_2_kB_freed(self) -> None:
        assert TestOsUpdater.sota_instance
        TestOsUpdater.sota_instance.factory = SotaOsFactory(
            TestOsUpdater.mock_disp_broker, None, []).get_os('Ubuntu')
        factory = TestOsUpdater.sota_instance.factory
        assert factory
        TestOsUpdater.sota_instance.installer = factory.create_os_updater()
        actual = DebianBasedUpdater._get_estimated_size_from_apt_get_upgrade(
            "foo\nbar=\nAfter this operation ... 33.2 kB ... freed\nbaz")
        expected = 0
        self.assertEqual(actual, expected, '')

    def test_1_mB_used(self) -> None:
        assert TestOsUpdater.sota_instance
        TestOsUpdater.sota_instance.factory = SotaOsFactory(
            TestOsUpdater.mock_disp_broker, None, []).get_os('Ubuntu')
        factory = TestOsUpdater.sota_instance.factory
        assert factory
        TestOsUpdater.sota_instance.installer = factory.create_os_updater()
        actual = DebianBasedUpdater._get_estimated_size_from_apt_get_upgrade(
            "foo\nbar=\nAfter this operation ... 1 mB ... used\nbaz")
        expected = 1000000.0
        self.assertEqual(actual, expected, '')

    def test_42_gB_used(self) -> None:
        assert TestOsUpdater.sota_instance
        TestOsUpdater.sota_instance.factory = SotaOsFactory(
            TestOsUpdater.mock_disp_broker, None, []).get_os('Ubuntu')
        factory = TestOsUpdater.sota_instance.factory
        assert factory
        TestOsUpdater.sota_instance.installer = factory.create_os_updater()
        actual = DebianBasedUpdater._get_estimated_size_from_apt_get_upgrade(
            "foo\nbar=\nAfter this operation ... 42 gB ... used\nbaz")
        expected = 42000000000.0
        self.assertEqual(actual, expected, '')

    def test_234_3_B_used(self) -> None:
        assert TestOsUpdater.sota_instance
        TestOsUpdater.sota_instance.factory = SotaOsFactory(
            TestOsUpdater.mock_disp_broker, None, []).get_os('Ubuntu')
        factory = TestOsUpdater.sota_instance.factory
        assert factory
        TestOsUpdater.sota_instance.installer = factory.create_os_updater()
        actual = DebianBasedUpdater._get_estimated_size_from_apt_get_upgrade(
            "foo\nbar=\nAfter this operation ... 234.3 B ... used\nbaz")
        expected = 234.3
        self.assertEqual(actual, expected, '')

    def test_bad_input(self) -> None:
        assert TestOsUpdater.sota_instance
        TestOsUpdater.sota_instance.factory = SotaOsFactory(
            TestOsUpdater.mock_disp_broker, None, []).get_os('Ubuntu')
        factory = TestOsUpdater.sota_instance.factory
        assert factory
        TestOsUpdater.sota_instance.installer = factory.create_os_updater()
        actual = DebianBasedUpdater._get_estimated_size_from_apt_get_upgrade(
            "abc\ndef\nghi")
        expected = 0
        self.assertEqual(actual, expected, '')

    @patch('dispatcher.sota.os_updater.YoctoX86_64Updater.update_remote_source')
    def test_Yocto_update(self, mock_yocto_os_update) -> None:
        assert TestOsUpdater.sota_instance
        factory = SotaOsFactory(TestOsUpdater.mock_disp_broker, None, []).get_os('YoctoX86_64')
        assert factory
        installer = factory.create_os_updater()
        assert installer
        installer.update_remote_source(mock_url, mock_signature, TestOsUpdater._build_mock_repo(0))
        mock_yocto_os_update.assert_called_once()

    @staticmethod
    def _build_mock_repo(num_files=0):
        mem_repo = MemoryRepo("test")
        if num_files != 0:
            for i in range(0, num_files):
                mem_repo.add("test" + str(i + 1) + ".rpm", b"0123456789")
        return mem_repo
