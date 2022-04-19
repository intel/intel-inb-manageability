import unittest
from typing import Optional
import os

from ..common.mock_resources import *
from dispatcher.dispatcher_callbacks import DispatcherCallbacks
from dispatcher.sota.os_factory import ISotaOs, SotaOsFactory
from dispatcher.sota.os_updater import DebianBasedUpdater
from dispatcher.sota.sota import SOTA
from dispatcher.packagemanager.memory_repo import MemoryRepo
from dispatcher.sota.constants import *
from mock import patch
from inbm_lib.xmlhandler import XmlHandler
from unit.common.mock_resources import *
from dispatcher.sota.constants import *

TEST_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                    '../../../fpm-template/usr/share/dispatcher-agent/'
                                    'manifest_schema.xsd')


class TestOsUpdater(unittest.TestCase):
    sota_instance: Optional[SOTA] = None
    resource = {'': ''}
    mock_disp_obj: Optional[MockDispatcher] = None

    @classmethod
    def setUpClass(cls):
        cls.mock_disp_obj = MockDispatcher.build_mock_dispatcher()

        assert cls.mock_disp_obj is not None
        parsed = XmlHandler(fake_sota_success, is_file=False, schema_location=TEST_SCHEMA_LOCATION)
        cls.resource = parsed.get_children('ota/type/sota')
        parsed_manifest = {'resource': cls.resource,
                           'callback': cls.mock_disp_obj, 'signature': None, 'hash_algorithm': None,
                           'uri': mock_url, 'repo': TestOsUpdater._build_mock_repo(0), 'username': username,
                           'password': password}
        cls.sota_instance = SOTA(parsed_manifest, "remote",
                                 DispatcherCallbacks(install_check=cls.mock_disp_obj.install_check,
                                                     broker_core=MockDispatcherBroker.build_mock_dispatcher_broker(),
                                                     sota_repos=cls.mock_disp_obj.sota_repos,
                                                     proceed_without_rollback=cls.mock_disp_obj.proceed_without_rollback),
                                 snapshot=1)

    def test_Ubuntu_update(self):
        assert TestOsUpdater.sota_instance
        TestOsUpdater.sota_instance.factory = SotaOsFactory(
            TestOsUpdater.mock_disp_obj).get_os('Ubuntu')  # type: ignore

        factory = TestOsUpdater.sota_instance.factory
        assert factory
        installer = factory.create_os_updater()

        cmd_list = ["apt-get update",
                    "dpkg-query -f '${binary:Package}\\n' -W",
                    "apt-get -yq upgrade"]
        x_cmd_list = installer.update_remote_source(  # type: ignore
            mock_url, TestOsUpdater._build_mock_repo(0))

        def get_next_index():
            i = 0
            while i < len(x_cmd_list):
                yield i
                i = i + 1

        gen = get_next_index()

        for each in cmd_list:
            expected = x_cmd_list[next(gen)].text
            assert (each == expected)

    def test_33_2_kB_used(self):
        assert TestOsUpdater.sota_instance
        TestOsUpdater.sota_instance.factory = SotaOsFactory(
            TestOsUpdater.mock_disp_obj).get_os('Ubuntu')  # type: ignore
        factory = TestOsUpdater.sota_instance.factory
        assert factory
        TestOsUpdater.sota_instance.installer = factory.create_os_updater()
        actual = DebianBasedUpdater._get_estimated_size_from_apt_get_upgrade(
            "foo\nbar=\nAfter this operation ... 33.2 kB ... used\nbaz")
        expected = 33200.0
        self.assertEqual(actual, expected, '')

    def test_33_2_kB_freed(self):
        assert TestOsUpdater.sota_instance
        TestOsUpdater.sota_instance.factory = SotaOsFactory(
            TestOsUpdater.mock_disp_obj).get_os('Ubuntu')  # type: ignore
        factory = TestOsUpdater.sota_instance.factory
        assert factory
        TestOsUpdater.sota_instance.installer = factory.create_os_updater()
        actual = DebianBasedUpdater._get_estimated_size_from_apt_get_upgrade(
            "foo\nbar=\nAfter this operation ... 33.2 kB ... freed\nbaz")
        expected = 0
        self.assertEqual(actual, expected, '')

    def test_1_mB_used(self):
        assert TestOsUpdater.sota_instance
        TestOsUpdater.sota_instance.factory = SotaOsFactory(
            TestOsUpdater.mock_disp_obj).get_os('Ubuntu')  # type: ignore
        factory = TestOsUpdater.sota_instance.factory
        assert factory
        TestOsUpdater.sota_instance.installer = factory.create_os_updater()
        actual = DebianBasedUpdater._get_estimated_size_from_apt_get_upgrade(
            "foo\nbar=\nAfter this operation ... 1 mB ... used\nbaz")
        expected = 1000000.0
        self.assertEqual(actual, expected, '')

    def test_42_gB_used(self):
        assert TestOsUpdater.sota_instance
        TestOsUpdater.sota_instance.factory = SotaOsFactory(
            TestOsUpdater.mock_disp_obj).get_os('Ubuntu')  # type: ignore
        factory = TestOsUpdater.sota_instance.factory
        assert factory
        TestOsUpdater.sota_instance.installer = factory.create_os_updater()
        actual = DebianBasedUpdater._get_estimated_size_from_apt_get_upgrade(
            "foo\nbar=\nAfter this operation ... 42 gB ... used\nbaz")
        expected = 42000000000.0
        self.assertEqual(actual, expected, '')

    def test_234_3_B_used(self):
        assert TestOsUpdater.sota_instance
        TestOsUpdater.sota_instance.factory = SotaOsFactory(
            TestOsUpdater.mock_disp_obj).get_os('Ubuntu')  # type: ignore
        factory = TestOsUpdater.sota_instance.factory
        assert factory
        TestOsUpdater.sota_instance.installer = factory.create_os_updater()
        actual = DebianBasedUpdater._get_estimated_size_from_apt_get_upgrade(
            "foo\nbar=\nAfter this operation ... 234.3 B ... used\nbaz")
        expected = 234.3
        self.assertEqual(actual, expected, '')

    def test_bad_input(self):
        assert TestOsUpdater.sota_instance
        TestOsUpdater.sota_instance.factory = SotaOsFactory(
            TestOsUpdater.mock_disp_obj).get_os('Ubuntu')  # type: ignore
        factory = TestOsUpdater.sota_instance.factory
        assert factory
        TestOsUpdater.sota_instance.installer = factory.create_os_updater()
        actual = DebianBasedUpdater._get_estimated_size_from_apt_get_upgrade(
            "abc\ndef\nghi")
        expected = 0
        self.assertEqual(actual, expected, '')

    @patch('dispatcher.sota.os_updater.YoctoX86_64Updater.update_remote_source')
    def test_Yocto_update(self, mock_yocto_os_update):
        assert TestOsUpdater.sota_instance
        TestOsUpdater.sota_instance.factory = SotaOsFactory(
            TestOsUpdater.mock_disp_obj).get_os('YoctoX86_64')  # type: ignore
        factory = TestOsUpdater.sota_instance.factory
        assert factory
        TestOsUpdater.sota_instance.installer = factory.create_os_updater()
        installer = TestOsUpdater.sota_instance.installer
        assert installer
        TestOsUpdater.sota_instance.cmd_list = installer.update_remote_source(  # type: ignore
            mock_url, TestOsUpdater._build_mock_repo(0))
        mock_yocto_os_update.assert_called_once()

    @staticmethod
    def _build_mock_repo(num_files=0):
        mem_repo = MemoryRepo("test")
        if num_files != 0:
            for i in range(0, num_files):
                mem_repo.add("test" + str(i + 1) + ".rpm", b"0123456789")
        return mem_repo
