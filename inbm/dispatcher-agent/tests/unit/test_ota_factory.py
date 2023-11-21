from unittest import TestCase

from unit.common.mock_resources import *
from dispatcher.ota_factory import *


class TestOtaFactory(TestCase):

    def setUp(self):
        self.mock_disp_obj = MockDispatcher.build_mock_dispatcher()

    def test_get_factory_fota(self):
        assert type(OtaFactory.get_factory("FOTA", "remote",
                                           self.mock_disp_obj, True,
                                           None,
                                           MockInstallCheckService(),
                                           ConfigDbs.ON)) is FotaFactory

    def test_get_factory_sota(self):
        assert type(OtaFactory.get_factory("SOTA", "remote",
                                           self.mock_disp_obj, True,
                                           None,
                                           MockInstallCheckService(),
                                           ConfigDbs.ON)) is SotaFactory

    def test_get_factory_aota(self):
        assert type(OtaFactory.get_factory("AOTA", "remote",
                                           self.mock_disp_obj, True,
                                           None,
                                           MockInstallCheckService(), ConfigDbs.ON)) is AotaFactory

    def test_raise_error_unsupported_ota(self):
        self.assertRaises(ValueError, OtaFactory.get_factory,
                          "IOTA", "remote", self.mock_disp_obj, True, None, MockInstallCheckService(), True)

    def test_create_fota_parser(self):
        assert type(OtaFactory.get_factory(
            "FOTA", "remote", self.mock_disp_obj, True, None, MockInstallCheckService(), ConfigDbs.ON).create_parser()) is FotaParser

    def test_create_sota_parser(self):
        assert type(OtaFactory.get_factory(
            "SOTA", "remote", self.mock_disp_obj, True, None, MockInstallCheckService(), ConfigDbs.ON).create_parser()) is SotaParser

    def test_create_aota_parser(self):
        assert type(OtaFactory.get_factory(
            "AOTA", "remote", self.mock_disp_obj, True, None, MockInstallCheckService(), ConfigDbs.ON).create_parser()) is AotaParser

    def test_create_fota_thread(self):
        assert type(OtaFactory.get_factory(
            "FOTA", "remote", self.mock_disp_obj, True, None, MockInstallCheckService(), ConfigDbs.ON).create_thread('abc')) is FotaThread

    def test_create_sota_thread(self):
        assert type(OtaFactory.get_factory(
            "SOTA", "remote", self.mock_disp_obj, True, None, MockInstallCheckService(), ConfigDbs.ON).create_thread('abc')) is SotaThread

    def test_create_aota_thread(self):
        assert type(OtaFactory.get_factory(
            "AOTA", "remote", self.mock_disp_obj, True, None, MockInstallCheckService(), ConfigDbs.ON).create_thread('abc')) is AotaThread
