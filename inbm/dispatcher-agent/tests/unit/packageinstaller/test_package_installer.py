import unittest
from unittest import TestCase

from unit.common.mock_resources import *
from mock import patch

from dispatcher.config_dbs import ConfigDbs
from inbm_lib.trtl import Trtl
from dispatcher.packageinstaller.package_installer import TrtlContainer, \
    INSTALL_SUCCESS, INSTALL_FAILURE
from dispatcher.packageinstaller.package_installer import _is_valid_extension


class MockTrtl(Trtl):

    def __init__(self, smart_error=False, params=None):
        self.rollback_called = False
        self.copy_called = False
        self.stop_called = False
        self.commit_called = False
        self.import_called = False
        self.load_called = False
        self.get_latest_tag_called = False
        self.list_called = False
        self.params = params
        self.__smart_error = smart_error

    def list(self):
        self.list_called = True
        return None, ''

    def snapshot(self, image):
        self.snapshot_called = True
        return "", 0, 0

    def commit(self, image, version):
        self.commit_called = True
        return "", "", 0

    def start(self, image, version, opt=False):
        return "", "", 0

    def rollback(self, in_image, in_version, out_image, out_version):
        self.rollback_called = True
        return "", "", 0

    def stop(self, image, version):
        self.stop_called = True
        return "", "", 0

    def image_import(self, url, image_name):
        self.import_called = True
        return "", "", 0

    def image_load(self, url, image_name):
        self.load_called = True
        return "", "", 0

    def get_latest_tag(self, image):
        self.get_latest_tag_called = True
        return 1, ''


class TestContainerManagement(TestCase):

    @patch('dispatcher.packageinstaller.dbs_checker.DbsChecker.run_docker_security_test')
    def test_return_success_if_valid_import(self, mock_docker_security_test):
        mock_docker_security_test.return_value = "Pass"
        self.__test_import("sample-container:2", False)

    def test_return_fail_if_no_colon_import(self):
        self.__test_import("sample-container", True)

    def test_return_fail_if_ver_not_int_import(self):
        self.__test_import("sample-container:a", True)

    @patch('dispatcher.packageinstaller.dbs_checker.DbsChecker.run_docker_security_test')
    def test_return_success_if_valid_load(self, mock_docker_security_test):
        mock_docker_security_test.return_value = "Pass"
        self.__test_load("sample-container", False)

    def __test_import(self, image_name, smart_fail_stderr=False):
        mock_trtl = MockTrtl(smart_error=smart_fail_stderr)
        container = TrtlContainer(mock_trtl, image_name, MockDispatcher.build_mock_dispatcher(),
                                  ConfigDbs.ON)
        result = container.image_import("repo")
        if smart_fail_stderr:
            self.assertEqual(result, INSTALL_FAILURE)
        else:
            self.assertEqual(result, INSTALL_SUCCESS)

    def __test_load(self, image_name, smart_fail_stderr=False):
        mock_trtl = MockTrtl(smart_error=smart_fail_stderr)
        container = TrtlContainer(mock_trtl, image_name, MockDispatcher.build_mock_dispatcher(),
                                  ConfigDbs.ON)
        result = container.image_load("repo")
        if smart_fail_stderr:
            self.assertEqual(result, INSTALL_FAILURE)
        else:
            self.assertEqual(result, INSTALL_SUCCESS)

    def test_extract_ext_success(self):
        self.assertEquals(_is_valid_extension("abc.deb"), True)
        self.assertEquals(_is_valid_extension("abc.rpm"), True)

    def test_extract_ext_fail(self):
        self.assertEquals(_is_valid_extension("abc.abc"), False)


if __name__ == '__main__':
    unittest.main()
