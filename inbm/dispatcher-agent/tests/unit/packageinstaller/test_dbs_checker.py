from unittest import TestCase

from mock import patch
from unit.common.mock_resources import *

from dispatcher.dispatcher_exception import DispatcherException
from dispatcher.packageinstaller.dbs_checker import DbsChecker
from .test_package_installer import MockTrtl


class TestDbsChecker(TestCase):
    @patch('dispatcher.packageinstaller.package_installer.TrtlContainer')
    def test_return_build_result_success(self, mock_trtl_container):
        mock_trtl = MockTrtl(smart_error=True)
        success_flag = True
        result = "Test results: "
        fails = "Failures in: "
        try:
            DbsChecker(MockDispatcherBroker.build_mock_dispatcher_broker(), mock_trtl_container,
                       mock_trtl, "sample-container", 0, ConfigDbs.WARN). \
                _return_build_result(success_flag, result, fails,
                                     failed_images=[], failed_containers=[])
        except DispatcherException:
            self.fail('Exception thrown when not expected.')

    @patch('dispatcher.packageinstaller.package_installer.TrtlContainer')
    def test_return_build_result_fail(self, mock_trtl_container):
        mock_trtl = MockTrtl(smart_error=True)
        success_flag = False
        result = "Test results: "
        fails = "Failures in: 5.3, 5.4"
        failed_images = ['123', '234']
        failed_containers = ['456']
        with self.assertRaisesRegex(DispatcherException, "Test results: Failures in: 5.3, 5.4"):
            DbsChecker(MockDispatcherBroker.build_mock_dispatcher_broker(), mock_trtl_container,
                       mock_trtl, "sample-container", 0, ConfigDbs.ON). \
                _return_build_result(success_flag, result, fails, failed_images, failed_containers)

    @patch('dispatcher.packageinstaller.package_installer.TrtlContainer')
    def test_find_current_container(self, mock_trtl_container):
        mock_trtl = MockTrtl(smart_error=True)
        container = DbsChecker(MockDispatcherBroker.build_mock_dispatcher_broker(), mock_trtl_container,
                               mock_trtl, "sample-container", 0, ConfigDbs.ON). \
            _find_current_container()
        self.assertEqual(container, None)
