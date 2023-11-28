from unittest import TestCase

from mock import patch
from unit.common.mock_resources import *

from dispatcher.dispatcher_exception import DispatcherException
from dispatcher.packageinstaller.dbs_checker import DbsChecker
from .test_package_installer import MockTrtl


class TestDbsChecker(TestCase):
    @patch('dispatcher.packageinstaller.package_installer.TrtlContainer')
    def test_successfully_parse_failed_dbs_results(self, mock_trtl_container):
        mock_trtl = MockTrtl(smart_error=True)
        output = """
    [WARN] 5.2  - Ensure SELinux security options are set, if applicable
    [WARN]      * No SecurityOptions Found: container_name"""
        try:
            result = DbsChecker(MockDispatcherBroker.build_mock_dispatcher_broker(), mock_trtl_container,
                                mock_trtl, "sample-container", 0, ConfigDbs.WARN). \
                _handle_docker_security_test_results(output)
            self.assertEqual('Test results: Failures in: 5.2', result)
        except DispatcherException:
            self.fail('Exception thrown when not expected.')


    @patch('dispatcher.packageinstaller.package_installer.TrtlContainer')
    def test_successfully_parse_success_dbs_results(self, mock_trtl_container):
        mock_trtl = MockTrtl(smart_error=True)
        output = """[INFO] 5.9  - Some text"""
        try:
            result = DbsChecker(MockDispatcherBroker.build_mock_dispatcher_broker(), mock_trtl_container,
                       mock_trtl, "sample-container", 0, ConfigDbs.WARN). \
                _handle_docker_security_test_results(output)
            self.assertEqual('Test results: All Passed', result)
        except DispatcherException:
            self.fail('Exception thrown when not expected.')

    @patch('dispatcher.packageinstaller.package_installer.TrtlContainer')
    def test_find_current_container(self, mock_trtl_container):
        mock_trtl = MockTrtl(smart_error=True)
        container = DbsChecker(MockDispatcherBroker.build_mock_dispatcher_broker(), mock_trtl_container,
                               mock_trtl, "sample-container", 0, ConfigDbs.ON). \
            _find_current_container()
        self.assertEqual(container, None)
