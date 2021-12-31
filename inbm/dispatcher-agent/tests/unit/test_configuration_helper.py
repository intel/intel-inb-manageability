from unittest import TestCase
from dispatcher.configuration_helper import ConfigurationHelper
from .common.mock_resources import *
from dispatcher.packagemanager import memory_repo
from dispatcher.dispatcher_exception import DispatcherException
from inbm_lib.xmlhandler import XmlHandler
from mock import patch
import os

from typing import Any

TEST_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                    '../../fpm-template/usr/share/dispatcher-agent/'
                                    'manifest_schema.xsd')

GOOD_XML = '<?xml version="1.0" encoding="UTF-8"?>' \
           '<manifest><type>config</type><config><cmd>load</cmd><configtype><load>' \
           '<fetch>http://u.intel.com:8000/tc.xml</fetch></load>' \
           '</configtype></config></manifest>'

TAR_XML = '<?xml version="1.0" encoding="UTF-8"?>' \
    '<manifest><type>config</type><config><cmd>load</cmd><configtype><load>' \
    '<fetch>http://u.intel.com:8000/tc.tar</fetch></load>' \
    '</configtype></config></manifest>'

SIGN_TAR_XML = '<?xml version="1.0" encoding="UTF-8"?>' \
    '<manifest><type>config</type><config><cmd>load</cmd><configtype><load>' \
    '<fetch>http://u.intel.com:8000/tc.tar</fetch><signature>asgasd</signature></load>' \
    '</configtype></config></manifest>'

GOOD_PARSED_XML = {'fetch': 'http://ubuntu.intel.com:8000/tc.xml'}
GOOD_TAR_PARSED_XML = {'fetch': 'http://ubuntu.intel.com:8000/tc.tar'}
GOOD_SIGN_TAR_PARSED_XML = {'fetch': 'http://ubuntu.intel.com:8000/tc.tar', 'signature': 'asgasd'}


class TestConfigurationHelper(TestCase):

    def setUp(self) -> None:
        self.mock_callbacks_obj = MockDispatcherCallbacks.build_mock_dispatcher_callbacks()
        self.good = XmlHandler(GOOD_XML, is_file=False, schema_location=TEST_SCHEMA_LOCATION)
        self.tar = XmlHandler(TAR_XML, is_file=False, schema_location=TEST_SCHEMA_LOCATION)
        self.sign_tar = XmlHandler(SIGN_TAR_XML, is_file=False,
                                   schema_location=TEST_SCHEMA_LOCATION)

    @patch('dispatcher.configuration_helper.verify_source')
    @patch('dispatcher.configuration_helper.get', return_value=dummy_success)
    @patch('inbm_lib.xmlhandler.XmlHandler.get_children', return_value=GOOD_PARSED_XML)
    @patch('dispatcher.configuration_helper.validate_file_type')
    def test_file_download_success(self, mock_validate_file, mock_xml, mock_fetch, mock_source):
        try:
            ConfigurationHelper(self.mock_callbacks_obj).download_config(
                self.good, memory_repo.MemoryRepo(""))
        except DispatcherException:
            self.fail("Dispatcher download raised DispatcherException unexpectedly!")

    @patch('dispatcher.configuration_helper.verify_source')
    @patch('dispatcher.configuration_helper.get', return_value=dummy_failure)
    @patch('inbm_lib.xmlhandler.XmlHandler.get_children', return_value=GOOD_PARSED_XML)
    def test_file_download_fetch_fails(self, mock_xml, mock_fetch, mock_source):
        with self.assertRaisesRegex(DispatcherException, "Configuration File Fetch Failed: {\"status\": 400, "
                                                         "\"message\": \"FAILED TO INSTALL\"}"):
            ConfigurationHelper(self.mock_callbacks_obj).download_config(
                self.good, memory_repo.MemoryRepo(""))

    @patch('dispatcher.configuration_helper.verify_source')
    @patch('dispatcher.configuration_helper.get', return_value=Result(404, "Not Found"))
    def test_file_download_xml_fails(self, mock_get, mock_source):
        with self.assertRaisesRegex(DispatcherException,
                                    "Configuration File Fetch Failed: {\"status\": 404, "
                                    "\"message\": \"Not Found\"}"):
            ConfigurationHelper(self.mock_callbacks_obj).download_config(
                self.good, memory_repo.MemoryRepo(""))

    @patch('dispatcher.configuration_helper.verify_source', side_effect=DispatcherException('Source verification failed'))
    def test_source_verification_fails(self, mock_source):
        with self.assertRaisesRegex(DispatcherException, 'Source verification failed'):
            ConfigurationHelper(self.mock_callbacks_obj).download_config(
                self.good, memory_repo.MemoryRepo(""))

    @patch('dispatcher.configuration_helper.verify_source')
    @patch('dispatcher.configuration_helper.get', return_value=dummy_success)
    @patch('inbm_lib.xmlhandler.XmlHandler.get_children', return_value=GOOD_PARSED_XML)
    @patch('dispatcher.configuration_helper.validate_file_type')
    def test_conf_file_name_correct(self, mock_validate_file, mock_xml, mock_fetch, mock_source):
        try:
            conf = ConfigurationHelper(self.mock_callbacks_obj).download_config(
                self.good, memory_repo.MemoryRepo(""))
        except DispatcherException:
            self.fail("Raised exception when not expected.")
        self.assertEqual(conf, 'tc.xml')

    @patch('dispatcher.configuration_helper.verify_source')
    @patch('dispatcher.configuration_helper.get')
    @patch('inbm_lib.xmlhandler.XmlHandler.get_children')
    @patch('dispatcher.configuration_helper.ConfigurationHelper._extract_files_from_tar')
    @patch('dispatcher.configuration_helper.validate_file_type')
    def test_tar_conf_filename_correct(self, mock_validate, mock_files, mock_xml, mock_fetch, mock_source):
        mock_xml.return_value = GOOD_TAR_PARSED_XML
        mock_fetch.return_value = dummy_success
        mock_files.return_value = 'tc.xml'

        try:
            conf = ConfigurationHelper(self.mock_callbacks_obj).download_config(
                self.tar, memory_repo.MemoryRepo(""))
        except DispatcherException:
            self.fail("Raised exception when not expected.")
        self.assertEqual(conf, 'tc.xml')

    @patch('dispatcher.configuration_helper.verify_source')
    @patch('dispatcher.configuration_helper.get')
    @patch('inbm_lib.xmlhandler.XmlHandler.get_children')
    @patch('dispatcher.configuration_helper.ConfigurationHelper._extract_files_from_tar')
    @patch('dispatcher.configuration_helper.validate_file_type')
    @patch('dispatcher.configuration_helper.os.path.exists', return_value=True)
    def test_tar_conf_with_pem_no_sign_fail(self, mock_valid_file, mock_validate, mock_files, mock_xml, mock_fetch, mock_source):
        mock_xml.return_value = GOOD_TAR_PARSED_XML
        mock_fetch.return_value = dummy_success
        mock_files.return_value = 'tc.xml'
        with self.assertRaisesRegex(DispatcherException,
                                    'Configuration Load Aborted: Signature is required to proceed with the update.'):
            ConfigurationHelper(self.mock_callbacks_obj).download_config(
                self.tar, memory_repo.MemoryRepo(""))

    @patch('dispatcher.configuration_helper.verify_source')
    @patch('dispatcher.configuration_helper.get')
    @patch('inbm_lib.xmlhandler.XmlHandler.get_children')
    @patch('dispatcher.configuration_helper.ConfigurationHelper._extract_files_from_tar')
    @patch('dispatcher.configuration_helper.verify_signature', result=True)
    @patch('dispatcher.configuration_helper.validate_file_type')
    def test_tar_file_download_success(self, mock_validate, mock_sign, mock_files, mock_xml, mock_fetch, mock_source):
        mock_xml.return_value = GOOD_SIGN_TAR_PARSED_XML
        mock_fetch.return_value = dummy_success
        mock_files.return_value = 'tc.xml'

        try:
            conf = ConfigurationHelper(self.mock_callbacks_obj).download_config(
                self.sign_tar, memory_repo.MemoryRepo(""))
            self.assertEqual(conf, 'tc.xml')
        except DispatcherException:
            self.fail("Raised exception when not expected.")

    @patch("dispatcher.packagemanager.memory_repo.MemoryRepo.delete")
    @patch('dispatcher.configuration_helper.verify_source')
    @patch('dispatcher.configuration_helper.get')
    @patch('inbm_lib.xmlhandler.XmlHandler.get_children')
    @patch('dispatcher.configuration_helper.ConfigurationHelper.parse_url', return_value='')
    @patch('dispatcher.configuration_helper.validate_file_type')
    @patch('dispatcher.configuration_helper.os.path.exists', return_value=True)
    def test_signature_check_fails(self, mock_is_file, mock_validate, mock_parse, mock_children, mock_get, mock_source, mock_delete):
        mock_get.return_value = Result(status=200, message="OK")
        with self.assertRaisesRegex(DispatcherException, 'Configuration Load Aborted. Signature check failed'):
            ConfigurationHelper(self.mock_callbacks_obj).download_config(
                self.good, memory_repo.MemoryRepo(""))
            mock_delete.assert_called_once()

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run')
    @patch('inbm_lib.xmlhandler.XmlHandler.get_children')
    def test_extract_files_from_tar(self, mock_xml: Any, mock_runner: Any) -> None:
        mock_xml.return_value = GOOD_PARSED_XML
        mock_runner.return_value = ('tc.conf', '', 0)
        conf_file = ConfigurationHelper(
            self.mock_callbacks_obj)._extract_files_from_tar(
            '/var/cache/manageability/repository/tc.tar')
        self.assertEqual(conf_file, 'tc.conf')

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run')
    @patch('inbm_lib.xmlhandler.XmlHandler.get_children')
    def test_extract_files_from_tar_file_fail(self, mock_xml, mock_runner):
        mock_xml.return_value = GOOD_PARSED_XML
        mock_runner.return_value = ('tc.txt', '', 0)
        with self.assertRaisesRegex(DispatcherException, 'Configuration File Load Error: Invalid File sent. error:'):
            ConfigurationHelper(self.mock_callbacks_obj)._extract_files_from_tar(
                '/var/cache/manageability/repository/tc.tar')
