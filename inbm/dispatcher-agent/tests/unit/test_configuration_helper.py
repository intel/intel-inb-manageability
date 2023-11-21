import pytest
from dispatcher.configuration_helper import ConfigurationHelper
from .common.mock_resources import *
from dispatcher.packagemanager import memory_repo
from dispatcher.dispatcher_exception import DispatcherException
from inbm_lib.xmlhandler import XmlHandler
from unittest.mock import patch, MagicMock
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


@pytest.fixture
def setup_xml_handlers():
    mock_callbacks_obj = MockDispatcherCallbacks.build_mock_dispatcher_callbacks()
    mock_dispatcher_broker = MockDispatcherBroker.build_mock_dispatcher_broker()
    good = XmlHandler(GOOD_XML, is_file=False, schema_location=TEST_SCHEMA_LOCATION)
    tar = XmlHandler(TAR_XML, is_file=False, schema_location=TEST_SCHEMA_LOCATION)
    sign_tar = XmlHandler(SIGN_TAR_XML, is_file=False, schema_location=TEST_SCHEMA_LOCATION)
    return mock_callbacks_obj, mock_dispatcher_broker, good, tar, sign_tar


def test_file_download_success(setup_xml_handlers, mocker):
    mock_callbacks_obj, mock_dispatcher_broker, good, tar, sign_tar = setup_xml_handlers
    mock_validate_file = mocker.patch('dispatcher.configuration_helper.validate_file_type')
    mock_xml = mocker.patch('inbm_lib.xmlhandler.XmlHandler.get_children',
                            return_value=GOOD_PARSED_XML)
    mock_fetch = mocker.patch('dispatcher.configuration_helper.get', return_value=dummy_success)
    mock_source = mocker.patch('dispatcher.configuration_helper.verify_source')

    try:
        ConfigurationHelper(mock_callbacks_obj, mock_dispatcher_broker).download_config(good, memory_repo.MemoryRepo(""))
    except DispatcherException:
        pytest.fail("Dispatcher download raised DispatcherException unexpectedly!")


def test_file_download_fetch_fails(setup_xml_handlers, mocker):
    mock_callbacks_obj, mock_dispatcher_broker, good, tar, sign_tar = setup_xml_handlers
    mock_xml = mocker.patch('inbm_lib.xmlhandler.XmlHandler.get_children',
                            return_value=GOOD_PARSED_XML)
    mock_fetch = mocker.patch('dispatcher.configuration_helper.get', return_value=dummy_failure)
    mock_source = mocker.patch('dispatcher.configuration_helper.verify_source')

    with pytest.raises(DispatcherException, match="Configuration File Fetch Failed: {\"status\": 400, "
                       "\"message\": \"FAILED TO INSTALL\"}"):

        ConfigurationHelper(mock_callbacks_obj, mock_dispatcher_broker).download_config(good, memory_repo.MemoryRepo(""))


def test_file_download_xml_fails(setup_xml_handlers, mocker):
    mock_callbacks_obj, mock_dispatcher_broker, good, tar, sign_tar = setup_xml_handlers
    mock_get = mocker.patch('dispatcher.configuration_helper.get',
                            return_value=Result(404, "Not Found"))
    mock_source = mocker.patch('dispatcher.configuration_helper.verify_source')

    with pytest.raises(DispatcherException, match="Configuration File Fetch Failed: {\"status\": 404, "
                       "\"message\": \"Not Found\"}"):
        ConfigurationHelper(mock_callbacks_obj, mock_dispatcher_broker).download_config(good, memory_repo.MemoryRepo(""))


def test_source_verification_fails(setup_xml_handlers, mocker):
    mock_callbacks_obj, mock_dispatcher_broker, good, tar, sign_tar = setup_xml_handlers
    mock_source = mocker.patch('dispatcher.configuration_helper.verify_source',
                               side_effect=DispatcherException('Source verification failed'))

    with pytest.raises(DispatcherException, match='Source verification failed'):
        ConfigurationHelper(mock_callbacks_obj, mock_dispatcher_broker).download_config(good, memory_repo.MemoryRepo(""))


def test_conf_file_name_correct(setup_xml_handlers, mocker):
    mock_callbacks_obj, mock_dispatcher_broker, good, tar, sign_tar = setup_xml_handlers
    mock_validate_file = mocker.patch('dispatcher.configuration_helper.validate_file_type')
    mock_xml = mocker.patch('inbm_lib.xmlhandler.XmlHandler.get_children',
                            return_value=GOOD_PARSED_XML)
    mock_fetch = mocker.patch('dispatcher.configuration_helper.get', return_value=dummy_success)
    mock_source = mocker.patch('dispatcher.configuration_helper.verify_source')

    try:
        conf = ConfigurationHelper(mock_callbacks_obj, mock_dispatcher_broker).download_config(
            good, memory_repo.MemoryRepo(""))
    except DispatcherException:
        pytest.fail("Raised exception when not expected.")
    assert conf == 'tc.xml'


def test_tar_conf_filename_correct(setup_xml_handlers, mocker):
    mock_callbacks_obj, mock_dispatcher_broker, good, tar, sign_tar = setup_xml_handlers

    mock_validate = mocker.patch('dispatcher.configuration_helper.validate_file_type')
    mock_files = mocker.patch(
        'dispatcher.configuration_helper.ConfigurationHelper._extract_files_from_tar')
    mock_xml = mocker.patch('inbm_lib.xmlhandler.XmlHandler.get_children')
    mock_fetch = mocker.patch('dispatcher.configuration_helper.get')
    mock_source = mocker.patch('dispatcher.configuration_helper.verify_source')

    mock_xml.return_value = GOOD_TAR_PARSED_XML
    mock_fetch.return_value = dummy_success
    mock_files.return_value = 'tc.xml'

    try:
        conf = ConfigurationHelper(mock_callbacks_obj, mock_dispatcher_broker).download_config(
            tar, memory_repo.MemoryRepo(""))
    except DispatcherException:
        pytest.fail("Raised exception when not expected.")
    assert conf == 'tc.xml'


def test_tar_conf_with_pem_no_sign_fail(setup_xml_handlers, mocker):
    mock_callbacks_obj, mock_dispatcher_broker, good, tar, sign_tar = setup_xml_handlers

    mock_valid_file = mocker.patch(
        'dispatcher.configuration_helper.os.path.exists', return_value=True)
    mock_validate = mocker.patch('dispatcher.configuration_helper.validate_file_type')
    mock_files = mocker.patch(
        'dispatcher.configuration_helper.ConfigurationHelper._extract_files_from_tar')
    mock_xml = mocker.patch('inbm_lib.xmlhandler.XmlHandler.get_children')
    mock_fetch = mocker.patch('dispatcher.configuration_helper.get')
    mock_source = mocker.patch('dispatcher.configuration_helper.verify_source')

    mock_xml.return_value = GOOD_TAR_PARSED_XML
    mock_fetch.return_value = dummy_success
    mock_files.return_value = 'tc.xml'

    with pytest.raises(DispatcherException, match='Configuration Load Aborted: Signature is required to proceed with the update.'):
        ConfigurationHelper(mock_callbacks_obj, mock_dispatcher_broker).download_config(tar, memory_repo.MemoryRepo(""))


def test_tar_file_download_success(setup_xml_handlers, mocker):
    mock_callbacks_obj, mock_dispatcher_broker, good, tar, sign_tar = setup_xml_handlers

    mock_validate = mocker.patch('dispatcher.configuration_helper.validate_file_type')
    mock_sign = mocker.patch('dispatcher.configuration_helper.verify_signature', result=True)
    mock_files = mocker.patch(
        'dispatcher.configuration_helper.ConfigurationHelper._extract_files_from_tar')
    mock_xml = mocker.patch('inbm_lib.xmlhandler.XmlHandler.get_children')
    mock_fetch = mocker.patch('dispatcher.configuration_helper.get')
    mock_source = mocker.patch('dispatcher.configuration_helper.verify_source')

    mock_xml.return_value = GOOD_SIGN_TAR_PARSED_XML
    mock_fetch.return_value = dummy_success
    mock_files.return_value = 'tc.xml'

    try:
        conf = ConfigurationHelper(mock_callbacks_obj, mock_dispatcher_broker).download_config(
            sign_tar, memory_repo.MemoryRepo(""))
        assert conf == 'tc.xml'
    except DispatcherException:
        pytest.fail("Raised exception when not expected.")


def test_signature_check_fails(setup_xml_handlers, mocker):
    mock_callbacks_obj, mock_dispatcher_broker, good, tar, sign_tar = setup_xml_handlers

    mock_is_file = mocker.patch(
        'dispatcher.configuration_helper.os.path.exists', return_value=True)
    mock_validate = mocker.patch('dispatcher.configuration_helper.validate_file_type')
    mock_parse = mocker.patch(
        'dispatcher.configuration_helper.ConfigurationHelper.parse_url', return_value='')
    mock_children = mocker.patch('inbm_lib.xmlhandler.XmlHandler.get_children')
    mock_get = mocker.patch('dispatcher.configuration_helper.get')
    mock_source = mocker.patch('dispatcher.configuration_helper.verify_source')
    mock_delete = mocker.patch("dispatcher.packagemanager.memory_repo.MemoryRepo.delete")

    mock_get.return_value = Result(status=200, message="OK")

    with pytest.raises(DispatcherException, match='Configuration Load Aborted. Signature check failed'):
        ConfigurationHelper(mock_callbacks_obj, mock_dispatcher_broker).download_config(good, memory_repo.MemoryRepo(""))
        mock_delete.assert_called_once()


def test_extract_files_from_tar(setup_xml_handlers, mocker):
    mock_callbacks_obj, mock_dispatcher_broker, good, tar, sign_tar = setup_xml_handlers

    mock_xml = mocker.patch('inbm_lib.xmlhandler.XmlHandler.get_children',
                            return_value=GOOD_PARSED_XML)
    mock_runner = mocker.patch(
        'inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=('tc.conf', '', 0))

    conf_file = ConfigurationHelper(mock_callbacks_obj, mock_dispatcher_broker)._extract_files_from_tar(
        '/var/cache/manageability/repository/tc.tar')
    assert conf_file == 'tc.conf'


def test_extract_files_from_tar_file_fail(setup_xml_handlers, mocker):
    mock_callbacks_obj, mock_dispatcher_broker, good, tar, sign_tar = setup_xml_handlers

    mock_xml = mocker.patch('inbm_lib.xmlhandler.XmlHandler.get_children',
                            return_value=GOOD_PARSED_XML)
    mock_runner = mocker.patch(
        'inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=('tc.txt', '', 0))

    with pytest.raises(DispatcherException, match='Configuration File Load Error: Invalid File sent. error:'):
        ConfigurationHelper(mock_callbacks_obj, mock_dispatcher_broker)._extract_files_from_tar(
            '/var/cache/manageability/repository/tc.tar')
