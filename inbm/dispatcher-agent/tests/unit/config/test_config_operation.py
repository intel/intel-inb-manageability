import os
from unittest import TestCase
from unittest.mock import patch, Mock
from dispatcher.common.result_constants import CONFIG_LOAD_FAIL_WRONG_PATH, CONFIG_LOAD_SUCCESS
from dispatcher.config.config_operation import ConfigOperation

from inbm_lib.xmlhandler import XmlHandler

TEST_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                    '../../../fpm-template/usr/share/dispatcher-agent/'
                                    'manifest_schema.xsd')


class TestConfigOperation(TestCase):
    @patch('dispatcher.config.config_operation.ConfigOperation._request_config_agent')
    @patch('dispatcher.configuration_helper.ConfigurationHelper.parse_url')
    @patch('dispatcher.configuration_helper.ConfigurationHelper.download_config')
    def test_config_load_operation_on_local_path_pass(self,
                                                      mock_download: Mock,
                                                      mock_url: Mock,
                                                      mock_req_conf_func: Mock) -> None:

        xml = '<?xml version="1.0" encoding="UTF-8"?><manifest><type>config</type><config> ' \
              '<cmd>load</cmd><configtype><load><path>/var/cache/manageability/intel.conf</path></load></configtype> ' \
              '</config></manifest> '
        parsed_head = XmlHandler(xml, is_file=False, schema_location=TEST_SCHEMA_LOCATION)
        c = ConfigOperation(dispatcher_broker=Mock())
        # mock_xml_init.return_value = None
        mock_url.return_value = None
        mock_download.return_value = False, None
        mock_req_conf_func.assert_not_called()
        self.assertEqual(CONFIG_LOAD_SUCCESS, c._do_config_install_load(
            parsed_head=parsed_head, xml=xml))
    

    @patch('dispatcher.config.config_operation.ConfigOperation._request_config_agent')
    @patch('dispatcher.configuration_helper.ConfigurationHelper.parse_url')
    @patch('dispatcher.configuration_helper.ConfigurationHelper.download_config')
    def test_config_load_operation_on_local_path_fail(self,
                                                      mock_download: Mock,
                                                      mock_url: Mock,
                                                      mock_req_conf_func: Mock) -> None:

        xml = '<?xml version="1.0" encoding="UTF-8"?><manifest><type>config</type><config> ' \
              '<cmd>load</cmd><configtype><load><path>/var/cache/abc/intel.conf</path></load></configtype> ' \
              '</config></manifest> '
        parsed_head = XmlHandler(xml, is_file=False, schema_location=TEST_SCHEMA_LOCATION)
        c = ConfigOperation(dispatcher_broker=Mock())
        # mock_xml_init.return_value = None
        mock_url.return_value = None
        mock_download.return_value = False, None
        mock_req_conf_func.assert_not_called()
        self.assertEqual(CONFIG_LOAD_FAIL_WRONG_PATH, c._do_config_install_load(
            parsed_head=parsed_head, xml=xml))