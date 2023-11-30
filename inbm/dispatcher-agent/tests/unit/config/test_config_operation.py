import os
import pytest
from dispatcher.common.result_constants import CONFIG_LOAD_FAIL_WRONG_PATH, CONFIG_LOAD_SUCCESS
from dispatcher.config.config_operation import ConfigOperation
from inbm_lib.xmlhandler import XmlHandler

TEST_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                    '../../../fpm-template/usr/share/dispatcher-agent/'
                                    'manifest_schema.xsd')

# Parameterize the test function to run it with different inputs and expected outputs
@pytest.mark.parametrize(
    "xml_path, expected_result",
    [
        ('/var/cache/manageability/intel.conf', CONFIG_LOAD_SUCCESS),
        ('/var/cache/abc/intel.conf', CONFIG_LOAD_FAIL_WRONG_PATH),
    ]
)
def test_config_load_operation(mocker, xml_path, expected_result):
    xml = f'<?xml version="1.0" encoding="UTF-8"?><manifest><type>config</type><config>' \
          f'<cmd>load</cmd><configtype><load><path>{xml_path}</path></load></configtype>' \
          f'</config></manifest> '
    parsed_head = XmlHandler(xml, is_file=False, schema_location=TEST_SCHEMA_LOCATION)
    c = ConfigOperation(dispatcher_broker=mocker.Mock())

    mock_download = mocker.patch('dispatcher.configuration_helper.ConfigurationHelper.download_config')
    mock_url = mocker.patch('dispatcher.configuration_helper.ConfigurationHelper.parse_url')
    mock_req_conf_func = mocker.patch('dispatcher.config.config_operation.ConfigOperation.request_config_agent')

    # Set return values for mocked functions
    mock_url.return_value = None
    mock_download.return_value = False, None
    mock_req_conf_func.assert_not_called()

    # Run the test and check the result
    assert expected_result == c._do_config_install_load(parsed_head=parsed_head, xml=xml)