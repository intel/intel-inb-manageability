import datetime
import os
from typing import Any
from unittest import TestCase

from unittest.mock import Mock, patch
from dispatcher.dispatcher import WindowsDispatcherService
from unit.common.mock_resources import *

from dispatcher.aota.aota_error import AotaError
from dispatcher.common.result_constants import PUBLISH_SUCCESS, CODE_OK, CODE_BAD_REQUEST
from dispatcher.dispatcher_class import Dispatcher
from dispatcher.dispatcher_exception import DispatcherException
from dispatcher.ota_thread import AotaThread
from dispatcher.install_check_service import InstallCheckService
from dispatcher.ota_util import create_ota_resource_list

from inbm_common_lib.platform_info import PlatformInformation

TEST_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                    '../../fpm-template/usr/share/dispatcher-agent/'
                                    'manifest_schema.xsd')
TEST_JSON_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                         '../../fpm-template/usr/share/dispatcher-agent/'
                                         'config_param_schema.json')

date_time = datetime.datetime(
    2006,
    12,
    1,
    0,
    0)

devicetree_parsed_1 = PlatformInformation(datetime.datetime(2006, 12, 1, 0, 0),
                                          'innotek GmbH',
                                          'VirtualBox',
                                          'innotek GmbH',
                                          'VirtualBox')

dmi_parsed_1 = PlatformInformation(date_time, 'innotek GmbH',
                                   'VirtualBox', 'innotek GmbH', 'VirtualBox')
dmi_unknown = PlatformInformation()


@patch('dispatcher.dispatcher_class.get_log_config_path',
       return_value=os.path.join(os.path.dirname(__file__),
                                 '../../fpm-template/etc/intel-manageability/public/dispatcher-agent/logging.ini'))
class TestDispatcher(TestCase):

    @patch('dispatcher.ota_thread.AotaThread.start')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('dispatcher.dispatcher_class.Dispatcher._send_result')
    def test_invalid_command(self,
                             mock_send_result: Any,
                             m_sub: Any,
                             m_connect: Any,
                             m_thread_start: Any,
                             mock_logging: Any) -> None:
        xml = '<?xml version="1.0" encoding="UTF-8"?>' \
              '<manifest><type>ota</type><ota><header><id>sampleId</id><name>Sample FOTA</name><description>' \
              'Sample FOTA manifest file</description><type>aota</type><repository>remote</repository>' \
              '<bundle>0</bundle></header><type><aota name="sample.rpm"><fetch>http://www.example.com/</fetch>' \
              '<version>1.0</version><signature>abcd</signature><containerTag>defg</containerTag>' \
              '</aota></type></ota></manifest>'
        d = TestDispatcher._build_dispatcher()
        result_code = d.do_install(xml=xml, schema_location=TEST_SCHEMA_LOCATION).status
        self.assertEqual(result_code, 300)
        assert not m_thread_start.called

    @patch('dispatcher.ota_thread.AotaThread.start')
    @patch('dispatcher.dispatcher_class.Dispatcher._do_ota_update')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('dispatcher.dispatcher_class.Dispatcher._send_result')
    @patch('dispatcher.dispatcher_class.Dispatcher.invoke_workload_orchestration_check')
    def test_pre_check_pass(self,
                            mock_workload_orchestration_func: Any,
                            mock_send_result: Any,
                            m_sub: Any,
                            m_connect: Any,
                            m_do_ota_update: Any,
                            m_thread_start: Any,
                            mock_logging: Any) -> None:
        xml = '<?xml version="1.0" encoding="UTF-8"?>' \
              '<manifest><type>ota</type><ota><header><id>sampleId</id><name>Sample AOTA</name><description>' \
              'Sample AOTA manifest file</description><type>aota</type><repo>remote</repo>' \
              '</header><type><aota name="sample.rpm"><cmd>load</cmd><app>docker</app><fetch>http://www.example.com/</fetch>' \
              '<version>1.0</version><containerTag>defg</containerTag>' \
              '</aota></type></ota></manifest>'
        d = TestDispatcher._build_dispatcher()
        d.do_install(xml=xml, schema_location=TEST_SCHEMA_LOCATION)
        mock_workload_orchestration_func.assert_called()
        m_do_ota_update.assert_called_once()
        # assert m_thread_start.called

    @patch('dispatcher.ota_thread.AotaThread.start')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('dispatcher.dispatcher_class.Dispatcher._send_result')
    @patch('dispatcher.dispatcher_class.Dispatcher.invoke_workload_orchestration_check')
    def test_aota_thread_start_called_without_valid_signature(self,
                                                              mock_workload_orchestration_func: Any,
                                                              mock_send_result: Any,
                                                              m_sub: Any,
                                                              m_connect: Any,
                                                              m_thread_start: Any,
                                                              mock_logging: Any) -> None:
        xml = '<?xml version="1.0" encoding="UTF-8"?>' \
              '<manifest><type>ota</type><ota><header><id>sampleId</id><name>Sample AOTA</name><description>' \
              'Sample AOTA manifest file</description><type>aota</type><repo>remote</repo>' \
              '</header><type><aota name="sample.rpm"><cmd>load</cmd><app>docker</app><fetch>http://www.example.com/</fetch>' \
              '<version>1.0</version><containerTag>defg</containerTag><signature>abcdefg</signature><sigversion>384</sigversion>' \
              '</aota></type></ota></manifest>'
        d = TestDispatcher._build_dispatcher()
        d.do_install(xml=xml, schema_location=TEST_SCHEMA_LOCATION)
        mock_workload_orchestration_func.assert_called()
        assert m_thread_start.called

    @patch('dispatcher.ota_thread.AotaThread.start')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('dispatcher.dispatcher_class.Dispatcher._send_result')
    @patch('dispatcher.dispatcher_class.Dispatcher.invoke_workload_orchestration_check')
    def test_aota_thread_start_called_with_signature(self,
                                                     mock_workload_orchestration_func: Any,
                                                     mock_send_result: Any,
                                                     m_sub: Any,
                                                     m_connect: Any,
                                                     m_thread_start: Any,
                                                     mock_logging: Any) -> None:
        xml = '<?xml version="1.0" encoding="UTF-8"?>' \
              '<manifest><type>ota</type><ota><header><id>sampleId</id><name>Sample AOTA</name><description>' \
              'Sample AOTA manifest file</description><type>aota</type><repo>remote</repo>' \
              '</header><type><aota name="sample.rpm"><cmd>load</cmd><app>docker</app><fetch>http://www.example.com/</fetch>' \
              '<version>1.0</version><containerTag>defg</containerTag>' \
              '</aota></type></ota></manifest>'
        d = TestDispatcher._build_dispatcher()
        d.do_install(xml=xml, schema_location=TEST_SCHEMA_LOCATION)
        mock_workload_orchestration_func.assert_called()
        assert m_thread_start.called

    @patch('dispatcher.ota_thread.OtaThread.pre_install_check', return_value=True)
    @patch('dispatcher.ota_thread.OtaThread')
    @patch('os.path.isfile', return_value=False)
    def test_aota_fails_on_no_trtl_framework(self,
                                             mock_trtl_path: Any,
                                             mock_ota_thread: Any,
                                             mock_pre_install_check: Any,
                                             mock_logging: Any) -> None:
        mock_parsed_manifest = Mock()
        mock_dbs = Mock()
        aota = AotaThread('remote', Mock(), UpdateLogger("AOTA", "metadata"), MockInstallCheckService(),
                          mock_parsed_manifest, mock_dbs)
        with self.assertRaisesRegex(AotaError, 'Cannot proceed with the AOTA '):
            aota.start()

    @patch.object(Dispatcher, '_send_result', autospec=True)
    def test_on_cloud_response_with_unicode_succeeds(self, mock_logging, mock_send_result) -> None:
        d = TestDispatcher._build_dispatcher()
        d.update_queue = Mock()
        d.update_queue.full = Mock(return_value=False)
        d.update_queue.full.return_value = False
        d.update_queue.put = Mock()
        d._on_cloud_request('topic', '\xe2\x82\xac', 1)
        assert d.update_queue.put.call_count == 1

    @patch('dispatcher.dispatcher_class.OtaFactory', autospec=True)
    @patch('inbm_lib.xmlhandler.XmlHandler', autospec=True)
    @patch('dispatcher.dispatcher_class.Dispatcher.invoke_workload_orchestration_check')
    def test_do_install_ota_error_result_succeeds(self, mock_workload_orchestration_func, MockXmlHandler,
                                                  MockOtaFactory, mock_logging) -> None:
        parsed_head = MockXmlHandler.return_value
        mock_ota_factory = Mock()
        MockOtaFactory.get_factory.return_value = mock_ota_factory
        mock_parser = mock_ota_factory.create_parser.return_value
        mock_parser.parse.side_effect = AotaError("Error!")

        d = TestDispatcher._build_dispatcher()
        with patch('dispatcher.dispatcher_class._check_type_validate_manifest', return_value=("ota", parsed_head)):
            d._send_result = Mock()  # type: ignore[method-assign]
            d.do_install("<xml></xml>")
            args, _ = d._send_result.call_args
            result, = args

            assert "400" in result

    @patch('inbm_lib.xmlhandler.XmlHandler', autospec=True)
    def test_do_install_pota_do_ota_func_called(self, MockXmlHandler, mock_logging) -> None:
        parsed_head = MockXmlHandler.return_value
        resource = {'fota': ' ', 'sota': ' '}
        d = TestDispatcher._build_dispatcher()
        with patch('dispatcher.dispatcher_class._check_type_validate_manifest', return_value=("ota", parsed_head)):
            d._send_result = Mock()  # type: ignore[method-assign]
            d.do_install("<xml></xml>")
            res = create_ota_resource_list(parsed_head, resource)
            self.assertEqual(list(res.keys()), ['fota', 'sota'])

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('dispatcher.dispatcher_class.Dispatcher._send_result')
    @patch('dispatcher.config.config_operation.ConfigOperation.request_config_agent')
    @patch('dispatcher.dispatcher_class.Dispatcher.invoke_workload_orchestration_check')
    def test_config_set_check_pass(self,
                                   mock_workload_orchestration_func: Any,
                                   mock_request_config_agent: Any,
                                   mock_send_result: Any,
                                   m_sub: Any,
                                   m_connect: Any,
                                   mock_logging: Any) -> None:

        xml = '<?xml version="1.0" encoding="UTF-8"?><manifest><type>config</type><config><cmd>set_element</cmd><configtype><set><path>maxCacheSize:149</path></set></configtype></config></manifest>'
        d = TestDispatcher._build_dispatcher(
            install_check=MockInstallCheckService(install_check=True))
        mock_request_config_agent.return_value = True
        self.assertEqual(200, d.do_install(xml=xml, schema_location=TEST_SCHEMA_LOCATION).status)

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('dispatcher.dispatcher_class.Dispatcher._send_result')
    @patch('dispatcher.config.config_operation.ConfigOperation.request_config_agent')
    @patch('dispatcher.dispatcher_class.Dispatcher.invoke_workload_orchestration_check')
    def test_config_set_check_fail(self,
                                   mock_workload_orchestration_func: Any,
                                   mock_request_config_agent: Any,
                                   mock_send_result: Any,
                                   m_sub: Any,
                                   m_connect: Any,
                                   mock_logging: Any) -> None:

        xml = '<?xml version="1.0" encoding="UTF-8"?><manifest><type>config</type><config><cmd>set_element</cmd><configtype><set><path>"maxCacheSize":"149"</path></set></configtype></config></manifest>'
        d = TestDispatcher._build_dispatcher(
            install_check=MockInstallCheckService(install_check=False))
        mock_request_config_agent.return_value = True
        self.assertEqual(400, d.do_install(xml=xml, schema_location=TEST_SCHEMA_LOCATION).status)

    @patch('dispatcher.dispatcher_class.Dispatcher.invoke_sota')
    @patch('dispatcher.common.dispatcher_state.is_dispatcher_state_file_exists', return_value=True)
    @patch('dispatcher.common.dispatcher_state.consume_dispatcher_state_file',
           return_value={'restart_reason': 'sota_upgrade'})
    def test_dispatcher_state_file_info_sota(self, mock_disp_state_file_exist, mock_consume_disp_file, mock_invoke_sota,
                                             mock_logging) -> None:
        mock_install = MockInstallCheckService()
        d = TestDispatcher._build_dispatcher(install_check=mock_install)
        d.check_dispatcher_state_info()
        self.assertTrue(mock_install.install_check_called())
        mock_invoke_sota.assert_called_once()
    
    @patch('dispatcher.ota_thread.SotaThread.start')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('dispatcher.dispatcher_class.Dispatcher._send_result')
    @patch('dispatcher.schedule.schedule.schedule_update')
    def test_sota_schedule_update(self, mock_schedule, mock_send_result,
                                        m_sub,
                                        m_connect,
                                        m_thread_start,
                                        mock_logging):
        xml = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header>' \
        '<type>sota</type><repo>remote</repo></header><type><sota><cmd logtofile="y">update</cmd>' \
        '<mode>full</mode><deviceReboot>no</deviceReboot>' \
        '<scheduledTime><start>2002-05-30T09:30:10-06:00</start></scheduledTime></sota></type></ota></manifest>'
        d = TestDispatcher._build_dispatcher()
        result = d.do_install(xml=xml, schema_location=TEST_SCHEMA_LOCATION)
        self.assertEqual(200, result.status)
        mock_schedule.assert_called()
        assert m_thread_start.not_called

    @patch('dispatcher.common.dispatcher_state.is_dispatcher_state_file_exists', return_value=True)
    @patch('dispatcher.common.dispatcher_state.consume_dispatcher_state_file', return_value={'abc': 'abc'})
    def test_dispatcher_state_file_info_no_restart_reason(self, mock_disp_state_file_exist, mock_consume_disp_file,
                                                          mock_logging) -> None:
        d = TestDispatcher._build_dispatcher()
        try:
            d.check_dispatcher_state_info()
        except DispatcherException as e:
            self.assertTrue("state file doesn't contain 'restart_reason'" in str(e))

    @patch('dispatcher.dispatcher_class.Dispatcher.invoke_sota')
    @patch('dispatcher.common.dispatcher_state.is_dispatcher_state_file_exists', return_value=True)
    @patch('dispatcher.common.dispatcher_state.consume_dispatcher_state_file',
           return_value={'mender-version': 'abcvdk'})
    def test_dispatcher_state_file_info_sota_without_restart_reason(self, mock_disp_state_file_exist,
                                                                    mock_consume_disp_file, mock_invoke_sota,
                                                                    mock_logging) -> None:
        mock_install = MockInstallCheckService()
        d = TestDispatcher._build_dispatcher(install_check=mock_install)
        d.check_dispatcher_state_info()
        self.assertTrue(mock_install.install_check_called())
        mock_invoke_sota.assert_called_once()

    @patch('dispatcher.dispatcher_class.Dispatcher._send_result')
    @patch('dispatcher.dispatcher_class.is_dmi_path_exists', return_value=True)
    @patch('dispatcher.dispatcher_class.get_dmi_system_info', return_value=dmi_parsed_1)
    @patch('dispatcher.common.dispatcher_state.is_dispatcher_state_file_exists', return_value=True)
    @patch('dispatcher.common.dispatcher_state.consume_dispatcher_state_file',
           return_value={'restart_reason': 'fota', 'bios_version': 'VirtualBox', 'release_date': date_time})
    def test_dispatcher_state_file_info_fota(self, mock_consume_disp_file, mock_disp_state_file_exist, mock_dmi,
                                             mock_dmi_exists, mock_send_result, mock_logging) -> None:
        d = TestDispatcher._build_dispatcher()
        d.check_dispatcher_state_info()
        mock_send_result.assert_called_once_with(
            "FAILED INSTALL: Overall FOTA update failed. Firmware not updated.")

    @patch('dispatcher.dispatcher_class.Dispatcher._send_result')
    @patch('dispatcher.dispatcher_class.is_dmi_path_exists', return_value=True)
    @patch('dispatcher.dispatcher_class.get_dmi_system_info', return_value=dmi_unknown)
    @patch('dispatcher.common.dispatcher_state.is_dispatcher_state_file_exists', return_value=True)
    @patch('dispatcher.common.dispatcher_state.consume_dispatcher_state_file',
           return_value={'restart_reason': 'fota', 'bios_version': 'VirtualBox', 'release_date': date_time})
    def test_dispatcher_state_file_info_fota1(self, mock_consume_disp_file, mock_disp_state_file_exist, mock_dmi,
                                              mock_dmi_exists, mock_send_result, mock_logging) -> None:
        d = TestDispatcher._build_dispatcher()
        d.check_dispatcher_state_info()
        mock_send_result.assert_called_once_with(
            "FOTA INSTALL UNKNOWN: Error gathering BIOS information.")

    @patch('dispatcher.dispatcher_class.Dispatcher._send_result')
    @patch('inbm_common_lib.dmi.is_dmi_path_exists', return_value=False)
    @patch('inbm_common_lib.device_tree.get_device_tree_system_info', return_value=devicetree_parsed_1)
    @patch('dispatcher.common.dispatcher_state.is_dispatcher_state_file_exists', return_value=True)
    @patch('dispatcher.common.dispatcher_state.consume_dispatcher_state_file',
           return_value={'restart_reason': 'fota', 'bios_version': 'VirtualBox', 'release_date': date_time})
    def test_dispatcher_device_tree_called_on_disp_state(self, mock_consume_disp_file, mock_disp_state_file_exist,
                                                         mock_devicetree, mock_dmi_path, mock_send_result,
                                                         mock_logging) -> None:
        d = TestDispatcher._build_dispatcher()
        d.check_dispatcher_state_info()
        mock_send_result.assert_called()

    @patch('dispatcher.dispatcher_class.Dispatcher._do_config_operation')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('dispatcher.dispatcher_class.Dispatcher._send_result')
    @patch('dispatcher.dispatcher_class.Dispatcher.invoke_workload_orchestration_check')
    def test_config_operation_called(self,
                                     mock_workload_orchestration_func: Any,
                                     mock_send_result: Any,
                                     m_sub: Any,
                                     m_connect: Any,
                                     mock_config_func: Any,
                                     mock_logging: Any) -> None:
        xml = '<?xml version="1.0" encoding="UTF-8"?><manifest><type>config</type><config> ' \
              '<cmd>get_element</cmd><configtype><get><path>maxCacheSize</path></get></configtype> ' \
              '</config></manifest> '

        d = TestDispatcher._build_dispatcher()
        d.do_install(xml=xml, schema_location=TEST_SCHEMA_LOCATION)
        mock_workload_orchestration_func.assert_called()
        mock_config_func.assert_called_once()
        mock_config_func.return_value = PUBLISH_SUCCESS
        self.assertEqual(200, d.do_install(xml=xml, schema_location=TEST_SCHEMA_LOCATION).status)

    @patch('dispatcher.dispatcher_class.do_source_command')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('dispatcher.dispatcher_class.Dispatcher._send_result')
    @patch('dispatcher.dispatcher_class.Dispatcher.invoke_workload_orchestration_check')
    def test_do_install_can_call_do_source_command(self,
                                                   mock_workload_orchestration_func: Any,
                                                   mock_send_result: Any,
                                                   m_sub: Any,
                                                   m_connect: Any,
                                                   mock_do_source_command: Any,
                                                   mock_logging: Any) -> None:
        xml = """\
<?xml version="1.0" encoding="utf-8"?>
    <manifest>
        <type>source</type>
        <applicationSource><list/></applicationSource>
    </manifest>"""

        d = TestDispatcher._build_dispatcher()
        mock_do_source_command.return_value = PUBLISH_SUCCESS
        self.assertEqual(200, d.do_install(xml=xml, schema_location=TEST_SCHEMA_LOCATION).status)
        mock_workload_orchestration_func.assert_called()
        mock_do_source_command.assert_called_once()

    def test_abc(self, mock_logging: Any):
        xml = """\
<?xml version="1.0" encoding="utf-8"?>
    <manifest>
        <type>source</type>
        <applicationSource><list/></applicationSource>
    </manifest>"""

        d = TestDispatcher._build_dispatcher()
        d.do_install(xml=xml, schema_location=TEST_SCHEMA_LOCATION)

    @patch('dispatcher.config.config_operation.ConfigOperation._do_config_install_load')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('dispatcher.dispatcher_class.Dispatcher._send_result')
    @patch('dispatcher.dispatcher_class.Dispatcher.invoke_workload_orchestration_check')
    def test_config_load_operation_called(self,
                                          mock_workload_orchestration: Any,
                                          mock_send_result: Any,
                                          m_sub: Any,
                                          m_connect: Any,
                                          mock_install_func: Any,
                                          mock_logging: Any) -> None:
        xml = '<?xml version="1.0" encoding="UTF-8"?><manifest><type>config</type><config> ' \
              '<cmd>load</cmd><configtype><load><fetch>maxCacheSize</fetch></load></configtype> ' \
              '</config></manifest> '

        d = TestDispatcher._build_dispatcher()
        d.do_install(xml=xml, schema_location=TEST_SCHEMA_LOCATION)
        mock_workload_orchestration.assert_called()
        mock_install_func.assert_called_once()
        mock_install_func.return_value = PUBLISH_SUCCESS
        self.assertEqual(200, d.do_install(xml=xml, schema_location=TEST_SCHEMA_LOCATION).status)

    @patch('dispatcher.config.config_operation.ConfigOperation._do_config_install_load')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('dispatcher.dispatcher_class.Dispatcher._send_result')
    @patch('dispatcher.dispatcher_class.Dispatcher.invoke_workload_orchestration_check')
    def test_config_load_operation_called_bad(self,
                                              mock_workload_orchestration: Any,
                                              mock_send_result: Any,
                                              m_sub: Any,
                                              m_connect: Any,
                                              mock_install_func: Any,
                                              mock_logging: Any) -> None:
        xml = '<?xml version="1.0" encoding="UTF-8"?><manifest><type>config</type><config> ' \
              '<cmd>load</cmd><bad>bad</bad><configtype><load><fetch>maxCacheSize</fetch></load></configtype> ' \
              '</config></manifest> '

        d = TestDispatcher._build_dispatcher()
        self.assertIn("Error parsing/validating manifest: XML va", d.do_install(
            xml=xml, schema_location=TEST_SCHEMA_LOCATION).message)

    @patch('dispatcher.dispatcher_class.Dispatcher.invoke_workload_orchestration_check')
    @patch('dispatcher.dispatcher_class.Dispatcher._perform_cmd_type_operation')
    def test_reboot_cmd(self, mock_perform_cmd_type_operation, mock_workload_orchestration, mock_logging) -> None:
        xml = '<?xml version="1.0" encoding="UTF-8"?><manifest><type>cmd</type><cmd>restart</cmd></manifest>'
        d = TestDispatcher._build_dispatcher()
        d.do_install(xml=xml, schema_location=TEST_SCHEMA_LOCATION)
        mock_workload_orchestration.assert_called()
        mock_perform_cmd_type_operation.assert_called_once()

    @patch('dispatcher.dispatcher_class.Dispatcher.invoke_workload_orchestration_check')
    @patch('dispatcher.dispatcher_class.Dispatcher._perform_cmd_type_operation')
    def test_query_cmd(self, mock_perform_cmd_type_operation, mock_workload_orchestration, mock_logging) -> None:
        xml = '<?xml version="1.0" encoding="UTF-8"?><manifest><type>cmd</type><cmd>query</cmd><query><option>status</option></query></manifest>'
        d = TestDispatcher._build_dispatcher()
        d.do_install(xml=xml, schema_location=TEST_SCHEMA_LOCATION).status
        mock_workload_orchestration.assert_called()
        mock_perform_cmd_type_operation.assert_called_once()

    def test_parse_error_invalid_command(self, mock_logging) -> None:
        xml = '<?xml version="1.0" encoding="UTF-8"?><manifest><type>cmd</type><cmd>orange</cmd><orange></orange></manifest>'
        d = TestDispatcher._build_dispatcher()
        status = d.do_install(xml=xml, schema_location=TEST_SCHEMA_LOCATION).status
        self.assertEqual(300, status)

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('dispatcher.dispatcher_class.Dispatcher._send_result')
    @patch('dispatcher.config.config_operation.ConfigOperation.request_config_agent')
    @patch('dispatcher.dispatcher_class.Dispatcher.invoke_workload_orchestration_check')
    def test_config_get_element_fail(self,
                                     mock_workload_orchestration: Any,
                                     mock_request_config_agent: Any,
                                     mock_send_result: Any,
                                     m_sub: Any,
                                     m_connect: Any,
                                     mock_logging: Any) -> None:

        xml = '<?xml version="1.0" encoding="UTF-8"?><manifest><type>config</type><config><cmd>get_element</cmd><configtype><get><path>minPowerPercen</path></get></configtype></config></manifest>'
        d = TestDispatcher._build_dispatcher()
        mock_request_config_agent.side_effect = DispatcherException
        self.assertEqual(400, d.do_install(xml=xml, schema_location=TEST_SCHEMA_LOCATION).status)

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    @patch('dispatcher.dispatcher_class.Dispatcher._send_result')
    @patch('dispatcher.config.config_operation.ConfigOperation.request_config_agent')
    @patch('dispatcher.dispatcher_class.Dispatcher.invoke_workload_orchestration_check')
    def test_config_get_element_pass(self,
                                     mock_workload_orchestration: Any,
                                     mock_request_config_agent: Any,
                                     mock_send_result: Any,
                                     m_sub: Any,
                                     m_connect: Any,
                                     mock_logging: Any) -> None:

        xml = '<?xml version="1.0" encoding="UTF-8"?><manifest><type>config</type><config><cmd>get_element</cmd><configtype><get><path>minPowerPercent</path></get></configtype></config></manifest>'
        d = TestDispatcher._build_dispatcher()
        mock_request_config_agent.return_value = True
        self.assertEqual(200, d.do_install(xml=xml, schema_location=TEST_SCHEMA_LOCATION).status)

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    def test_service_name_prefixed_inbm(self,
                                        m_sub: Any,
                                        m_connect: Any,
                                        mock_logging: Any) -> None:

        d = WindowsDispatcherService([])
        self.assertFalse(' ' in d._svc_name_)
        self.assertEqual(d._svc_name_.split('-')[0], 'inbm')

    @staticmethod
    def _build_dispatcher(install_check: InstallCheckService = MockInstallCheckService()) -> Dispatcher:
        d = Dispatcher([], MockDispatcherBroker.build_mock_dispatcher_broker(),
                       install_check)
        d._update_logger = Mock()
        return d
