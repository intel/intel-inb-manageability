
from unittest import TestCase

from vision.broker import Broker
from vision.constant import *
from inbm_vision_lib.constants import *
from vision.data_handler.data_handler import DataHandler
from mock import patch, Mock


class TestBroker(TestCase):

    @patch('inbm_vision_lib.timer.Timer.start')
    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    def test_broker_subscribe_topics(self, m_sub, m_connect, t_start, timer_start):
        d = TestBroker._build_broker()
        self.assertTrue(m_sub.called)
        self.assertEquals(len(d.mqttc.topics), 7)
        self.assertTrue(STATE_CHANNEL in d.mqttc.topics)
        self.assertTrue(INSTALL_CHANNEL in d.mqttc.topics)
        self.assertTrue(RESTART_CHANNEL in d.mqttc.topics)

    @patch('inbm_vision_lib.timer.Timer.start')
    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    def test_on_message(self, m_pub, m_connect, t_start, timer_start):
        d = TestBroker._build_broker()
        d._on_message('topic', 'payload', 1)

    @patch('inbm_vision_lib.timer.Timer.start')
    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('vision.data_handler.data_handler.DataHandler.receive_restart_request')
    def test_on_restart(self, mock_restart_request, m_pub, m_connect, t_start, timer_start):
        restart_request = '<?xml version="1.0" ' \
            'encoding="utf-8"?><manifest><type>cmd</type><cmd>restart</cmd><restart>' \
            '<targetType>node</targetType><targets><target>node-id1</target><target>node-id2</target><' \
            '/targets></restart></manifest>'
        d = TestBroker._build_broker()
        d._on_restart('ma/request/restart', restart_request, 1)
        mock_restart_request.assert_called_once()

    @patch('inbm_vision_lib.timer.Timer.start')
    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('vision.data_handler.data_handler.DataHandler.receive_mqtt_message')
    def test_on_update_success(self, mock_receive_mqtt_message, m_pub, m_connect, t_start,
                               timer_start):
        update_request = '<?xml version="1.0" ' \
                         'encoding="utf-8"?><manifest><type>ota</type><ota><header><id>sampleId' \
                         '</id><name>Sample FOTA</name><description>Sample FOTA manifest ' \
                         'file</description><type>' \
                         'fota</type><repo>remote</repo></header><type><fota ' \
                         'name="sample"><targets><target>slave-id1' \
                         '</target><target>slave-id2</target><target>vision-id</target></targets' \
                         '>' \
                         '<fetch>http://10.108.50.83/test_files/bmpv2/test-files-1068/mutate' \
                         '-fail-1.0-1.noarch.tar' \
                         '</fetch><biosversion>1.0</biosversion><vendor>American Megatrends ' \
                         'Inc.</vendor>' \
                         '<manufacturer>Default string</manufacturer><product>Default ' \
                         'string</product><releasedate>' \
                         '2018-03-30</releasedate><path>/var/cache/repository-tool</path' \
                         '><tooloptions>' \
                         '/p /b</tooloptions></fota></type></ota></manifest>'
        d = TestBroker._build_broker()
        d._on_ota_update('ma/request/install', update_request, 1)
        mock_receive_mqtt_message.assert_called_once()

    @patch('inbm_vision_lib.timer.Timer.start')
    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('vision.data_handler.data_handler.DataHandler.receive_mqtt_message')
    def test_on_update_fail_on_topic(self, mock_receive_mqtt_message, m_pub, m_connect, t_start,
                                     timer_start):
        update_request = '<?xml version="1.0" ' \
                         'encoding="utf-8"?><manifest><type>ota</type><ota><header><id>sampleId' \
                         '</id><name>Sample FOTA</name><description>Sample FOTA manifest ' \
                         'file</description><type>' \
                         'fota</type><repo>remote</repo></header><type><fota ' \
                         'name="sample"><targets><target>slave-id1' \
                         '</target><target>slave-id2</target><target>vision-id</target></targets' \
                         '>' \
                         '<fetch>http://10.108.50.83/test_files/bmpv2/test-files-1068/mutate' \
                         '-fail-1.0-1.noarch.tar' \
                         '</fetch><biosversion>1.0</biosversion><vendor>American Megatrends ' \
                         'Inc.</vendor>' \
                         '<manufacturer>Default string</manufacturer><product>Default ' \
                         'string</product><releasedate>' \
                         '2018-03-30</releasedate><path>/var/cache/repository-tool</path' \
                         '><tooloptions>' \
                         '/p /b</tooloptions></fota></type></ota></manifest>'
        d = TestBroker._build_broker()
        try:
            d._on_ota_update('ma/request/push', update_request, 1)
        except VisionException as e:
            self.assertRaises(VisionException)
            self.assertEqual(
                str(e), "Unsupported command received: push")
        mock_receive_mqtt_message.assert_not_called()

    @patch('inbm_vision_lib.timer.Timer.start')
    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('vision.data_handler.data_handler.DataHandler.receive_mqtt_message')
    def test_on_update_fail_on_payload(self, mock_receive_mqtt_message, m_pub, m_connect, t_start,
                                       timer_start):
        update_request = None
        d = TestBroker._build_broker()
        d._on_ota_update('ma/request/install', update_request, 1)
        mock_receive_mqtt_message.assert_not_called()
        self.assertRaises(ValueError)

    @patch('inbm_vision_lib.timer.Timer.start')
    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    def test_initialize_broker_fail(self, m_pub, m_connect, t_start, timer_start):
        m_pub.side_effect = Exception('abc')
        d = TestBroker._build_broker()
        self.assertRaises(Exception)

    @patch('inbm_vision_lib.timer.Timer.start')
    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('vision.data_handler.data_handler.DataHandler.manage_configuration_request')
    def test_on_config_update_success(self, mock_manage_req, m_pub, m_connect, t_start,
                                      timer_start):
        get_request = '<?xml version="1.0" ' \
                      'encoding="utf-8"?><manifest><type>config</type><config><cmd>get_element</cmd> ' \
                      '<agent>vision</agent>' \
                      '<configtype><get><path>isAliveTimerSecs</path>' \
                      '</get></configtype></config></manifest>'
        d = TestBroker._build_broker()
        d._on_config_update('ma/configuration/update/get_element', get_request, 1)
        mock_manage_req.assert_called_once()

    @patch('vision.broker.logger')
    @patch('inbm_vision_lib.timer.Timer.start')
    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('vision.data_handler.data_handler.DataHandler.manage_configuration_request', side_effect=ValueError)
    def test_on_config_update_value_error(self, mock_manage_req, m_pub, m_connect, t_start,
                                          timer_start, mock_logger):
        get_request = '<?xml version="1.0" ' \
                      'encoding="utf-8"?><manifest><type>config</type><config><cmd>get_element</cmd> ' \
                      '<agent>vision</agent>' \
                      '<configtype><get><path>isAliveTimerSecs</path>' \
                      '</get></configtype></config></manifest>'
        d = TestBroker._build_broker()
        d._on_config_update('ma/configuration/update/get_element', get_request, 1)
        assert mock_logger.error.call_count == 1

    @patch('vision.broker.logger')
    @patch('inbm_vision_lib.timer.Timer.start')
    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('vision.data_handler.data_handler.DataHandler.receive_mqtt_message', side_effect=ValueError)
    def test_on_ota_update_value_error(self, receive_msg, m_pub, m_connect, t_start,
                                       timer_start,  mock_logger):
        update_request = '<?xml version="1.0" ' \
                         'encoding="utf-8"?><manifest><type>ota</type><ota><header><id>sampleId' \
                         '</id><name>Sample FOTA</name><description>Sample FOTA manifest ' \
                         'file</description><type>' \
                         'fota</type><repo>remote</repo></header><type><fota ' \
                         'name="sample"><targets><target>slave-id1' \
                         '</target><target>slave-id2</target><target>vision-id</target></targets' \
                         '>' \
                         '<fetch>http://10.108.50.83/test_files/bmpv2/test-files-1068/mutate' \
                         '-fail-1.0-1.noarch.tar' \
                         '</fetch><biosversion>1.0</biosversion><vendor>American Megatrends ' \
                         'Inc.</vendor>' \
                         '<manufacturer>Default string</manufacturer><product>Default ' \
                         'string</product><releasedate>' \
                         '2018-03-30</releasedate><path>/var/cache/repository-tool</path' \
                         '><tooloptions>' \
                         '/p /b</tooloptions></fota></type></ota></manifest>'
        d = TestBroker._build_broker()
        d._on_ota_update('ma/request/install', update_request, 1)
        assert mock_logger.error.call_count == 1
        receive_msg.assert_called_once()

    @staticmethod
    @patch('vision.data_handler.data_handler.DataHandler.load_config_file')
    def _build_broker(load_file):
        mock_vision_agent = Mock()
        mock_configmanager = Mock()
        data_handler = DataHandler(mock_vision_agent, mock_configmanager)
        return Broker(tls=False, data_handler=data_handler)
