from unittest import TestCase

from inbm_common_lib.constants import TELEMETRY_CHANNEL, EVENT_CHANNEL, RESPONSE_CHANNEL

from mock import patch, Mock
from node.broker import Broker
from node.constant import *
from node.data_handler import DataHandler


class TestBroker(TestCase):

    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    def test_broker_subscribe_topics(self, m_sub, m_connect, m_start):
        d = TestBroker._build_broker()
        self.assertTrue(m_sub.called)
        self.assertEquals(len(d.mqttc.topics), 5)
        self.assertTrue(STATE_CHANNEL in d.mqttc.topics)
        self.assertTrue(TELEMETRY_CHANNEL in d.mqttc.topics)
        self.assertTrue(EVENT_CHANNEL in d.mqttc.topics)
        self.assertTrue(RESPONSE_CHANNEL in d.mqttc.topics)
        self.assertTrue(CONFIGURATION_RESP_CHANNEL in d.mqttc.topics)

    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    def test_on_command_failed(self, m_pub, m_connect, m_start):
        get_command = '<?xml version="1.0" encoding="utf-8"?>' \
                      '<message>' \
                      '    <isAlive id="ABC123"/>' \
                      '</message>'
        d = TestBroker._build_broker()
        d._on_command('manageability/telemetry', get_command, 1)

    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    def test_on_command_success(self, m_pub, m_connect, m_start):
        get_command = "{\"cmd\": \"g_element\", \"value\": null, \"headers\": \"diagnostic\", " \
                      "\"path\": null, " \
                      "\"id\": \"b5cHpb6HpK42V84GHHeQD2\", \"valueString\": \"{u'minStorageMB': " \
                      "u''}, " \
                      "{u'minMemoryMB': u''}\"}"
        d = TestBroker._build_broker()
        d._on_command('/manageability/telemetry', get_command, 1)

    @patch('node.broker.logger')
    @patch('node.data_handler.DataHandler.receive_mqtt_message', side_effect=ValueError)
    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    def test_on_command_throw_exception(self, m_pub, m_connect, m_start, receive_msg, mock_logger):
        get_command = "{\"cmd\": \"g_element\", \"value\": null, \"headers\": \"diagnostic\", " \
                      "\"path\": null, " \
                      "\"id\": \"b5cHpb6HpK42V84GHHeQD2\", \"valueString\": \"{u'minStorageMB': " \
                      "u''}, " \
                      "{u'minMemoryMB': u''}\"}"
        d = TestBroker._build_broker()
        d._on_command('/manageability/telemetry', get_command, 1)
        mock_logger.error.assert_called_once()

    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    def test_on_result(self, m_pub, m_connect, m_start):
        d = TestBroker._build_broker()
        d._on_result('topic', 'payload', 1)

    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.publish')
    def test_on_message(self, m_pub, m_connect, m_start):
        d = TestBroker._build_broker()
        d._on_message('topic', 'payload', 1)

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    def test_subscription_fails(self, m_sub):
        e = ValueError('abc')
        m_sub.side_effect = e
        self.assertRaises(Exception)

    @patch('node.broker.logger')
    @patch('threading.Thread.start')
    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_vision_lib.mqttclient.mqtt.MQTT.publish', side_effect=Exception("Failed to init broker"))
    def test_init_broker_throw_exception(self, publish, m_connect, t_start, mock_logger):
        Broker(tls=False)
        mock_logger.exception.assert_called_once()

    @staticmethod
    @patch('node.data_handler.DataHandler.load_config_file')
    def _build_broker(load_file):
        mock_node = Mock()
        mock_configmanager = Mock()
        data_handler = DataHandler(mock_node, mock_configmanager)
        return Broker(tls=False, data_handler=data_handler)
