from unittest import TestCase
from unittest.mock import patch, Mock
from diagnostic.broker import Broker
from diagnostic.constants import STATE_CHANNEL, CMD_CHANNEL, CONFIGURATION_UPDATE_CHANNEL, ALL_AGENTS_UPDATE_CHANNEL


class TestBroker(TestCase):

    @patch('threading.Thread.start')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    def test_broker_subscribe_topics(self, m_sub, m_connect, m_thread):
        d = TestBroker._build_broker()
        self.assertTrue(m_sub.called)
        self.assertEqual(len(d._mqttc.topics), 4)
        self.assertTrue(STATE_CHANNEL in d._mqttc.topics)
        self.assertTrue(CMD_CHANNEL in d._mqttc.topics)
        self.assertTrue(CONFIGURATION_UPDATE_CHANNEL in d._mqttc.topics)
        self.assertTrue(ALL_AGENTS_UPDATE_CHANNEL in d._mqttc.topics)

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    def test_broker_stop(self, m_pub, m_connect):
        d = TestBroker._build_broker()
        d.stop()
        self.assertTrue(m_pub.called)

    @patch('threading.Thread.start')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    def test_on_message(self, m_pub, m_connect, m_thread):
        d = TestBroker._build_broker()
        d._on_message('topic', 'payload', 1)

    @staticmethod
    def _build_broker():
        return Broker(tls=False)
