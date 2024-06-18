import unittest
from unittest import TestCase

from unittest.mock import patch, ANY, Mock
from inbm_lib.mqttclient.mqtt import MQTT


class TestMQTT(TestCase):

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client')
    def test_client_creation(self, m_client: Mock) -> None:
        MQTT('id', 'broker', 1, 1, tls=False)
        m_client.assert_called_with(client_id='id')

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    def test_client_connection(self, m_client: Mock) -> None:
        MQTT('id', 'broker', 1, 1, tls=False)
        m_client.assert_called_with('broker', 1, 1)

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.disconnect')
    def test_client_stop(self, m_disconnect: Mock, m_connect: Mock) -> None:
        mqtt = MQTT('id', 'broker', 1, 1, tls=False)
        mqtt.stop()
        m_disconnect.assert_called_with()

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    def test_client_publish(self, m_publish: Mock, m_connect: Mock) -> None:
        mqtt = MQTT('id', 'broker', 1, 1, tls=False)
        mqtt.publish('test', 'test')
        m_publish.assert_called_with('test', b'test', ANY, ANY)

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    def test_client_subscribe(self, m_subscribe: Mock, m_connect: Mock) -> None:
        mqtt = MQTT('id', 'broker', 1, 1, tls=False)

        def callback(topic: str, msg: bytes, qos: int) -> None:
            pass
        mqtt.subscribe('test', callback)
        m_subscribe.assert_called_with('test', ANY)
        self.assertTrue('test' in mqtt.topics)


if __name__ == '__main__':
    unittest.main()
