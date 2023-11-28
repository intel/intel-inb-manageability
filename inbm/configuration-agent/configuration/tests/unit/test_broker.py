from typing import Any, Optional, Dict
from unittest import TestCase

from configuration.broker import Broker
from configuration.constants import *
from mock import patch

from configuration.ikeyvaluestore import IKeyValueStore


class TestKeyValueStore(IKeyValueStore):
    def get_element(self, path: str, element_string: Optional[str] = None,
                    is_attribute: bool = False) -> str:
        return ""

    def set_element(self, path: str, value: str = "", value_string: Optional[str] = None,
                    is_attribute: bool = False) -> str:
        return ""

    def load(self, path: str) -> None:
        pass

    def append(self, path: str, value_string: str) -> str:
        return ""

    def remove(self, path: str, value: Optional[str] = None, value_string: Optional[str] = None) -> str:
        return ""

    def get_children(self, path: str) -> Dict[str, str]:
        return {}

    def get_parent(self, child_element: str) -> Optional[str]:
        pass


class TestBroker(TestCase):

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    def test_broker_subscribe_topics(self, m_sub, m_connect) -> None:
        d = TestBroker._build_broker()
        self.assertTrue(m_sub.called)
        self.assertEqual(len(d.mqttc.topics), 2)
        self.assertTrue(STATE_CHANNEL in d.mqttc.topics)
        self.assertTrue(COMMAND_CHANNEL in d.mqttc.topics)

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    def test_broker_stop(self, m_pub, m_connect) -> None:
        d = TestBroker._build_broker()
        d.broker_stop()
        self.assertTrue(m_pub.called)

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    def test_on_message(self, m_pub, m_connect) -> None:
        d = TestBroker._build_broker()
        d._on_message('topic', 'payload', 1)

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('configuration.broker.Broker._execute')
    def test_on_command_success(self, mock_execute, m_pub, m_connect) -> None:
        get_command = "{\"cmd\": \"g_element\", \"value\": null, \"headers\": null, \"path\": null, " \
                      "\"id\": \"b5cHpb6HpK42V84GHHeQD2\", \"valueString\": \"{u'minStorageMB'}\"}"
        d = TestBroker._build_broker()
        d._on_command('/configuration/command/get_element', get_command, 1)
        mock_execute.assert_called_once()

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    @patch('configuration.broker.Broker._execute')
    def test_on_command_throws_error(self, mock_execute, m_pub, m_connect) -> None:
        get_command = "{, \"value\": null, \"headers\": null, \"path\": null, " \
                      " \"valueString\": \"{u'minStorageMB'}\"}"
        d = TestBroker._build_broker()
        d._on_command('/configuration/command/get_element', get_command, 1)
        mock_execute.assert_not_called()
        self.assertRaises(ValueError)

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    def test_execute_invalid_command(self, m_pub: Any, m_connect: Any) -> None:
        get_command = {'cmd': 'element', 'headers': 'diagnostic', 'path': 'telemetry/maxCacheSize',
                       'id': 'YYJcCtA7ZySxdJDP9JPcfN', 'valueString': 'minStorageMB'}
        d = TestBroker._build_broker()
        d._execute(get_command)
        self.assertEqual(m_pub.call_count, 2)

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.connect')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.publish')
    def test_execute_key_error(self, m_pub: Any, m_connect: Any) -> None:
        get_command = {'cmd': 'element', 'headers': 'diagnostic', 'path': 'telemetry/maxCacheSize',
                       'id': 'YYJcCtA7ZySxdJDP9JPcfN',   'valueString': 'minStorageMB'}
        d = TestBroker._build_broker()
        d._execute(get_command)
        self.assertRaises(KeyError)
        self.assertEqual(m_pub.call_count, 2)

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.subscribe')
    def test_subscription_fails(self, m_sub) -> None:
        e = ValueError('abc')
        m_sub.side_effect = e
        self.assertRaises(Exception)

    @staticmethod
    def _build_broker():
        return Broker(TestKeyValueStore(), tls=False)
