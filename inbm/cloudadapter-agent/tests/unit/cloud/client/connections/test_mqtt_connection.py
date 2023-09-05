"""
Unit tests for MQTTConnection


"""


from cloudadapter.cloud.client.connections.mqtt_connection import MQTTConnection
from cloudadapter.cloud.client.utilities import ProxyConfig, TLSConfig
from cloudadapter.exceptions import (
    ConnectError, DisconnectError, PublishError, AuthenticationError)
from paho.mqtt import client as mqtt
import socket

import unittest
import mock


class TestMQTTConnection(unittest.TestCase):

    @mock.patch('cloudadapter.cloud.client.connections.mqtt_connection.Waiter', autospec=True)
    @mock.patch('cloudadapter.cloud.client.connections.mqtt_connection.mqtt', autospec=True)
    def setUp(self, mock_mqtt, MockWaiter):
        mock_tls_config = mock.create_autospec(TLSConfig).return_value
        mock_proxy_config = mock.create_autospec(ProxyConfig).return_value
        mock_proxy_config.endpoint = ("end.point", 42)
        self.mock_waiter = MockWaiter.return_value
        self.mock_client = mock_mqtt.Client.return_value
        self.mqtt_connection = MQTTConnection(
            username="username",
            hostname="hostname",
            port="1234",
            password="password",
            client_id="client_id",
            tls_config=mock_tls_config,
            proxy_config=mock_proxy_config)

    @mock.patch('cloudadapter.cloud.client.connections.mqtt_connection.Waiter', autospec=True)
    @mock.patch('cloudadapter.cloud.client.connections.mqtt_connection.mqtt', autospec=True)
    def test_no_proxy_config(self, mock_mqtt, MockWaiter):
        mock_tls_config = mock.create_autospec(TLSConfig).return_value
        mock_proxy_config = mock.create_autospec(ProxyConfig).return_value
        mock_proxy_config.endpoint = None
        self.mock_waiter = MockWaiter.return_value
        self.mock_client = mock_mqtt.Client.return_value
        self.mqtt_connection = MQTTConnection(
            username="username",
            hostname="hostname",
            port="1234",
            password="password",
            client_id="client_id",
            tls_config=mock_tls_config,
            proxy_config=mock_proxy_config)

    def test_request_id_generation_succeeds(self):
        r0 = self.mqtt_connection.request_id
        self.mock_client.publish.return_value.rc = mqtt.MQTT_ERR_SUCCESS
        self.mqtt_connection.publish("topic", "payload")
        r1 = self.mqtt_connection.request_id
        assert r0 != r1

    def test_publish_succeeds(self):
        self.mock_client.publish.return_value.rc = mqtt.MQTT_ERR_SUCCESS
        self.mqtt_connection.publish("topic", "payload")
        assert self.mock_client.publish.call_count == 1

    def test_publish_blank_topic_succeeds(self):
        # blank topic is used to disable publishing in our template files
        self.mock_client.publish.return_value.rc = mqtt.MQTT_ERR_SUCCESS
        self.mqtt_connection.publish("", "payload")
        assert self.mock_client.publish.call_count == 0

    def test_publish_with_publish_fail_fails(self):
        self.mock_client.publish.return_value.rc = mqtt.MQTT_ERR_INVAL
        failed = False
        try:
            self.mqtt_connection.publish("topic", "payload")
        except PublishError:
            failed = True

    def test_start_succeeds(self):
        self.mock_client.loop_start.return_value = None
        self.mock_waiter.wait.return_value = mqtt.MQTT_ERR_SUCCESS
        self.mock_client.connect = mock.Mock()

        result = self.mqtt_connection.start()

        assert self.mock_client.connect.call_count == 1
        assert self.mock_client.loop_start.call_count == 1
        assert result is None

    def test_start_with_loop_start_fail_fails(self):
        self.mock_client.loop_start.return_value = mqtt.MQTT_ERR_INVAL
        self.mock_waiter.wait.return_value = mqtt.MQTT_ERR_SUCCESS
        self.mock_client.connect = mock.Mock()

        failed = False
        try:
            self.mqtt_connection.start()
        except ConnectError:
            failed = True
        assert failed

    def test_start_with_connect_auth_fail_fails(self):
        self.mock_client.loop_start.return_value = None
        self.mock_waiter.wait.return_value = mqtt.MQTT_ERR_CONN_REFUSED
        self.mock_client.connect = mock.Mock()

        failed = False
        try:
            self.mqtt_connection.start()
        except AuthenticationError:
            failed = True
        assert failed

    def test_start_with_connect_fail_fails(self):
        self.mock_client.loop_start.return_value = None
        self.mock_waiter.wait.return_value = mqtt.MQTT_ERR_NOT_FOUND
        self.mock_client.connect = mock.Mock()

        failed = False
        try:
            self.mqtt_connection.start()
        except ConnectError:
            failed = True
        assert failed

    def test_start_with_connect_fatal_fail_fails(self):
        self.mock_client.loop_start.return_value = None
        self.mock_waiter.wait.return_value = mqtt.MQTT_ERR_NOT_FOUND
        self.mock_client.connect = mock.Mock()
        self.mock_client.connect.side_effect = socket.error("Error!")

        failed = False
        try:
            self.mqtt_connection.start()
        except ConnectError:
            failed = True
        assert failed

    def test_stop_succeeds(self):
        self.mock_client.loop_stop.return_value = None
        self.mock_client.disconnect.return_value = mqtt.MQTT_ERR_SUCCESS

        result = self.mqtt_connection.stop()

        assert self.mock_client.disconnect.call_count == 1
        assert self.mock_client.loop_stop.call_count == 1
        assert result is None

    def test_stop_with_loop_stop_fail_fails(self):
        self.mock_client.loop_stop.return_value = mqtt.MQTT_ERR_INVAL
        self.mock_client.disconnect.return_value = mqtt.MQTT_ERR_SUCCESS

        failed = False
        try:
            self.mqtt_connection.stop()
        except DisconnectError:
            failed = True
        assert failed

    def test_stop_with_disconnect_fail_fails(self):
        self.mock_client.loop_stop.return_value = None
        self.mock_client.disconnect.return_value = mqtt.MQTT_ERR_CONN_REFUSED

        failed = False
        try:
            self.mqtt_connection.stop()
        except DisconnectError:
            failed = True
        assert failed

    def test_subscribe_succeeds(self):
        self.mqtt_connection.subscribe("topic", lambda: None)

        assert self.mock_client.subscribe.call_count == 1
        assert self.mock_client.message_callback_add.call_count == 1

        args, _ = self.mock_client.subscribe.call_args
        assert ("topic",) == args

    def test_subscribe_blank_topic_succeeds(self):
        # blank topic is used to disable a topic in our config templates
        self.mqtt_connection.subscribe("", lambda: None)

        assert self.mock_client.subscribe.call_count == 0
        assert self.mock_client.message_callback_add.call_count == 0

    def test_connect_resubscribe_succeeds(self):
        callback = mock.Mock()
        self.mqtt_connection.subscribe("topic", callback)

        self.mock_client.loop_start.return_value = None
        self.mock_waiter.wait.return_value = mqtt.MQTT_ERR_SUCCESS
        self.mock_client.connect = mock.Mock()
        self.mqtt_connection.start()

        self.mqtt_connection._on_connect(
            client=self.mock_client,
            userdata={},
            flags={},
            rc=mqtt.MQTT_ERR_SUCCESS
        )

        assert self.mock_client.subscribe.call_count == 2
