"""
Implementation of the Connection interface for MQTT


"""


from typing import Dict, Optional, Any, Callable
from ._connection import Connection
from ..utilities import ProxyConfig, TLSConfig
from ....exceptions import (
    ConnectError, DisconnectError, PublishError, AuthenticationError)
from ....utilities import Waiter
from paho.mqtt import client as mqtt
from paho.mqtt.client import Client
from functools import partial
from threading import RLock
import socket
import socks
import logging
import time as t
import traceback
logger = logging.getLogger(__name__)


class MQTTConnection(Connection):

    def __init__(
            self,
            username: str,
            hostname: str,
            port: str,
            password: Optional[str] = None,
            client_id: Optional[str] = None,
            tls_config: Optional[TLSConfig] = None,
            proxy_config: Optional[ProxyConfig] = None) -> None:
        """Construct a Connection object for MQTT

        @param username:  (str) MQTT username
        @param password:  (str) MQTT password
        @param hostname:  (str) Target broker hostname
        @param port:      (str) Target broker port
        @param client_id: (str) Client ID to use when connecting to broker
        @param tls_config: (TLSConfig) TLS configuration to use
        @param proxy_config: (ProxyConfig) Proxy configuration to use
        """
        self._rid_lock = RLock()
        self._rid = 0

        self._subscribe_lock = RLock()
        self._subscriptions: Dict = {}

        self._connect_waiter = Waiter()
        self._client = self._create_mqtt_client(username, password, hostname, port, client_id)

        if tls_config:
            self._client.tls_set_context(tls_config.context)

        if proxy_config:
            logger.debug("MQTTConnection.__init__ with proxy: endpoint {} ".format(
                str(proxy_config.endpoint)))
            self._set_proxy(proxy_config)

    def _set_proxy(self, config: ProxyConfig) -> None:
        """Set the proxy; this is needed to avoid a pylint recursion error

        @param config: (ProxyConfig) Config to use
        """
        if config.endpoint:
            socks.set_default_proxy(socks.PROXY_TYPE_HTTP, *config.endpoint)
            socket.socket = socks.socksocket  # type: ignore

    def _create_mqtt_client(self, username: str, password: Optional[str], hostname: str, port: str, client_id: Optional[str] = "") -> Client:
        """Create an MQTT client"""
        client = mqtt.Client(client_id=client_id, protocol=mqtt.MQTTv311)
        client.username_pw_set(username, password)
        client.connect = partial(client.connect, host=hostname, port=port)
        client.on_connect = self._on_connect
        client.on_disconnect = self._on_disconnect
        return client

    def _subscribe_all(self) -> None:
        """Subscribe to all collected subscriptions"""
        with self._subscribe_lock:
            for topic, callback in self._subscriptions.items():
                self.subscribe(topic, callback)

    def _on_connect(self, client: Any, userdata: Any, flags: Any, rc: int) -> None:
        """MQTT connect event callback"""
        logger.info("Connected with code: %s", rc)
        if rc == mqtt.MQTT_ERR_SUCCESS:
            self._subscribe_all()
        self._connect_waiter.finish(rc)

    def _on_disconnect(self, client: Any, userdata: Any, rc: int) -> None:
        """MQTT disconnect event callback"""
        logger.info("Disconnected with code: %s", rc)

    @property
    def request_id(self) -> int:
        with self._rid_lock:
            return self._rid

    def start(self) -> None:
        logger.debug("Connecting to the cloud...")

        self._connect_waiter.reset()

        try:  # A lot of different socket errors can happen here
            self._client.connect()
        except Exception as e:
            raise ConnectError(str(e))

        # Set up the MQTT connection thread
        if self._client.loop_start() is not None:
            raise ConnectError("Could not start a new MQTT thread!")

        # Wait for connection result
        connection = self._connect_waiter.wait()
        if not connection == mqtt.MQTT_ERR_SUCCESS:
            self._client.loop_stop()
            if connection in (mqtt.MQTT_ERR_CONN_REFUSED, mqtt.MQTT_ERR_AUTH):
                raise AuthenticationError("Connection refused! Check authentication details.")
            raise ConnectError(f"Connection error, got code: {connection}")

    def stop(self) -> None:
        if not self._client.disconnect() == mqtt.MQTT_ERR_SUCCESS:
            raise DisconnectError("Disconnection error!")
        if not self._client.loop_stop() is None:
            raise DisconnectError("Could not stop the connection thread!")

    def subscribe(self, topic: Optional[str], callback: Callable) -> None:
        def wrapped(client, userdata, message):
            topic = message.topic
            payload = message.payload
            callback(topic, payload)

        with self._subscribe_lock:
            # Attempt to subscribe
            self._client.subscribe(topic)
            self._client.message_callback_add(topic, wrapped)
            # Add to subscriptions for potential resubscribing
            self._subscriptions[topic] = callback

    def publish(self, topic: str, payload: str) -> None:
#        for line in traceback.format_stack():
#            print(line.strip())
        with self._rid_lock:
            self._rid += 1

        logger.info("Publishing to %s: %s", topic, payload if payload else "[Empty string]")

        message = self._client.publish(topic=topic, payload=payload, qos=1)
        message.wait_for_publish()
        if message.rc != mqtt.MQTT_ERR_SUCCESS:
            error = f"Error publishing to MQTT topic, got code: {message.rc}"
            raise PublishError(error)
        t.sleep(1) 
