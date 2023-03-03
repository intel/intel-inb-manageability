"""
    MQTT client class which uses the Eclipse Paho client library

    @copyright: Copyright 2017-2023 Intel Corporation All Rights Reserved.
    @license: SPDX-License-Identifier: Apache-2.0
"""

import logging
import os
import ssl

import paho.mqtt.client as mqtt
from typing import Dict, Optional, Callable

from inbm_lib.security_masker import mask_security_info
from inbm_lib.mqttclient.config import DEFAULT_MQTT_CERTS

logger = logging.getLogger(__name__)


class MQTT:
    """MQTT client providing easy-to-use APIs for client connections

    @param client_id: client ID
    @param broker: hostname or IP address of the broker
    @param port: network port of the broker to connect to
    @param keep_alive: Max period in seconds allowed between communications
    @param env_config: True if environment host/port config is preferred to specified
    with broker; default=False
    @param tls: transport level security setting; default=True
    @param ca_certs: certificate authority certification; default=""
    @param client_certs: client certification; default=""
    @param client_keys: keys for the client; default=""
    """
    MQTT_HOST_ENV = "MQTT_HOST"
    MQTT_HOST_PORT_ENV = "MQTT_PORT"
    MQTT_CA_CERTS_ENV = "MQTT_CA_CERTS"
    MQTT_CLIENT_CERTS_ENV = "MQTT_CLIENT_CERTS"
    MQTT_CLIENT_KEYS_ENV = "MQTT_CLIENT_KEYS"

    def __init__(self,
                 client_id: str,
                 broker: str,
                 port: int,
                 keep_alive: int,
                 env_config: bool = False,
                 tls: bool = True,
                 ca_certs: str = str(DEFAULT_MQTT_CERTS),
                 client_certs: Optional[str] = None,
                 client_keys: Optional[str] = None) -> None:
        """Setup MQTT client
        @param client_id: name of client
        @param broker: broker hostname
        @param port: broker port
        @param keep_alive: Maximum period in seconds between communications with the
        broker. If no other messages are being exchanged, this controls the
        rate at which the client will send ping messages to the broker.
        @param env_config: Use environment for config?
        @param tls: Use tls?
        @param ca_certs: Path to ca_certs
        @param client_certs: optional path to client certs
        @param client_keys: optional path to client keys"""

        if env_config:
            mqtt_host = broker if self.MQTT_HOST_ENV not in os.environ \
                else os.environ[self.MQTT_HOST_ENV]

            mqtt_port = port if self.MQTT_HOST_PORT_ENV not in os.environ \
                else int(os.environ[self.MQTT_HOST_PORT_ENV])

            mqtt_ca_certs = ca_certs if self.MQTT_CA_CERTS_ENV not in os.environ \
                else os.environ[self.MQTT_CA_CERTS_ENV]

            mqtt_client_certs = client_certs if self.MQTT_CLIENT_CERTS_ENV not in os.environ \
                else os.environ[self.MQTT_CLIENT_CERTS_ENV]

            mqtt_client_keys = client_keys if self.MQTT_CLIENT_KEYS_ENV not in os.environ \
                else os.environ[self.MQTT_CLIENT_KEYS_ENV]
        else:
            mqtt_host = broker
            mqtt_port = port
            mqtt_ca_certs = ca_certs
            mqtt_client_certs = client_certs
            mqtt_client_keys = client_keys

        try:
            logger.debug('Connecting to MQTT broker: %s on port: %d', mqtt_host, mqtt_port)
            logger.debug('Using MQTT_ca_certs={}, certfile={}, keyfile={}, cert_reqs={}'.
                         format(mqtt_ca_certs, mqtt_client_certs, mqtt_client_keys, ssl.CERT_REQUIRED))

            self._mqttc = mqtt.Client(client_id=client_id)
            if tls:
                cipher = 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:' \
                         'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:' \
                         'ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256'
                self._mqttc.tls_set(mqtt_ca_certs, certfile=mqtt_client_certs, tls_version=ssl.PROTOCOL_TLS,
                                    keyfile=mqtt_client_keys, cert_reqs=ssl.CERT_REQUIRED, ciphers=cipher)
            self._mqttc.connect(mqtt_host, mqtt_port, keep_alive)
            logger.info('Connected to MQTT broker: %s on port: %d', mqtt_host, mqtt_port)
        except mqtt.socket.error:
            logger.error('Ensure MQTT service is running!')
            raise

        self.topics: Dict = {}

    def loop_once(self, timeout: float = 1.0, max_packets: int = 1) -> None:
        """Loop the MQTT client once

        @param timeout: Time in loop
        @param max_packets: Max packets - Default 1
        """
        self._mqttc.loop(timeout=timeout, max_packets=max_packets)

    def start(self) -> None:
        """Start the MQTT client"""
        self._mqttc.loop_start()

    def stop(self) -> None:
        """Stop the MQTT client"""
        self._mqttc.disconnect()
        logger.info('Disconnected from MQTT broker')

        self._mqttc.loop_stop()

    def publish(self, topic: str, payload: str, qos: int = 0, retain: bool = False) -> None:
        """Publish a MQTT message to the specified topic, encoded as utf-8

        @param topic: MQTT topic to publish message on
        @param payload: Payload to be published on topic (str; will be encoded as utf-8)
        @param qos: QoS of the message, 0 by default
        @param retain: Message retention policy, False by default
        """
        assert isinstance(payload, str)
        logger.info('Publishing message: %s on topic: %s with retain: %s',
                    mask_security_info(payload), topic, retain)
        self._mqttc.publish(topic, payload.encode('utf-8'), qos, retain)

    def subscribe(self, topic: str, callback: Callable[[str, str, int], None], qos=0) -> None:
        """Subscribe to an MQTT topic

        @param topic: MQTT topic to publish message on
        @param callback: Callback to call when message is received; 
                         message will be decoded from utf-8
        @param qos: QoS of the message, 0 by default
        """
        if topic in self.topics:
            logger.info('Topic: %s has already been subscribed to')
            return

        def _message_callback(client, userdata, message):
            """Add callback to callback list"""
            callback(message.topic, message.payload.decode(encoding='utf-8', errors='strict'),
                     message.qos)

        self._mqttc.subscribe(topic, qos)
        self._mqttc.message_callback_add(topic, _message_callback)
        self.topics[topic] = callback

    def unsubscribe(self, topic: str) -> None:
        """Unsubscribe from a MQTT topic

        @param topic: The topic to unsubscribe from
        """
        logger.info('Unsubscribe to topic: %s', topic)
        try:
            (code, mid) = self._mqttc.unsubscribe(topic)
        except ValueError as e:
            logger.error(e)
        else:
            if code == 0:
                logger.info('Unsubscribe to topic: %s', topic)
            else:
                logger.debug("Unsubscribe failed: code: %s mid: %s", code, mid)
