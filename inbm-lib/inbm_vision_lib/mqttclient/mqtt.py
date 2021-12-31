"""
    MQTT client class which uses the Eclipse Paho client library

    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""



import logging
import os
import ssl

import paho.mqtt.client as mqtt
from typing import Dict

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

    def __init__(self, client_id, broker, port, keep_alive, env_config=False, tls=True,
                 ca_certs="", client_certs="", client_keys=""):
        """Setup MQTT client"""
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
            self._mqttc = mqtt.Client(client_id=client_id)
            if tls:
                logger.debug("CERTS: {} CERTFILE: {} KEYF: {} CERT_REQ:{}".format(
                    mqtt_ca_certs, mqtt_client_certs, mqtt_client_keys, ssl.CERT_REQUIRED))
                self._mqttc.tls_set(mqtt_ca_certs, certfile=mqtt_client_certs,
                                    keyfile=mqtt_client_keys, cert_reqs=ssl.CERT_REQUIRED)
            self._mqttc.connect(mqtt_host, mqtt_port, keep_alive)
            logger.info('Connected to MQTT broker: %s on port: %d', mqtt_host, mqtt_port)
        except mqtt.socket.error:
            logger.error('Ensure MQTT service is running!')
            raise

        self.topics: Dict = {}

    def loop_once(self, timeout=1.0, max_packets=1):
        """Loop the MQTT client once

        @param timeout: Time in loop
        @param max_packets: Max packets - Default 1
        """
        self._mqttc.loop(timeout=timeout, max_packets=max_packets)

    def start(self):
        """Start the MQTT client"""
        self._mqttc.loop_start()

    def stop(self):
        """Stop the MQTT client"""
        self._mqttc.disconnect()
        logger.info('Disconnected from MQTT broker')

        self._mqttc.loop_stop()

    def publish(self, topic, payload, qos=0, retain=False):
        """Publish a MQTT message to the specified topic, encoded as utf-8

        @param topic: MQTT topic to publish message on
        @param payload: Payload to be published on topic (str; will be encoded as utf-8)
        @param qos: QoS of the message, 0 by default
        @param retain: Message retention policy, False by default
        """
        if not isinstance(payload, str):
            raise Exception("Payload is not in str format.")
        logger.info('Publishing message: %s on topic: %s with retain: %s',
                    payload, topic, retain)
        self._mqttc.publish(topic, payload.encode('utf-8'), qos, retain)

    def subscribe(self, topic, callback, qos=0):
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

    def unsubscribe(self, topic):
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
