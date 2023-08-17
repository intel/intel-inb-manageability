#!/usr/bin/python

# Copyright (C) 2021-2023 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

# -*- coding: utf-8 -*-

import os
import ssl
import sys
import signal
import time
import paho.mqtt.client as mqtt
from typing import Dict, Optional, Callable

import json
from future import standard_library

standard_library.install_aliases()

CUSTOM_CMD_CHANNEL = "manageability/cmd/custom"
DEFAULT_MQTT_HOST = 'localhost'
DEFAULT_MQTT_PORT = 8883

# Edit the DEFAULT_MQTT_CERTS, CLIENT_CERTS, CLIENT_KEYS to point to the user created directory
# Also modify docker run command in run.sh script by adding ‘-v <your_directory>:/var/certs’. For ex: '-v ~/certs:/var/certs
DEFAULT_MQTT_CERTS = "~/certs/mqtt-ca.crt"
CLIENT_CERTS = "~/certs/cmd-program.crt"
CLIENT_KEYS = "~/certs/cmd-program.key"


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

        mqtt_host = broker
        mqtt_port = port
        mqtt_ca_certs = ca_certs
        mqtt_client_certs = client_certs
        mqtt_client_keys = client_keys

        try:
            print(
                f'Connecting to MQTT broker: {mqtt_host} on port: {mqtt_port}')
            print('Using MQTT_ca_certs={}, certfile={}, keyfile={}, cert_reqs={}'.
                  format(mqtt_ca_certs, mqtt_client_certs, mqtt_client_keys, ssl.CERT_REQUIRED))

            self._mqttc = mqtt.Client(client_id=client_id)
            if tls:
                cipher = 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:' \
                         'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:' \
                         'ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256'
                self._mqttc.tls_set(mqtt_ca_certs, certfile=mqtt_client_certs, tls_version=ssl.PROTOCOL_TLS,
                                    keyfile=mqtt_client_keys, cert_reqs=ssl.CERT_REQUIRED, ciphers=cipher)
            self._mqttc.connect(mqtt_host, mqtt_port, keep_alive)
            print(
                f'Connected to MQTT broker: {mqtt_host} on port: {mqtt_port}')
        except mqtt.socket.error:
            print('Ensure MQTT service is running!')
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
        print('Disconnected from MQTT broker')

        self._mqttc.loop_stop()

    def publish(self, topic: str, payload: str, qos: int = 0, retain: bool = False) -> None:
        """Publish a MQTT message to the specified topic, encoded as utf-8

        @param topic: MQTT topic to publish message on
        @param payload: Payload to be published on topic (str; will be encoded as utf-8)
        @param qos: QoS of the message, 0 by default
        @param retain: Message retention policy, False by default
        """
        assert isinstance(payload, str)
        print(
            f'Publishing message: {payload} on topic: {topic} with retain: {retain}')
        self._mqttc.publish(topic, payload.encode('utf-8'), qos, retain)

    def subscribe(self, topic: str, callback: Callable[[str, str, int], None], qos=0) -> None:
        """Subscribe to an MQTT topic

        @param topic: MQTT topic to publish message on
        @param callback: Callback to call when message is received; 
                         message will be decoded from utf-8
        @param qos: QoS of the message, 0 by default
        """
        if topic in self.topics:
            print(f'Topic: {topic} has already been subscribed to')
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
        print('Unsubscribe to topic: %s', topic)
        try:
            (code, mid) = self._mqttc.unsubscribe(topic)
        except ValueError as e:
            print(e)
        else:
            if code == 0:
                print(f'Unsubscribe to topic: {topic}')
            else:
                print(f"Unsubscribe failed: code: {code} mid: {mid}")


def broker_stop(client: MQTT) -> None:
    """Shut down broker, publishing 'dead' event first.

    @param client: broker client
    """
    client.publish('cmd-program/state', 'dead', retain=True)
    # Disconnect MQTT client
    client.stop()


def broker_init(tls: bool = True, with_docker: bool = False) -> MQTT:
    """Set up generic action for message received; subscribe to state channel; publish
    'running' state

    @return: broker client
    """
    client = MQTT("cmd-program",
                  DEFAULT_MQTT_HOST,
                  DEFAULT_MQTT_PORT,
                  60,
                  env_config=True,
                  tls=tls,
                  client_certs=str(CLIENT_CERTS),
                  client_keys=str(CLIENT_KEYS))
    client.start()

    def on_message(topic, payload, qos):
        print(f'Message received: {payload} on topic: {topic}')
        if topic == CUSTOM_CMD_CHANNEL and 'running' in payload:
            print(f'Message received: {payload} on topic: {topic}')

    try:
        print(f'Subscribing to: {CUSTOM_CMD_CHANNEL}')
        client.subscribe(CUSTOM_CMD_CHANNEL, on_message)

    except Exception as exception:
        print(f'Subscribe failed: {exception}')

    client.publish('cmd-program/state', 'running', retain=True)
    return client


class Shared():
    def __init__(self, running=False) -> None:
        self.running = running


class CustomCmd():

    def __init__(self) -> None:

        self.shared = Shared()
        self.shared.running = False

    def svc_stop(self) -> None:
        self.shared.running = False

    def svc_main(self) -> None:
        self.start()

    def start(self) -> None:
        """Start the Command program service."""

        self.shared.running = True

        def _sig_handler(signo, _):
            if signo in (signal.SIGINT, signal.SIGTERM):
                self.shared.running = False
                print("Setting running to False")

        signal.signal(signal.SIGINT, _sig_handler)
        signal.signal(signal.SIGTERM, _sig_handler)

        if sys.version_info[0] < 3 or sys.version_info[0] == 3 and sys.version_info[1] < 8:
            print(
                "Python version must be 3.8 or higher. Python interpreter version: " + sys.version)
            sys.exit(1)
        print('Command program is running.')

        client = broker_init(tls=True)

        i = 0
        while self.shared.running is True:
            time.sleep(1)  # Gives tests time to listen

        broker_stop(client)


if __name__ == "__main__":
    custom_cmd = CustomCmd()
    custom_cmd.start()
