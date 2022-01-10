"""
    Central configuration/logging service for the manageability framework

    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging

from inbm_common_lib.constants import TELEMETRY_CHANNEL, RESPONSE_CHANNEL, EVENT_CHANNEL

from inbm_vision_lib.mqttclient.config import DEFAULT_MQTT_HOST, DEFAULT_MQTT_PORT, MQTT_KEEPALIVE_INTERVAL
from inbm_vision_lib.mqttclient.mqtt import MQTT
from node.constant import AGENT, CLIENT_CERTS, CLIENT_KEYS, STATE_CHANNEL, REQUEST_CHANNEL, CONFIGURATION_RESP_CHANNEL

logger = logging.getLogger(__name__)


class Broker(object):
    """Starts the agent and listens for incoming commands on the command channel

    @param tls: use of Transport Layer Security. Default = True
    @param data_handler: instance of data_handler
    """

    def __init__(self, tls=True, data_handler=None):
        self.mqttc = None
        self.node_data_handler = data_handler
        # MQTT not supported in KMB flashless. Supported in TBH flashless.
        try:
            self.mqttc = MQTT(AGENT + "-agent", DEFAULT_MQTT_HOST, DEFAULT_MQTT_PORT,
                              MQTT_KEEPALIVE_INTERVAL, env_config=True,
                              tls=tls, client_certs=CLIENT_CERTS, client_keys=CLIENT_KEYS)
            self.mqttc.start()
            self._initialize_broker()
        except ConnectionRefusedError as error:
            logger.error("Connection to broker failed with error: {0} . Please ensure MQTT is running. "
                         "Node started without broker connection.".format(error))

    def _initialize_broker(self) -> None:
        """Initialize module with topics when module starts up"""
        if self.mqttc:
            try:
                self.mqttc.publish('{}/state'.format(AGENT), 'running', retain=True)

                logger.debug('Subscribing to: %s', STATE_CHANNEL)
                self.mqttc.subscribe(STATE_CHANNEL, self._on_message)

                logger.debug('Subscribing to: %s', RESPONSE_CHANNEL)
                self.mqttc.subscribe(RESPONSE_CHANNEL, self._on_result)

                logger.debug('Subscribing to: %s', CONFIGURATION_RESP_CHANNEL)
                self.mqttc.subscribe(CONFIGURATION_RESP_CHANNEL, self._on_result)

                logger.debug('Subscribing to: %s', EVENT_CHANNEL)
                self.mqttc.subscribe(EVENT_CHANNEL, self._on_command)

                logger.debug('Subscribing to: %s', TELEMETRY_CHANNEL)
                self.mqttc.subscribe(TELEMETRY_CHANNEL, self._on_message)

            except Exception as exception:
                logger.exception('Subscribe failed: %s', exception)

    def _on_message(self, topic, payload, qos) -> None:
        """Callback for STATE_CHANNEL

        @param topic: topic on which message was published
        @param payload: message payload
        @param qos: quality of service level
        """
        logger.info('Message received: %s on topic: %s', payload, topic)
        if self.node_data_handler:
            self.node_data_handler.receive_mqtt_message(payload)

    def _on_result(self, topic, payload, qos) -> None:
        """Callback for RESPONSE_CHANNEL and CONFIGURATION_RESP_CHANNEL
        @param topic: topic on which message was published
        @param payload: message payload
        @param qos: quality of service level
        """
        logger.info('Message received: %s on topic: %s', payload, topic)
        if self.node_data_handler:
            self.node_data_handler.receive_mqtt_result(payload)

    def _on_command(self, topic, payload, qos) -> None:
        """Callback for COMMAND_CHANNEL

        @param topic: topic on which message was published
        @param payload: message payload
        @param qos: quality of service level
        """
        try:
            if payload is not None:
                logger.info('Received command request: %s on topic: %s', payload,
                            topic)
                if self.node_data_handler:
                    self.node_data_handler.receive_mqtt_message(payload)
        except ValueError as error:
            logger.error('Unable to parse command/request ID. Verify '
                         'request is in the correct format. {}'
                         .format(error))

    def push_ota(self, manifest: str) -> None:
        """push ota manifest to request channel

        @param manifest OTA manifest
        """
        logger.debug('push_ota message to {}, message is {}'.format(REQUEST_CHANNEL, manifest))
        if self.mqttc:
            self.mqttc.publish(REQUEST_CHANNEL, manifest)
        else:
            logger.info("MQTT does not exist. Message not sent.")

    def stop_broker(self) -> None:
        """Shutdown broker, publishing 'dead' event first."""
        if self.mqttc:
            self.mqttc.publish('{}/state'.format(AGENT), 'dead', retain=True)
            self.mqttc.stop()
