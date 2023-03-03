#!/usr/bin/python
"""
    Broker for MQTT communication of the agent.

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
import json

from typing import Optional

from diagnostic.ibroker import IBroker
from diagnostic.diagnostic_checker import DiagnosticChecker
from diagnostic.constants import AGENT, CONFIGURATION_UPDATE_CHANNEL, ALL_AGENTS_UPDATE_CHANNEL, CMD_CHANNEL, \
    RESPONSE_CHANNEL, STATE_CHANNEL, CLIENT_CERTS, CLIENT_KEYS
from inbm_lib.mqttclient.config import DEFAULT_MQTT_HOST, DEFAULT_MQTT_PORT, MQTT_KEEPALIVE_INTERVAL
from inbm_lib.mqttclient.mqtt import MQTT

logger = logging.getLogger(__name__)


class Broker(IBroker):  # pragma: no cover
    """Starts the agent and listens for incoming commands on the command channel"""

    def __init__(self, tls: bool = True) -> None:
        self.diagnostic_checker: Optional[DiagnosticChecker] = None
        self._mqttc = MQTT(AGENT + "-agent", DEFAULT_MQTT_HOST, DEFAULT_MQTT_PORT,
                           MQTT_KEEPALIVE_INTERVAL, env_config=True,
                           tls=tls, client_certs=CLIENT_CERTS, client_keys=CLIENT_KEYS)
        self._mqttc.start()

        self._initialize_broker()

    def publish(self, channel: str, message: str):
        """Publish message on MQTT channel

        @param channel: channel to publish upon
        @param message: message to publish
        """
        self._mqttc.publish(channel, message)

    def _initialize_broker(self) -> None:
        self.diagnostic_checker = DiagnosticChecker(self)

        try:
            logger.debug('Subscribing to: %s', STATE_CHANNEL)
            self._mqttc.subscribe(STATE_CHANNEL, self._on_message)

            logger.debug('Subscribing to: %s', CMD_CHANNEL)
            self._mqttc.subscribe(CMD_CHANNEL, self._on_command)

            logger.debug('Subscribing to: %s', CONFIGURATION_UPDATE_CHANNEL)
            self._mqttc.subscribe(CONFIGURATION_UPDATE_CHANNEL, self._on_update)

            logger.debug('Subscribing to: %s', ALL_AGENTS_UPDATE_CHANNEL)
            self._mqttc.subscribe(ALL_AGENTS_UPDATE_CHANNEL, self._on_update)

            self._mqttc.publish(f'{AGENT}/state', 'running', retain=True)

        except Exception as exception:
            logger.exception('Subscribe failed: %s', exception)

    def _on_update(self, topic: str, payload: str, qos: int) -> None:
        """Callback for messages received on Configuration Update Channel
        @param topic: channel message received
        @param payload: message received
        @param qos: quality of service level
        """
        logger.info(f'Message received:{payload} on topic: {topic}')
        if self.diagnostic_checker:
            self.diagnostic_checker.set_configuration_value(json.loads(
                payload), topic.split('/')[-2] + '/' + topic.split('/')[-1])

    def _on_command(self, topic: str, payload: str, qos: int) -> None:
        """Callback for messages received on Command Channel
        @param topic: channel message received
        @param payload: message received
        @param qos: quality of service level
        """
        # Parse payload
        try:
            if payload is not None:
                request = json.loads(payload)
                logger.info(f'Received message: {request} on topic: {topic}')
                if self.diagnostic_checker:
                    self.diagnostic_checker.execute(request)

        except ValueError as error:
            logger.error(
                f'Unable to parse command/request ID. Verify request is in the correct format. {error}')

    def _on_message(self, topic: str, payload: str, qos: int) -> None:
        """Callback for messages received on State Channel
        @param topic: channel message received
        @param payload: message received
        @param qos: quality of service level
        """
        logger.info(f'Message received: {payload} on topic: {topic}')

    def stop(self) -> None:
        """Shutdown broker, publishing 'dead' event first."""
        if self.diagnostic_checker:
            self.diagnostic_checker.stop_timer()
        self._mqttc.publish(f'{AGENT}/state', 'dead', retain=True)
        self._mqttc.stop()
