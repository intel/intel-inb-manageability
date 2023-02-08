"""
    Broker service for INBC tool

    Copyright (C) 2020-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


import logging
import json
from typing import Any

from inbc import shared
from .command.command_factory import create_command_factory
from .constants import MQTT_HOST, CA_CERTS, CLIENT_CERTS, CLIENT_KEYS
from .utility import search_keyword
from .ibroker import IBroker

from inbm_common_lib.constants import RESPONSE_CHANNEL, EVENT_CHANNEL

from inbm_vision_lib.constants import DEVICE_STATUS_CHANNEL, QUERY
from inbm_vision_lib.mqttclient.mqtt import MQTT
from inbm_vision_lib.mqttclient.config import DEFAULT_MQTT_PORT, MQTT_KEEPALIVE_INTERVAL

from inbm_lib.path_prefixes import INTEL_MANAGEABILITY_ETC_PATH_PREFIX

logger = logging.getLogger(__name__)

PROG = 'inbc-program'


class Broker(IBroker):
    """Starts the agent and listens for incoming commands on the command channel

    @param cmd_type: command issued
    @param parsed_args: arguments from user
    @param tls: use of Transport Layer Security. Default = True
    """

    def __init__(self, cmd_type: str, parsed_args: Any, tls: bool = True) -> None:
        try:
            with open(INTEL_MANAGEABILITY_ETC_PATH_PREFIX / 'local-mqtt-port.txt') as port:
                mqtt_port = int(port.readlines()[0])
        except OSError:
            mqtt_port = DEFAULT_MQTT_PORT
        except ValueError:
            mqtt_port = DEFAULT_MQTT_PORT

        self.mqttc = MQTT(PROG,
                          MQTT_HOST,
                          mqtt_port,
                          MQTT_KEEPALIVE_INTERVAL,
                          ca_certs=CA_CERTS,
                          env_config=True,
                          tls=tls,
                          client_certs=CLIENT_CERTS,
                          client_keys=CLIENT_KEYS)
        self.mqttc.start()
        self._subscribe()
        self._command = create_command_factory(cmd_type, self)
        # Topics are coded in the methods.  Abstract method is requiring param 2, but it's not used.
        self._command.trigger_manifest(parsed_args, "topic")

    def publish(self, topic: str, message: str, retain: bool = False) -> None:
        """Publishes message via MQTT

        @param topic: MQTT topic to publish on
        @param message: message to publish
        @param retain: True to retain message until successful; otherwise, false.
        """
        self.mqttc.publish(topic, message, retain)

    def _subscribe(self) -> None:
        """Subscribe to topics on start up"""
        try:
            logger.debug('Setting up broker.')

            """Subscribe to  Telemetry Response to check if update successful """
            print('Subscribe to: {0}'.format(RESPONSE_CHANNEL))
            self.mqttc.subscribe(RESPONSE_CHANNEL, self._on_response)

            logger.debug('Setting up broker success.')
        except Exception as exception:
            logger.exception('Subscribe failed: %s', exception)
            logger.debug('Setting up broker fail.')

    def _on_response(self, topic: str, payload: str, qos: int) -> None:
        """Callback for RESPONSE_CHANNEL

        @param topic: topic on which message was published
        @param payload: message payload
        @param qos: quality of service level
        """
        logger.info('Message received: %s on topic: %s', payload, topic)
        self._command.search_response(payload)

    def stop_broker(self) -> None:
        """Shutdown broker, publishing 'dead' event first."""
        shared.running = False
        self.mqttc.stop()
        self._command.stop_timer()
