"""
    Broker service for INBC tool

    Copyright (C) 2020-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


import logging
import json
from typing import Any

from inbc import shared
from .command.command_factory import create_command_factory
from .constants import MQTT_HOST, CA_CERTS, CLIENT_CERTS, CLIENT_KEYS, DRIVER_NOT_FOUND
from .utility import search_keyword, is_vision_agent_installed
from .xlink_checker import XlinkChecker
from .ibroker import IBroker

from inbm_common_lib.constants import RESPONSE_CHANNEL, EVENT_CHANNEL

from inbm_vision_lib.constants import DEVICE_STATUS_CHANNEL, QUERY
from inbm_vision_lib.mqttclient.mqtt import MQTT
from inbm_vision_lib.mqttclient.config import DEFAULT_MQTT_PORT, MQTT_KEEPALIVE_INTERVAL

from inbm_vision_lib.request_message_constants import NUM_TARGET, NO_DEVICE_FOUND

from inbm_lib.path_prefixes import INTEL_MANAGEABILITY_ETC_PATH_PREFIX

logger = logging.getLogger(__name__)

PROG = 'inbc-program'


class Broker(IBroker):
    """Starts the agent and listens for incoming commands on the command channel

    @param cmd_type: command issued
    @param parsed_args: arguments from user
    @param xlink_checker: XlinkChecker object
    @param tls: use of Transport Layer Security. Default = True
    """

    def __init__(self, cmd_type: str, parsed_args: Any, xlink_checker: XlinkChecker, tls: bool = True) -> None:
        self._xlink_checker = xlink_checker
        self._is_vision_agent_installed = is_vision_agent_installed()
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
        if cmd_type == QUERY:
            self._command.set_target_type(parsed_args.targettype)
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

            """Subscribe to  Telemetry Response to check if update success """
            print('Subscribe to: {0}'.format(RESPONSE_CHANNEL))
            self.mqttc.subscribe(RESPONSE_CHANNEL, self._on_response)

            print('Subscribe to: {0}'.format(EVENT_CHANNEL))
            self.mqttc.subscribe(EVENT_CHANNEL, self._on_vision_event)

            if self._is_vision_agent_installed:
                print('Subscribe to: {0}'.format(DEVICE_STATUS_CHANNEL))
                self.mqttc.subscribe(DEVICE_STATUS_CHANNEL, self._on_status)

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
        if search_keyword(payload, [NUM_TARGET]):
            # Vision-agent will send the number of target to be updated.
            try:
                num_dict = json.loads(payload)
                num_targets = int(num_dict["message"][-1])
                self._command.set_num_vision_targets(num_targets)
            except ValueError:
                print('Use default target number.')
            print("\n Number of targets to be updated: {0} ".format(
                self._command.get_num_vision_targets()))
        else:
            self._command.search_response(payload)

    def _on_vision_event(self, topic: str, payload: str, qos: int) -> None:
        """Callback for EVENT_CHANNEL

        @param topic: topic on which message was published
        @param payload: message payload
        @param qos: quality of service level
        """
        if search_keyword(payload, ["Vision agent is running"]):
            self._command.set_is_vision_agent_running(True)
        self._command.search_event(payload, topic)

    def _on_status(self, topic: str, payload: str, qos: int) -> None:
        """Callback for DEVICE_STATUS_CHANNEL

        @param topic: topic on which message was published
        @param payload: message payload
        @param qos: quality of service level
        """
        if search_keyword(payload, [NO_DEVICE_FOUND]):
            logger.info('Message received: %s on topic: %s', payload, topic)
            self._xlink_checker.return_error(DRIVER_NOT_FOUND)
            self.stop_broker()
        else:
            self._xlink_checker.update_device_status(payload)

    def stop_broker(self) -> None:
        """Shutdown broker, publishing 'dead' event first."""
        shared.running = False
        self._xlink_checker.stop()
        self.mqttc.stop()
        self._command.stop_timer()
