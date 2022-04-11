"""
    Broker service for the manageability framework

    Copyright (C) 2019-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


import json
import logging
from typing import Dict, Any

from .data_handler.idata_handler import IDataHandler
from . import ibroker

from .constant import AGENT, CLIENT_CERTS, CLIENT_KEYS, STATE_CHANNEL, \
    CONFIGURATION_UPDATE_CHANNEL, VisionException, VISION_ID

from inbm_common_lib.constants import RESPONSE_CHANNEL, EVENT_CHANNEL, CONFIG_LOAD

from inbm_vision_lib.constants import OTA_UPDATE, CONFIG_GET, CONFIG_SET, CONFIG_APPEND, \
    CONFIG_REMOVE, INSTALL_CHANNEL, RESTART_CHANNEL, QUERY_CHANNEL, DEVICE_STATUS_CHANNEL, \
    MQTT_CA_CERTS, PROVISION_CHANNEL
from inbm_vision_lib.mqttclient.config import DEFAULT_MQTT_HOST, DEFAULT_MQTT_PORT, MQTT_KEEPALIVE_INTERVAL
from inbm_vision_lib.mqttclient.mqtt import MQTT


logger = logging.getLogger(__name__)


class Broker(ibroker.IBroker):
    """Starts the agent and listens for incoming commands on the command channel

    @param tls: use of Transport Layer Security. Default = True
    @param data_handler: instance of data_handler
    """

    def __init__(self, tls: bool, data_handler: IDataHandler) -> None:
        self.mqttc = MQTT(AGENT + "-agent", DEFAULT_MQTT_HOST, DEFAULT_MQTT_PORT,
                          MQTT_KEEPALIVE_INTERVAL, env_config=True,
                          tls=tls, client_certs=CLIENT_CERTS, client_keys=CLIENT_KEYS, ca_certs=MQTT_CA_CERTS)
        self.mqttc.start()
        self._initialize()
        self.logger = logging.getLogger(__name__)
        self.data_handler = data_handler

    def _initialize(self) -> None:
        """Initialize module with topics when module starts up"""
        try:
            logger.debug('Setting up broker.')
            self.mqttc.publish('{}/state'.format(AGENT), 'running', retain=True)

            logger.debug('Subscribing to: %s', STATE_CHANNEL)
            self.mqttc.subscribe(STATE_CHANNEL, self._on_message)

            logger.debug('Subscribing to: %s', INSTALL_CHANNEL)
            self.mqttc.subscribe(INSTALL_CHANNEL, self._on_ota_update)

            logger.debug('Subscribing to: %s', RESTART_CHANNEL)
            self.mqttc.subscribe(RESTART_CHANNEL, self._on_restart)

            logger.debug('Subscribing to: %s', CONFIGURATION_UPDATE_CHANNEL)
            self.mqttc.subscribe(CONFIGURATION_UPDATE_CHANNEL, self._on_config_update)

            logger.debug('Subscribing to: %s', QUERY_CHANNEL)
            self.mqttc.subscribe(QUERY_CHANNEL, self._on_query)

            logger.debug('Subscribing to: %s', PROVISION_CHANNEL)
            self.mqttc.subscribe(PROVISION_CHANNEL, self._on_provision)

            logger.debug('Setting up broker success.')

        except Exception as exception:
            logger.exception('Subscribe failed: %s', exception)
            logger.debug('Setting up broker fail.')

    def _on_restart(self, topic, manifest, qos) -> None:
        if manifest is not None:
            logger.info('Received restart request')
            logger.debug("MANIFEST: {}".format(manifest))
            self.data_handler.receive_restart_request(manifest)

    def _on_message(self, topic, payload, qos) -> None:
        """Callback for STATE_CHANNEL

        @param topic: topic on which message was published
        @param payload: message payload
        @param qos: quality of service level
        """
        logger.info('Message received: %s on topic: %s', payload, topic)

    def _on_ota_update(self, topic, manifest, qos) -> None:
        """Callback for COMMAND_CHANNEL

        @param topic: topic on which message was published
        @param manifest: OTA manifest
        @param qos: quality of service level
        """
        # Example of topic = ma/request/ota
        request_type = topic.split('/')[-1]
        if request_type != OTA_UPDATE:
            e = "Unsupported command received: {}".format(request_type)
            raise VisionException(e)

        if manifest is not None:
            logger.info('Received command request: %s on topic: %s', request_type,
                        topic)
            logger.debug("MANIFEST : {}".format(manifest))
            self.publish_telemetry_event("None", manifest)
            try:
                self.data_handler.receive_mqtt_message(manifest)
            except ValueError as error:
                logger.error(
                    'Unable to parse command/id. Verify request is in the correct format. {}'.format(error))

    def _on_config_update(self, topic, payload, qos) -> None:
        """Callback for CONFIGURATION_UPDATE_CHANNEL

        @param topic: topic on which message was published
        @param payload: (str) message payload
        @param qos: quality of service level
        """
        # Example of topic =  ma/configuration/update/get_element
        logger.debug('Received configuration update request: %s on topic: %s', payload, topic)
        request_type = topic.split('/')[-1]
        manifest = payload
        if request_type in [CONFIG_SET, CONFIG_GET, CONFIG_LOAD, CONFIG_APPEND, CONFIG_REMOVE]:
            try:
                if manifest is not None:
                    self.data_handler.manage_configuration_request(manifest)
            except ValueError as error:
                logger.error('Unable to parse command/id. Verify '
                             'request is in the correct format. {}'
                             .format(error))
        else:
            logger.error('Invalid request type received:{}'.format(request_type))

    def _on_query(self, topic, payload, qos) -> None:
        """Callback for QUERY_CHANNEL

        @param topic: topic on which message was published
        @param payload: (str) message payload
        @param qos: quality of service level
        """
        logger.debug('Received query request: %s on topic: %s', payload, topic)
        try:
            if payload is not None:
                self.data_handler.receive_command_request(payload)
        except ValueError as error:
            logger.error('Unable to parse command/id. Verify '
                         'request is in the correct format. {}'
                         .format(error))

    def _on_provision(self, topic, payload, qos) -> None:
        """Callback for PROVISION_CHANNEL

        @param topic: topic on which message was published
        @param payload: (str) message payload
        @param qos: quality of service level
        """
        logger.debug('Received provision request: %s on topic: %s', payload, topic)
        try:
            if payload is not None:
                self.data_handler.receive_provision_node_request(payload)
        except ValueError as error:
            logger.error('Unable to parse command/id. Verify '
                         'request is in the correct format. {}'
                         .format(error))

    def publish_telemetry_event(self, nid: str, message: str) -> None:
        """Publish on EVENT_CHANNEL

        @param nid: Node ID
        @param message: message to publish on channel
        """
        logger.debug('Publish message to {}, message is: {}'.format(EVENT_CHANNEL, message))
        self.mqttc.publish(EVENT_CHANNEL, json.dumps(message))

    def publish_telemetry_response(self, nid: str, response: Dict[str, Any]) -> None:
        """Publish on RESPONSE_CHANNEL

        @param nid: Node ID
        @param response: OTA response to publish on channel
        """
        logger.debug('Publish message to {}, message is: {}'.format(RESPONSE_CHANNEL, response))
        self.mqttc.publish(RESPONSE_CHANNEL, json.dumps(response))

    def publish_xlink_status(self, nid: str, status: str) -> None:
        """Publish on DEVICE_STATUS_CHANNEL

        @param nid: Node ID
        @param status: xlink device status message
        """
        message = "{0}-{1}".format(nid, status)
        self.mqttc.publish(DEVICE_STATUS_CHANNEL, json.dumps(message))

    def stop_broker(self) -> None:
        """Shutdown broker, publishing 'dead' event first."""
        self.mqttc.publish('{}/state'.format(AGENT), 'dead', retain=True)
        self.mqttc.stop()
