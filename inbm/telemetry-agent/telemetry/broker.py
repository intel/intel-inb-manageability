"""
    Central telemetry/logging service for the manageability framework

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
from .constants import (
    STATE_CHANNEL,
    CLOUDADAPTER_STATE_CHANNEL,
    AGENT,
    CONFIGURATION_UPDATE_CHANNEL,
    TELEMETRY_UPDATE_CHANNEL,
    CLIENT_KEYS,
    CLIENT_CERTS
)
from inbm_lib.mqttclient.mqtt import MQTT
from inbm_lib.mqttclient.config import (
    DEFAULT_MQTT_HOST, DEFAULT_MQTT_PORT, MQTT_KEEPALIVE_INTERVAL, DEFAULT_MQTT_CERTS)
from inbm_common_lib.constants import TELEMETRY_CHANNEL
from .telemetry_handling import publish_telemetry_update, publish_static_telemetry
from .poller import Poller
import logging
import json
from future import standard_library

standard_library.install_aliases()

logger = logging.getLogger(__name__)


def broker_stop(client: MQTT) -> None:
    """Shut down broker, publishing 'dead' event first.

    @param client: broker client
    """
    client.publish(f'{AGENT}/state', 'dead', retain=True)
    # Disconnect MQTT client
    client.stop()


def broker_init(poller: Poller, tls: bool = True, with_docker: bool = False) -> MQTT:
    """Set up generic action for message received; subscribe to state channel; publish
    'running' state

    @return: broker client
    """
    client = MQTT(AGENT + "-agent",
                  DEFAULT_MQTT_HOST,
                  DEFAULT_MQTT_PORT,
                  MQTT_KEEPALIVE_INTERVAL,
                  env_config=True,
                  tls=tls,
                  client_certs=str(CLIENT_CERTS),
                  client_keys=str(CLIENT_KEYS))
    client.start()

    def on_message(topic, payload, qos) -> None:
        logger.info('Message received: %s on topic: %s', payload, topic)
        if topic == CLOUDADAPTER_STATE_CHANNEL and 'running' in payload:
            publish_static_telemetry(client, TELEMETRY_CHANNEL)

    def on_telemetry_update(topic, payload, qos) -> None:
        logger.info('Received telemetry update request for: %s', payload)
        publish_telemetry_update(
            client, TELEMETRY_CHANNEL, with_docker, payload)

    def on_update(topic, payload, qos) -> None:
        logger.info('Message received: %s on topic: %s', payload, topic)
        poller.set_configuration_value(json.loads(
            payload), 'telemetry/' + topic.split('/')[-1])

    try:
        logger.debug('Subscribing to: %s', STATE_CHANNEL)
        client.subscribe(STATE_CHANNEL, on_message)

        logger.debug('Subscribing to: %s', CONFIGURATION_UPDATE_CHANNEL)
        client.subscribe(CONFIGURATION_UPDATE_CHANNEL, on_update)

        logger.debug('Subscribing to %s', TELEMETRY_UPDATE_CHANNEL)
        client.subscribe(TELEMETRY_UPDATE_CHANNEL, on_telemetry_update)

    except Exception as exception:
        logger.exception('Subscribe failed: %s', exception)

    client.publish(f'{AGENT}/state', 'running', retain=True)
    return client
