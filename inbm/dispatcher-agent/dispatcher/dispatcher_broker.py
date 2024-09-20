"""
    Helper class to pass common Dispatcher MQTT broker interface to OTA threads
    without introducing a dependency on all of Dispatcher

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
from typing import Any, Optional, Callable

from dispatcher.constants import AGENT, CLIENT_CERTS, CLIENT_KEYS
from dispatcher.dispatcher_exception import DispatcherException
from inbm_lib.mqttclient.config import DEFAULT_MQTT_HOST, DEFAULT_MQTT_PORT, MQTT_KEEPALIVE_INTERVAL
from inbm_lib.mqttclient.mqtt import MQTT

from inbm_common_lib.constants import RESPONSE_CHANNEL, EVENT_CHANNEL, UPDATE_CHANNEL

logger = logging.getLogger(__name__)


class DispatcherBroker:
    def __init__(self) -> None:  # pragma: no cover
        self.mqttc: Optional[MQTT] = None
        self._is_started = False

    def start(self, tls: bool) -> None:  # pragma: no cover
        """Start the broker.

        @param tls: True if TLS connection is desired"""
        self.mqttc = MQTT(AGENT + "-agent", DEFAULT_MQTT_HOST, DEFAULT_MQTT_PORT,
                          MQTT_KEEPALIVE_INTERVAL, env_config=True,
                          tls=tls, client_certs=CLIENT_CERTS,
                          client_keys=CLIENT_KEYS)
        self.mqttc.start()
        self._is_started = True

    def send_update(self, message: str, job_id: str) -> None:
        """Sends node update to local MQTT 'UPDATE' channel to be published
        to the cloudadapter where it will be sent as a reques to INBS (service in UDM)       

        Raises ValueError if id contains a slash

        @param message: message to be published to cloud
        @param job_id: Job ID used to track the request in both UDM and TC
        """
        new_message = job_id + ":" + message
        logger.debug(f"Sending node update for job={job_id} to {UPDATE_CHANNEL} with message: {new_message}")
        self.mqtt_publish(topic=UPDATE_CHANNEL, payload=job_id + ":" + message)
        
    def send_result(self, message: str, request_id: str = "") -> None:  # pragma: no cover
        """Sends result to local MQTT channel        

        Raises ValueError if request_id contains a slash

        @param message: message to be published to cloud
        @param request_id: if not "", publish to RESPONSE_CHANNEL/request_id instead of RESPONSE_CHANNEL
        """
        if request_id:
            extra_log = f" with id {request_id}"
        else:
            extra_log = ""
        logger.debug(f"Sending result message{extra_log}: {message}")

        if "/" in request_id:
            raise ValueError("id cannot contain '/'")

        if not self.is_started():
            logger.error('Cannot send result: dispatcher core not initialized')
        else:
            if id != "":
                topic = RESPONSE_CHANNEL + "/" + request_id
                self.mqtt_publish(topic=topic, payload=message)
            else:
                self.mqtt_publish(topic=RESPONSE_CHANNEL, payload=message)

    def mqtt_publish(self, topic: str, payload: Any, qos: int = 0, retain: bool = False) -> None:  # pragma: no cover
        """Publish arbitrary message on arbitrary topic.

        @param topic: topic to publish
        @param payload: message to publish
        @param qos: QoS of the message, 0 by default
        @param retain: Message retention policy, False by default
        """
        if self.mqttc is None:
            raise DispatcherException("Cannot publish on MQTT: client not initialized.")
        self.mqttc.publish(topic=topic, payload=payload, qos=qos, retain=retain)

    def mqtt_subscribe(self, topic: str, callback: Callable[[str, str, int], None], qos: int = 0) -> None:  # pragma: no cover
        """Subscribe to an MQTT topic

        @param topic: MQTT topic to publish message on
        @param callback: Callback to call when message is received;
                         message will be decoded from utf-8
        @param qos: QoS of the message, 0 by default
        """
        if self.mqttc is None:
            raise DispatcherException("Cannot subscribe on MQTT: client not initialized.")
        self.mqttc.subscribe(topic, callback, qos)

    def telemetry(self, message: str) -> None:
        logger.debug('Received event message: %s', message)
        if not self.is_started():
            logger.error('Cannot log event message: dispatcher core not initialized')
        else:
            self.mqtt_publish(topic=EVENT_CHANNEL, payload=message)

    def stop(self) -> None:  # pragma: no cover
        if not self.is_started():
            raise DispatcherException("Cannot stop dispatcher core: not started")
        if self.mqttc is not None:
            self.mqttc.stop()
        self._is_started = False

    def is_started(self) -> bool:  # pragma: no cover
        return self._is_started
