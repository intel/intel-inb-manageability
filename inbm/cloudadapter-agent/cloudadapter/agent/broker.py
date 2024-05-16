"""
    Central configuration/logging service for the manageability framework
    
    An instance of this class will be created to start the agent and listen
    for incoming commands on the command channel
    
    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from ..constants import (
    SCHEDULE,
    TC_TOPIC,
    TC_REQUEST_CHANNEL,
    SHUTDOWN,
    RESTART,
    INSTALL,
    DECOMMISSION,
    CLIENT_CERTS,
    CLIENT_KEYS,
    AGENT,
    COMMAND)
from ..utilities import make_threaded
from inbm_lib.mqttclient.mqtt import MQTT
from inbm_lib.mqttclient.config import DEFAULT_MQTT_HOST, DEFAULT_MQTT_PORT, MQTT_KEEPALIVE_INTERVAL, DEFAULT_MQTT_CERTS
from typing import Tuple, Callable
import os
import logging
logger = logging.getLogger(__name__)


class Broker:
    """Connects to the MQTT Broker and subscribes to channels

    @param tls: (bool, optional) Whether to use TLS
    """

    def __init__(self, tls: bool = True) -> None:
        if os.path.islink(CLIENT_CERTS) or os.path.islink(CLIENT_KEYS):
            raise ValueError(
                f"CLIENT_CERTS ({CLIENT_CERTS}) and CLIENT_KEYS ({CLIENT_KEYS}) should not be symbolic links.")

        logger.debug("Initializing connection to MQTT broker. MQTT host: {}. MQTT port: {}. tls: {}."
                     " client certs: {}. client keys: {}.".
                     format(DEFAULT_MQTT_HOST, DEFAULT_MQTT_PORT, tls, CLIENT_CERTS, CLIENT_KEYS))
        self.mqttc = MQTT(AGENT + "-agent",
                          DEFAULT_MQTT_HOST,
                          DEFAULT_MQTT_PORT,
                          MQTT_KEEPALIVE_INTERVAL,
                          env_config=True,
                          tls=tls,
                          client_certs=str(CLIENT_CERTS),
                          client_keys=str(CLIENT_KEYS))

    def bind_callback(self, topic: Tuple[str, ...], callback: Callable) -> None:
        """Bind a callback to process messages from certain topics
        The callback must be a function with the signature: (str, str) -> None
            (str): The specific topic that triggered the callback
            (str): The callback payload

        @param topic:    The topic to bind the callback to
        @param callback: (Callable) The callback to trigger
        """
        if topic not in TC_TOPIC.__dict__.values():  # pylint: disable=dict-values-not-iterating
            logger.error("Attempted to subscribe to unsupported topic: %s", topic)
            return

        def threaded(topic: str, payload: str, _) -> None:
            make_threaded(callback)(topic, payload)

        for t in topic:
            logger.debug("Subscribing to: %s", t)
            self.mqttc.subscribe(t, threaded)

    def start(self) -> None:
        """Start the broker and connect to Intel(R) In-Band Manageability"""
        logger.info("Connecting to Intel(R) In-Band Manageability...")
        self.mqttc.start()
        self.mqttc.publish(f"{AGENT}/state", "running", retain=True)

    def stop(self) -> None:
        """Stop the broker, disconnecting from the rest of Intel(R) In-Band Manageability"""
        logger.info("Disconnecting from Intel(R) In-Band Manageability...")
        self.mqttc.publish(f'{AGENT}/state', 'dead', retain=True)
        self.mqttc.stop()

    def publish_reboot(self) -> None:
        """Publishes a request to reboot the device"""
        logger.info("Rebooting the device...")
        self.mqttc.publish(TC_REQUEST_CHANNEL + RESTART, '', retain=True)

    def publish_shutdown(self) -> None:
        """Publishes a request to shut down the device"""
        logger.info("Shutting down the device...")
        self.mqttc.publish(TC_REQUEST_CHANNEL + SHUTDOWN, '', retain=True)

    def publish_decommission(self) -> None:
        """Publishes a request to shut down the device"""
        logger.info("Shutting down the device...")
        self.mqttc.publish(TC_REQUEST_CHANNEL + DECOMMISSION, '', retain=True)

    def publish_install(self, manifest: str) -> None:
        """Publishes a manifest request

        @param manifest: (str) The XML formatted manifest to send
        """
        logger.info("Sending a manifest...")
        self.mqttc.publish(TC_REQUEST_CHANNEL + INSTALL, manifest, retain=False)

    def publish_schedule(self, manifest: str) -> None:
        """Publishes a schedule request

        @param manifest: (str) The XML formatted schedule to send
        """
        logger.info("Sending a schedule...")
        self.mqttc.publish(TC_REQUEST_CHANNEL + SCHEDULE, manifest, retain=False)

    def publish_command(self, command: str) -> None:
        """Publishes a received command message

        @param command: (str) The command to send
        """
        logger.info("Sending command...")
        self.mqttc.publish(TC_REQUEST_CHANNEL + COMMAND, command, retain=False)

    def publish_ucc(self, message: str) -> None:
        """Publishes a received command message to UCC
        @param message: The message to send
        """
        logger.info("Sending command to UCC...")
        # FIXME: put in real UCC channel
        topic = TC_REQUEST_CHANNEL + COMMAND
        logger.debug(f"details: topic = {topic}; message = {message}")

        self.mqttc.publish(topic, message, retain=False)
