"""
Bridges the connection between the cloud adapter and the Intel(R) In-Band Manageability broker

Copyright (C) 2017-2023 Intel Corporation
SPDX-License-Identifier: Apache-2.0
"""


from .cloud import adapter_factory as adapter_factory
from .cloud.cloud_publisher import CloudPublisher

from .agent.broker import Broker
from .agent.publisher import Publisher
from .agent.device_manager import DeviceManager

from .constants import SLEEP_DELAY, TC_TOPIC, METHOD
from .exceptions import (
    ConnectError, DisconnectError, AuthenticationError, BadConfigError)
from .utilities import make_threaded

from time import sleep
from typing import Callable
import logging
logger = logging.getLogger(__name__)


class Client:

    def __init__(self) -> None:
        """Construct the Client object
        @exception BadConfigError: If the adapter configuration is bad
        """
        self._broker = Broker()
        self._publisher = Publisher(self._broker)
        self._device_manager = DeviceManager(self._broker)

        self._adapter = adapter_factory.get_adapter()
        self._cloud_publisher = CloudPublisher(self._adapter)

    def _bind_agent_to_cloud(self) -> None:
        """Bind Intel(R) In-Band Manageability messages to the cloud"""
        self._broker.bind_callback(
            TC_TOPIC.TELEMETRY,
            lambda _, payload: self._cloud_publisher.publish_telemetry(payload)
        )
        self._broker.bind_callback(
            TC_TOPIC.EVENT,
            lambda _, payload: self._cloud_publisher.publish_event(payload)
        )

    def _bind_cloud_to_agent(self) -> None:
        """Bind cloud methods to Intel(R) In-Band Manageability calls"""
        adapter_bindings = {
            METHOD.MANIFEST: self._publisher.publish_manifest,
            METHOD.AOTA: self._publisher.publish_aota,
            METHOD.FOTA: self._publisher.publish_fota,
            METHOD.SOTA: self._publisher.publish_sota,
            METHOD.QUERY: self._publisher.publish_query,
            METHOD.CONFIG: self._publisher.publish_config,
            METHOD.SHUTDOWN: self._device_manager.shutdown_device,
            METHOD.REBOOT: self._device_manager.reboot_device,
            METHOD.DECOMMISSION: self._device_manager.decommission_device
        }

        loggers = [self._cloud_publisher.publish_event, logger.info]

        for name, callback in adapter_bindings.items():
            callback = self._with_log(callback, *loggers)
            self._adapter.bind_callback(name, callback)

    def _with_log(self, f, *loggers) -> Callable:
        """Decorator function to log a message via one or more logging functions
        The logging functions should have the signature: (str) -> None
            (str): The message to log
        Does not work as an @ decorator.

        @param f:       (Callable) The function to decorate
        @param loggers: (*args: Callable) The logger(s) to log to
        @return:        (Callable) The decorated function
        """
        def decorated(*args, **kwargs):
            message = ""
            try:
                message = f(*args, **kwargs)
            except (ValueError, KeyError, TypeError) as e:
                message = f"Command {f.__name__} failed: {e}"
            finally:
                for logger in loggers:
                    make_threaded(logger)(message)
            return message

        return decorated

    def start(self) -> None:
        """Connect the cloud to Intel(R) In-Band Manageability
        @exception BadConfigError: If the connection configuration is bad
        """
        self._bind_agent_to_cloud()
        self._bind_cloud_to_agent()

        connected = False
        while not connected:
            try:
                self._adapter.connect()
                connected = True
            except AuthenticationError as e:
                raise BadConfigError(str(e))
            except ConnectError as e:
                logger.error(str(e))
                sleep(SLEEP_DELAY)

        self._cloud_publisher.publish_event("Connected")

        # Log agent states
        self._broker.bind_callback(
            TC_TOPIC.STATE,
            lambda topic, payload: logger.info("State: %-20s %s", topic, payload))
        self._broker.start()

    def stop(self) -> None:
        """Disconnect the cloud and Intel(R) In-Band Manageability"""
        self._broker.stop()
        self._cloud_publisher.publish_event("Disconnected")
        try:
            self._adapter.disconnect()
        except DisconnectError as e:
            logger.error(str(e))
