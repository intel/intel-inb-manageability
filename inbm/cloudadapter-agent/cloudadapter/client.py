"""
Bridges the connection between the cloud adapter and the Intel(R) In-Band Manageability broker

Copyright (C) 2017-2024 Intel Corporation
SPDX-License-Identifier: Apache-2.0
"""

from .cloud import adapter_factory as adapter_factory
from .cloud.cloud_publisher import CloudPublisher
from .cloud.adapters.inbs_adapter import InbsAdapter

from .agent.broker import Broker
from .agent.publisher import Publisher
from .agent.device_manager import DeviceManager

from .constants import SLEEP_DELAY, TC_TOPIC, METHOD, DISPATCHER, RUNNING, DEAD
from .exceptions import (
    ConnectError, DisconnectError, AuthenticationError, BadConfigError)
from .utilities import make_threaded, is_ucc_mode

from time import sleep
from typing import Callable, Any
import logging

logger = logging.getLogger(__name__)


class Client:

    def __init__(self) -> None:
        """Construct the Client object
        @exception BadConfigError: If the adapter configuration is bad
        """

        # These statements set up INBM-side communication
        self._broker = Broker()
        self._publisher = Publisher(self._broker)
        self._device_manager = DeviceManager(self._broker)

        # These statements set up the cloud side communication
        self._adapter = adapter_factory.get_adapter()
        self._cloud_publisher = CloudPublisher(self._adapter)

    def _bind_agent_to_cloud(self) -> None:
        """Bind Intel(R) In-Band Manageability messages to the cloud"""

        if is_ucc_mode():
            logger.info('UCC flag is ON.  Using UCC broker and UCC Service Agent')
            # Using the TC Telemetry topic, but publishing using event as this will just pass
            # the message through as is already done with event.  Telemetry publishes each key/value
            # pair individually.
            self._broker.bind_callback(
                TC_TOPIC.TELEMETRY,
                lambda _, payload: self._cloud_publisher.publish_event(payload)
            )
        else:
            self._broker.bind_callback(
                TC_TOPIC.TELEMETRY,
                lambda _, payload: self._cloud_publisher.publish_telemetry(payload)
            )
            self._broker.bind_callback(
                TC_TOPIC.EVENT,
                lambda _, payload: self._cloud_publisher.publish_event(payload)
            )
            self._broker.bind_callback(
                TC_TOPIC.UPDATE,
                lambda _, payload: self._cloud_publisher.publish_update(payload)
            )

    def _bind_ucc_to_agent(self) -> None:
        logger.debug("Binding cloud to Command")

        callback = self._publisher.publish_ucc
        loggers = [logger.info]
        callback = self._with_log(callback, *loggers)
        self._adapter.bind_callback(METHOD.RAW, callback)

    def _bind_cloud_to_agent(self) -> None:
        adapter_bindings = {
            METHOD.MANIFEST: self._publisher.publish_manifest,
            METHOD.SCHEDULE: self._publisher.publish_schedule,
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

        # This part sets up INBM->cloud function calls
        self._bind_agent_to_cloud()

        # This part sets up cloud->INBM function calls.
        if is_ucc_mode():
            self._bind_ucc_to_agent()
        else:
            self._bind_cloud_to_agent()

        connected = False
        while not connected:
            try:
                self._adapter.connect()
                connected = True
            except AuthenticationError as e:
                raise BadConfigError from e
            except ConnectError as e:
                logger.error(str(e))
                sleep(SLEEP_DELAY)

        self._cloud_publisher.publish_event("Connected")

        # Log agent states
        self._broker.bind_callback(
            TC_TOPIC.STATE,
            lambda topic, payload: self._handle_state(topic, payload))
        self._broker.start()

    def _handle_state(self, topic: str, payload: Any) -> None:
        """Handle state response from other agents"""
        logger.info("State: %-20s %s", topic, payload)
        # Set the dispatcher state
        if isinstance(self._adapter, InbsAdapter) and DISPATCHER in str(topic):
            if RUNNING in payload:
                self._adapter.set_dispatcher_state(RUNNING)
            elif DEAD in payload:
                self._adapter.set_dispatcher_state(DEAD)

    def stop(self) -> None:
        """Disconnect the cloud and Intel(R) In-Band Manageability"""
        logger.debug("Stopping cloudadapter client")
        self._broker.stop()
        self._cloud_publisher.publish_event("Disconnected")
        self._cloud_publisher.publish_update("Disconnected")
        try:
            logger.debug("Calling disconnect on adapter")
            self._adapter.disconnect()
        except DisconnectError as e:
            logger.error(str(e))
