"""
    Main.py file for vision-agent -- contains main() method

    Copyright (C) 2019-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import os
import signal
import sys
from logging.config import fileConfig
import platform
from time import sleep
from typing import Optional

from inbm_lib.windows_service import WindowsService

from vision import shared, ivision
from vision.broker import Broker
from vision.data_handler.data_handler import DataHandler
from vision.data_handler.idata_handler import IDataHandler
from vision.node_communicator.node_connector import NodeConnector
from inbm_vision_lib.configuration_manager import ConfigurationManager
from vision.constant import CONFIG_SCHEMA_LOCATION, CONFIG_LOCATION, VisionException, DEFAULT_LOGGING_PATH


class Vision(ivision.IVision, WindowsService):
    """main class that contains broker, node connector and data handler"""

    _svc_name_ = 'inbm-vision-vision'
    _svc_display_name_ = 'Vision agent'
    _svc_description_ = 'Intel Manageability - Vision agent'

    def __init__(self) -> None:
        self._broker: Optional[Broker] = None
        self._node_connector: Optional[NodeConnector] = None
        self._data_handler: Optional[IDataHandler] = None

    def svc_stop(self) -> None:
        shared.running = False

    def svc_main(self) -> None:
        self.start()

    def start(self) -> None:
        def _sig_handler(signo, _) -> None:
            if signo in (signal.SIGINT, signal.SIGTERM):
                shared.running = False

        def catch_termination_via_systemd() -> None:
            """Register with systemd for termination."""
            signal.signal(signal.SIGTERM, _sig_handler)

        def catch_ctrl_c_from_user() -> None:
            """Terminate on control-c from user."""
            signal.signal(signal.SIGINT, _sig_handler)

        if platform.system() != 'Windows':
            catch_ctrl_c_from_user()
            catch_termination_via_systemd()

        log_config_path = get_log_config_path()
        fileConfig(log_config_path,
                   disable_existing_loggers=False)
        logger = logging.getLogger(__name__)

        logger.info('Vision Agent is setting up.')
        logger.info("")
        logger.info("3rd party license information:")
        logger.info(
            "defusedxml - license: Python License 2.0 - https://github.com/tiran/defusedxml/blob/vision/LICENSE")
        logger.info("")

        vision = Vision()
        vision_config = ConfigurationManager(
            xml=CONFIG_LOCATION, schema_location=CONFIG_SCHEMA_LOCATION)
        data_handler = DataHandler(vision, vision_config)
        broker = Broker(tls=True, data_handler=data_handler)
        node_connector = NodeConnector(data_handler=data_handler,
                                       config_callback=vision_config)
        vision.initialize(broker, node_connector, data_handler)

        logger.info('Vision-agent is running.')

        while shared.running:
            sleep(1)

        logger.info('Vision-agent is stopping.')
        try:
            vision.stop()
        except VisionException as e:
            logger.error("Exception when trying to stop vision agent: {}".format(e))
            exit(1)

    def initialize(self, broker: Broker, node_connector: NodeConnector, data_handler: IDataHandler):
        """Sets the value for broker, node connector and data handler

        @param broker: MQTT broker
        @param node_connector: NodeConnector object
        @param data_handler: vision data handler
        """
        self._broker = broker
        self._node_connector = node_connector
        self._data_handler = data_handler

    def get_broker(self) -> Optional[Broker]:
        """ Get MQTT broker used in vision-agent

        @return: returns broker object
        """
        return self._broker

    def get_node_connector(self) -> Optional[NodeConnector]:
        """ Get Node Connector used in vision-agent

        @return: NodeConnector object
        """
        return self._node_connector

    def stop(self) -> None:
        """Stop listen xlink channel, data handler event and broker"""
        if self._data_handler is None:
            raise VisionException("Cannot stop vision-agent with uninitialized DataHandler")
        if self._node_connector is None:
            raise VisionException("Cannot stop vision-agent uninitialized connection to nodes.")

        self._data_handler.stop()
        if self._broker is not None:
            self._broker.stop_broker()
        self._node_connector.stop()


def get_log_config_path() -> str:
    """Return the config path for this agent, taken by default from LOGGERCONFIG environment
    variable
    and then from a fixed default path.

    """
    try:
        return os.environ['LOGGERCONFIG']
    except KeyError:
        return DEFAULT_LOGGING_PATH


def main() -> None:
    """Function called by __main__."""

    if platform.system() == 'Windows':
        import servicemanager
        import win32serviceutil

        if len(sys.argv) == 1:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(Vision)
            servicemanager.StartServiceCtrlDispatcher()
        else:
            win32serviceutil.HandleCommandLine(Vision)
    else:
        vision = Vision()
        vision.start()


if __name__ == "__main__":
    main()
