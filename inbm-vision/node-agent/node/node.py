#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
    Main class of the Node-agent

    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import os
import signal

from logging.config import fileConfig
from time import sleep
from typing import Optional

from node import shared, idata_handler, inode
from node.broker import Broker
from node.data_handler import DataHandler
from node.node_exception import NodeException
from node.xlink_manager import XlinkManager
from node.constant import CONFIG_SCHEMA_LOCATION, CONFIG_LOCATION
from node.idata_handler import IDataHandler
from node.inode import INode

from inbm_vision_lib.configuration_manager import ConfigurationManager
from inbm_vision_lib.constants import CACHE

from inbm_common_lib.utility import remove_file


class Node(INode):

    def __init__(self):
        self._broker: Optional[Broker] = None
        self._xlink_manager: Optional[XlinkManager] = None
        self._data_handler: Optional[IDataHandler] = None

    def initialize(self, broker: Broker, xlink_manager: XlinkManager, data_handler: IDataHandler) -> None:
        self._broker = broker
        self._xlink_manager = xlink_manager
        self._data_handler = data_handler

    def start(self) -> None:
        if self._xlink_manager is None:
            raise NodeException("Cannot start node agent with uninitialized XlinkManager")
        self._xlink_manager.start()

    def stop(self) -> None:
        if self._xlink_manager:
            self._xlink_manager.stop()
        if self._data_handler:
            self._data_handler.stop()

        if self._broker is not None:
            self._broker.stop_broker()

    def get_xlink(self) -> Optional[XlinkManager]:
        return self._xlink_manager

    def get_broker(self) -> Optional[Broker]:
        return self._broker

    def get_data_handler(self) -> Optional[IDataHandler]:
        return self._data_handler


def purge_cache() -> None:
    """Remove all OTA file that were downloaded """
    if os.path.exists(CACHE):
        files_to_remove = [os.path.join(CACHE, f) for f in os.listdir(CACHE)]
        for f in files_to_remove:
            if f.endswith(".tar") or f.endswith(".mender"):
                remove_file(f)


def _sig_handler(signo, _) -> None:
    if signo in (signal.SIGINT, signal.SIGTERM):
        shared.running = False


def get_log_config_path() -> str:
    """Return the config path for this agent, taken by default from LOGGERCONFIG environment variable
    and then from a fixed default path.
    """
    try:
        return os.environ['LOGGERCONFIG']
    except KeyError:
        return "/etc/intel-manageability/public/node-agent/logging.ini"


def main() -> None:
    """Function called by __main__"""

    catch_ctrl_c_from_user()
    catch_termination_via_systemd()
    log_config_path = get_log_config_path()
    fileConfig(log_config_path,
               disable_existing_loggers=False)
    logger = logging.getLogger(__name__)

    logger.info('Node Agent is setting up.')
    logger.info("")
    logger.info("3rd party license information:")
    logger.info(
        "defusedxml - license: Python License 2.0 - https://github.com/tiran/defusedxml/blob/master/LICENSE")
    logger.info("")

    node = Node()
    node_config = ConfigurationManager(xml=CONFIG_LOCATION, schema_location=CONFIG_SCHEMA_LOCATION)
    node_data_handler = DataHandler(node, node_config)
    node_xlink = XlinkManager(data_handler=node_data_handler, config_callback=node_config)
    # Waiting xlink initialization complete
    while shared.running and not node_xlink.get_init_status():
        sleep(1)
    node_broker = Broker(tls=True, data_handler=node_data_handler)
    node.initialize(node_broker, node_xlink, node_data_handler)
    try:
        node.start()
    except NodeException as e:
        logger.error("Exception when trying to start node: {}".format(e))
        exit(1)

    purge_cache()

    # if xlink connection is established, send the register request
    if node_xlink.get_init_status():
        node_data_handler.register()
    logger.info('Node Agent is running.')

    while shared.running:
        sleep(1)

    logger.info('Node Agent is stopping.')

    try:
        node.stop()
    except NodeException as e:
        logger.error("Exception when trying to stop node: {}".format(e))
        exit(1)


def catch_termination_via_systemd() -> None:
    """Register with systemd for termination."""
    signal.signal(signal.SIGTERM, _sig_handler)


def catch_ctrl_c_from_user() -> None:
    """Terminate on control-c from user."""
    signal.signal(signal.SIGINT, _sig_handler)


if __name__ == "__main__":
    main()
