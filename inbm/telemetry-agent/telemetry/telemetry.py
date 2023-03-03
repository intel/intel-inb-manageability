#!/usr/bin/python

# -*- coding: utf-8 -*-
"""
    Central telemetry/logging service for the manageability framework 

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import platform
from typing import Optional, List, Union

from inbm_lib.windows_service import WindowsService
from telemetry.constants import DEFAULT_LOGGING_PATH, SCHEMA_LOCATION, EVENTS_CHANNEL
from inbm_lib.constants import QUERY_CMD_CHANNEL
from inbm_lib.xmlhandler import XmlHandler
from telemetry import software_bom_list
from telemetry.poller import Poller
from telemetry.broker import broker_init, broker_stop
from telemetry import telemetry_handling
from telemetry import software_checker
from telemetry import shared
from logging.config import fileConfig
from telemetry.telemetry_exception import TelemetryException
from pathlib import Path
import time
import sys
import signal
import os
import logging

# TODO: let command line change this (maybe default to INFO); unit tests should stay DEBUG


class PathLogger:

    @classmethod
    def get_log_config_path(cls) -> Union[Path, str]:
        try:
            return os.environ['LOGGERCONFIG']
        except KeyError as e:
            return DEFAULT_LOGGING_PATH


class Telemetry(WindowsService):
    _svc_name_ = 'inbm-telemetry'
    _svc_display_name_ = 'Telemetry Agent'
    _svc_description_ = 'Intel Manageability agent handling device telemetry'

    def __init__(self, args: Optional[List] = None) -> None:
        if args is None:
            args = []

        self.argv = args
        shared.running = False

        super().__init__(args)

        logging_path = PathLogger.get_log_config_path()
        print(f"Looking for logging configuration file at {logging_path}")
        fileConfig(logging_path, disable_existing_loggers=False)
        self.logger = logging.getLogger(__name__)

    def svc_stop(self) -> None:
        shared.running = False

    def svc_main(self) -> None:
        self.start()

    def start(self) -> None:
        """Start the Telemetry service.

        Call this directly for Linux and indirectly through svc_main for Windows."""

        shared.running = True

        def _sig_handler(signo, _):
            if signo in (signal.SIGINT, signal.SIGTERM):
                shared.running = False
                # Following line will only execute in testing
                assert self.logger  # noqa: S101
                self.logger.debug("Setting running to False")

        if platform.system() != 'Windows':
            # Terminate on control-c from user.
            signal.signal(signal.SIGINT, _sig_handler)
            # Register with systemd for termination.
            signal.signal(signal.SIGTERM, _sig_handler)

        if sys.version_info[0] < 3 or sys.version_info[0] == 3 and sys.version_info[1] < 8:
            self.logger.error(
                "Python version must be 3.8 or higher. Python interpreter version: " + sys.version)
            sys.exit(1)
        self.logger.info('Telemetry agent is running.')

        docker_stack_present = software_checker.are_docker_and_trtl_on_system()
        poller = Poller()
        client = broker_init(poller, tls=True, with_docker=docker_stack_present)

        i = 0
        while i < 5 and shared.running:
            i += 1
            time.sleep(1)  # Gives tests time to listen
        if shared.running:
            telemetry_handling.send_initial_telemetry(
                client, with_docker=docker_stack_present)
            try:
                self.logger.debug(f'Subscribing to {QUERY_CMD_CHANNEL}')

                def on_query(topic: str, payload: str, qos: int) -> None:
                    try:
                        parsed = XmlHandler(xml=payload,
                                            is_file=False,
                                            schema_location=SCHEMA_LOCATION)
                        option = parsed.get_element('query/option')
                        if option == "swbom":
                            software_bom_list.publish_software_bom(client, True)
                        else:
                            info = telemetry_handling.get_static_telemetry_info()
                            query_result = telemetry_handling.get_query_related_info(option, info)
                            key = 'queryEndResult' if option != 'all' else 'queryResult'
                            Query = {'values': {key: query_result},
                                     'type': 'dynamic_telemetry'}
                            telemetry_handling.publish_dynamic_telemetry(
                                client, EVENTS_CHANNEL, Query)
                            if option == 'all':
                                software_bom_list.publish_software_bom(client, True)
                    except TelemetryException:
                        Query = {'values': {'queryEndResult': 'Unable to gather query requested info'},
                                 'type': "dynamic_telemetry"}
                        telemetry_handling.publish_dynamic_telemetry(
                            client, EVENTS_CHANNEL, Query)

                client.subscribe(QUERY_CMD_CHANNEL, on_query)
            except Exception:  # we're looking for a socket error but I don't see one exported from paho-mqtt
                self.logger.error('Cannot subscribe to {QUERY_CMD_CHANNEL}')
                shared.running = False
                raise

            poller.loop_telemetry(client)

        broker_stop(client)


if __name__ == "__main__":
    if platform.system() == 'Windows':
        import servicemanager
        import win32serviceutil

        if len(sys.argv) == 1:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(Telemetry)
            servicemanager.StartServiceCtrlDispatcher()
        else:
            win32serviceutil.HandleCommandLine(Telemetry)
    else:
        telemetry = Telemetry()
        telemetry.start()
