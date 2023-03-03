#!/usr/bin/python
"""
    Central configuration-agent/configuration service for the manageability framework 

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import os
import platform
import signal
import sys
from logging.config import fileConfig
from time import sleep

from typing import Callable, Any, Optional, List

from configuration.broker import Broker
from configuration.constants import DEFAULT_LOGGING_PATH, XML_LOCATION, SCHEMA_LOCATION
from configuration.xml_key_value_store import XmlKeyValueStore
from inbm_lib.windows_service import WindowsService


class LoggingPath:

    def __init__(self):
        pass

    @classmethod
    def get_log_config_path(cls):
        try:
            return os.environ['LOGGERCONFIG']
        except KeyError:
            return DEFAULT_LOGGING_PATH


class Configuration(WindowsService):
    _svc_name_ = 'inbm-configuration'
    _svc_display_name_ = 'Configuration Agent'
    _svc_description_ = 'Intel Manageability agent handling framework configuration'

    def __init__(self, args: Optional[List] = None) -> None:
        if args is None:
            args = []

        self.argv = args
        self.running = False

        super().__init__(args)

    def _set_up_signal_handlers(self, handler: Callable[[signal.Signals, Any], None]) -> None:
        # Register with systemd for termination.
        signal.signal(signal.SIGTERM, handler)
        # Terminate on control-c from user."""
        signal.signal(signal.SIGINT, handler)

    def _set_up_logging(self) -> logging.Logger:
        log_config_path: str = LoggingPath.get_log_config_path()
        print(f"Looking for logging configuration file at {log_config_path}")
        fileConfig(log_config_path,
                   disable_existing_loggers=False)
        return logging.getLogger(__name__)

    def _quit_if_wrong_python(self, logger: logging.Logger) -> None:
        if sys.version_info[0] < 3 or sys.version_info[0] == 3 and sys.version_info[1] < 8:
            logger.error(
                "Python version must be 3.8 or higher. Python interpreter version: " + sys.version)
            sys.exit(1)

    def svc_stop(self) -> None:
        self.running = False

    def svc_main(self) -> None:
        self.start()

    def start(self) -> None:
        """Start the Configuration service.

        Call this directly for Linux and indirectly through svc_main for Windows."""

        self.running = True

        def _sig_handler(signo, _):
            if signo in (signal.SIGINT, signal.SIGTERM):
                self.running = False

        if platform.system() != 'Windows':
            self._set_up_signal_handlers(_sig_handler)

        logger = self._set_up_logging()
        self._quit_if_wrong_python(logger)

        logger.info('Configuration Agent is running.')

        # Hardcoded to use XML until we have a request to support other tools.
        config = XmlKeyValueStore(XML_LOCATION, True, SCHEMA_LOCATION)
        broker = Broker(config)

        broker.publish_initial_values()

        while self.running is True:
            sleep(1)

        broker.broker_stop()


if __name__ == "__main__":  # pragma: no cover
    if platform.system() == 'Windows':
        import servicemanager
        import win32serviceutil

        if len(sys.argv) == 1:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(Configuration)
            servicemanager.StartServiceCtrlDispatcher()
        else:
            win32serviceutil.HandleCommandLine(Configuration)
    else:
        configuration = Configuration()
        configuration.start()
