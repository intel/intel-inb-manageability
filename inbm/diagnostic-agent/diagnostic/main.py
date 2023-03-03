#!/usr/bin/python
"""
    Agent which monitors and reports the state of critical components of the framework

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import json
import logging
import platform
import types
import os
import signal
import sys

from time import sleep
from logging.config import fileConfig
from .constants import DEFAULT_LOGGING_PATH
from typing import Optional, List
from diagnostic.broker import Broker
from inbm_lib.windows_service import WindowsService


class LoggingPath:  # pragma: no cover

    def __init__(self):
        pass

    @classmethod
    def get_log_config_path(cls):
        try:
            return os.environ['LOGGERCONFIG']
        except KeyError:
            return DEFAULT_LOGGING_PATH


class Diagnostic(WindowsService):  # pragma: no cover
    """Listen for commands.

    An instance of this class will be created to start the agent and listen for incoming commands
    on the command channel.
    """

    _svc_name_ = 'inbm-diagnostic'
    _svc_display_name_ = 'Diagnostic Agent'
    _svc_description_ = 'Intel Manageability diagnostic agent'

    def __init__(self, args: Optional[List] = None) -> None:
        if args is None:
            args = []

        super().__init__(args)

        self.running = False
        self.broker: Broker = Broker()

    def svc_stop(self) -> None:  # pragma: no cover
        self.running = False

    def svc_main(self) -> None:  # pragma: no cover
        self.start()

    def start(self, tls: bool = True) -> None:
        """Start the Diagnostic service.

        Call this directly for Linux and indirectly through svc_main for Windows."""

        def _register_stop_callbacks() -> None:  # pragma: no cover
            """Register callbacks to stop the agent on certain signals"""

            # Register with systemd for termination
            signal.signal(signal.SIGTERM, _sig_handler)

            # Catch the CTRL-C exit from the user
            signal.signal(signal.SIGINT, _sig_handler)

        def _sig_handler(signo: signal.Signals, _: types.FrameType) -> None:
            if signo in (signal.SIGINT, signal.SIGTERM):
                self.running = False

        if platform.system() != 'Windows':
            _register_stop_callbacks()
        logger = self._set_up_logging()
        logger.info('Diagnostic agent is running')
        if sys.version_info[0] <= 3 and sys.version_info[1] < 8:
            logger.error(
                "Python version must be 3.8 or higher. Python interpreter version: " + sys.version)
            sys.exit(1)

        self.running = True

        while self.running:
            sleep(1)

        self.broker.stop()

    def _set_up_logging(self) -> logging.Logger:
        log_config_path: str = LoggingPath.get_log_config_path()
        print(f"Looking for logging configuration file at {log_config_path}")
        fileConfig(log_config_path,
                   disable_existing_loggers=False)
        return logging.getLogger(__name__)


def main() -> None:
    """Function called by __main__."""

    if platform.system() == 'Windows':  # pragma: no cover
        import servicemanager
        import win32serviceutil

        if len(sys.argv) == 1:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(Diagnostic)
            servicemanager.StartServiceCtrlDispatcher()
        else:
            win32serviceutil.HandleCommandLine(Diagnostic)
    else:
        diagnostic = Diagnostic()
        diagnostic.start()


if __name__ == "__main__":
    main()
