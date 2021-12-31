#!/usr/bin/python
"""
Agent that monitors and reports the state of critical components of the framework


"""
import platform
from typing import Optional, List

from cloudadapter.client import Client
from cloudadapter.constants import LOGGERCONFIG
from cloudadapter.exceptions import BadConfigError
from cloudadapter.utilities import Waiter

import os
import signal
import logging
import sys
from logging.config import fileConfig

from inbm_lib.windows_service import WindowsService


class CloudAdapter(WindowsService):
    _svc_name_ = 'inbm-cloud-adapter'
    _svc_display_name_ = 'Cloud Adapter Agent'
    _svc_description_ = 'Intel Manageability agent handling cloud connections'

    def __init__(self, args: Optional[List] = None) -> None:
        if args is None:
            args = []

        super().__init__(args)

        self.waiter: Waiter = Waiter()

    def svc_stop(self) -> None:
        self.waiter.finish()

    def svc_main(self) -> None:
        self.start()

    def start(self) -> None:
        """Start the Cloudadapter service.

        Call this directly for Linux and indirectly through svc_main for Windows."""

        # Configure logging
        path = os.environ.get('LOGGERCONFIG', LOGGERCONFIG)
        print(f"Looking for logging configuration file at {path}")
        fileConfig(path, disable_existing_loggers=False)
        logger = logging.getLogger(__name__)
        if sys.version_info[0] < 3 or sys.version_info[0] == 3 and sys.version_info[1] < 8:
            logger.error(
                "Python version must be 3.8 or higher. Python interpreter version: " + sys.version)
            sys.exit(1)
        logger.info('Cloud Adapter agent is running')

        # Exit if configuration is malformed
        try:
            client = Client()
            client.start()
        except BadConfigError as e:
            logger.error(str(e))
            return

        # Refresh Waiter
        self.waiter.finish()
        self.waiter = Waiter()

        if platform.system() != 'Windows':
            # Unblock on termination signals
            def unblock(signal, _):
                self.waiter.finish()

            signal.signal(signal.SIGTERM, unblock)
            signal.signal(signal.SIGINT, unblock)

        self.waiter.wait()
        client.stop()


def main():
    """The main function"""

    if platform.system() == 'Windows':
        import servicemanager
        import win32serviceutil

        if len(sys.argv) == 1:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(CloudAdapter)
            servicemanager.StartServiceCtrlDispatcher()
        else:
            win32serviceutil.HandleCommandLine(CloudAdapter)
    else:
        cloudadapter = CloudAdapter()
        cloudadapter.start()


if __name__ == "__main__":
    main()
