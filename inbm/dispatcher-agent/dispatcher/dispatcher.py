"""
    Main .py file for Dispatcher agent -- contains main() method

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import platform
import sys
import os
from typing import List

from dispatcher.constants import DEFAULT_LOGGING_PATH
from dispatcher.install_check_service import InstallCheckService
from dispatcher.dispatcher_class import Dispatcher
from dispatcher.dispatcher_broker import DispatcherBroker
from logging.config import fileConfig
from inbm_lib.windows_service import WindowsService


def get_log_config_path() -> str:
    """Return the config path for this agent, taken by default from LOGGERCONFIG environment
    variable and then from a fixed default path.
    """
    try:
        return os.environ['LOGGERCONFIG']
    except KeyError:
        return DEFAULT_LOGGING_PATH

def make_dispatcher(args: List[str]) -> Dispatcher:
    """Make a dispatcher with the given args.

    Handle dependency injection in one place"""
    broker = DispatcherBroker()
    log_config_path = get_log_config_path()
    msg = f"Looking for logging configuration file at {log_config_path}"
    print(msg)
    fileConfig(log_config_path,
                disable_existing_loggers=False)

    return Dispatcher(args=args, broker=broker, install_check_service=InstallCheckService(broker))


class WindowsDispatcherService(WindowsService):
    _svc_name_ = 'inbm-dispatcher'
    _svc_display_name_ = 'Dispatcher Agent'
    _svc_description_ = 'Intel Manageability coordinating agent'

    def __init__(self, args: List[str]) -> None:
        if args is None:
            args = []

        self.dispatcher = make_dispatcher(args)

        super().__init__(args)

    def svc_stop(self) -> None:
        self.dispatcher.stop()

    def svc_main(self) -> None:
        self.start()


def main() -> None:
    """Function called by __main__."""

    if platform.system() == 'Windows':
        import servicemanager
        import win32serviceutil

        if len(sys.argv) == 1:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(WindowsDispatcherService)
            servicemanager.StartServiceCtrlDispatcher()
        else:
            win32serviceutil.HandleCommandLine(WindowsDispatcherService)
    else:
        dispatcher = make_dispatcher(sys.argv)
        dispatcher.start()


if __name__ == "__main__":
    main()
