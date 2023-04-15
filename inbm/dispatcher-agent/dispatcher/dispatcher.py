"""
    Main .py file for Dispatcher agent -- contains main() method

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import platform
import sys

from dispatcher.dispatcher_class import Dispatcher


def main() -> None:
    """Function called by __main__."""

    if platform.system() == 'Windows':
        import servicemanager
        import win32serviceutil

        if len(sys.argv) == 1:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(Dispatcher)
            servicemanager.StartServiceCtrlDispatcher()
        else:
            win32serviceutil.HandleCommandLine(Dispatcher)
    else:
        dispatcher = Dispatcher()
        dispatcher.start()


if __name__ == "__main__":
    main()
