"""
    Windows service base class for agents

    Inherit from this class and implement svc_stop and svc_main to allow an agent
    to run as a Windows service.  On other OSes, these methods will be ignored and the base class
    will be a stub.

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0 
"""
import abc
import logging
import platform
import sys
from abc import ABC

from typing import List, Any

logger = logging.getLogger(__name__)

if platform.system() == 'Windows' and 'unittest' not in sys.modules.keys():
    import socket

    import win32serviceutil

    import servicemanager
    import win32event
    import win32service
    import win32timezone  # needed for pyinstaller to handle transitive import

    class WindowsService(win32serviceutil.ServiceFramework, ABC):
        # Inherit from this class to create a service

        def __init__(self, args: List[str]) -> None:
            # name: service name
            # display_name: service display name
            # description: service description

            win32serviceutil.ServiceFramework.__init__(self, args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            socket.setdefaulttimeout(60)

        def SvcStop(self) -> None:
            # This method is called when the service is stopping

            # DO NOT RENAME

            self.svc_stop()
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.hWaitStop)

        def SvcDoRun(self) -> None:
            # This method is called when the service is starting

            # DO NOT RENAME

            servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                                  servicemanager.PYS_SERVICE_STARTED,
                                  (self._svc_name_, ''))
            self.svc_main()

        @abc.abstractmethod
        def svc_stop(self) -> None:
            # Overwrite this method to stop your service
            pass

        @abc.abstractmethod
        def svc_main(self) -> None:
            # Overwrite this method to start your service
            pass

else:  # no Windows service code
    class WindowsService:  # type: ignore

        def __init__(self, args: List[str]) -> None:
            pass
