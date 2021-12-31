"""
    FOTA update tool which is called from the dispatcher during installation

    Copyright (C) 2017-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
import time
from abc import ABC, abstractmethod

from ..device_manager.constants import WIN_POWER, WIN_RESTART
from ..dispatcher_callbacks import DispatcherCallbacks
from inbm_common_lib.shell_runner import PseudoShellRunner

logger = logging.getLogger(__name__)


class Rebooter(ABC):
    """Base class for rebooting the system.

    @param callback: Callback to Dispatcher
    """

    def __init__(self, callback: DispatcherCallbacks) -> None:
        self._dispatcher_callbacks = callback

    @abstractmethod
    def reboot(self) -> None: pass


class LinuxRebooter(Rebooter):
    """Derived class. Reboots the system on a Linux OS

    @param dispatcher_callbacks: callback to dispatcher
    """

    def __init__(self, dispatcher_callbacks: DispatcherCallbacks) -> None:
        super().__init__(dispatcher_callbacks)

    def reboot(self) -> None:
        """reboots the gateway"""
        logger.debug("")
        self._dispatcher_callbacks.broker_core.telemetry('Rebooting platform in 2 seconds......')
        time.sleep(2)
        (output, err, code) = PseudoShellRunner.run("reboot -f")

        if code != 0:
            self._dispatcher_callbacks.broker_core.telemetry(
                f"Firmware Update Aborted: Reboot Failed: {err}")  # pragma: no cover


class WindowsRebooter(Rebooter):
    """Derived class. Reboots the system on a Windows OS

    @param callback: callback to dispatcher
    """

    def __init__(self, callback: DispatcherCallbacks) -> None:
        super().__init__(callback)

    def reboot(self) -> None:  # pragma: no cover
        """reboots the gateway"""
        logger.debug("")
        self._dispatcher_callbacks.broker_core.telemetry('Rebooting platform in 2 seconds......')
        time.sleep(2)
        (output, err, code) = PseudoShellRunner.run(WIN_POWER + WIN_RESTART)

        if code != 0:
            self._dispatcher_callbacks.broker_core.telemetry(
                f"Firmware Update Aborted: Reboot Failed: {err}")  # pragma: no cover
