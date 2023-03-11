"""
    Superclass responsible for device power and decommissioning.

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
import sys
import abc
import os

from inbm_common_lib.shell_runner import PseudoShellRunner
from ..dispatcher_exception import DispatcherException
from ..device_manager.constants import (
    LINUX_POWER, LINUX_SHUTDOWN, LINUX_RESTART,
    WIN_POWER, WIN_SHUTDOWN, WIN_RESTART,
    SUCCESS_RESTART, SUCCESS_SHUTDOWN, SUCCESS_DECOMMISSION,
    LINUX_SECRETS_FILE)

logger = logging.getLogger(__name__)


class DeviceManager(abc.ABC):

    @abc.abstractmethod
    def restart(self):
        """Restart the device

        @return: (str) Message on success
        """

    @abc.abstractmethod
    def shutdown(self):
        """Shutdown the device

        @return: (str) Message on success
        """

    @abc.abstractmethod
    def decommission(self):
        """Decommission the device

        @return: (str) Message on success
        """


class LinuxDeviceManager(DeviceManager):

    def __init__(self) -> None:
        self.runner = PseudoShellRunner()

    def restart(self) -> str:
        (out, err, code) = self.runner.run(LINUX_POWER + LINUX_RESTART)
        if code != 0:
            raise DispatcherException(f"Restart FAILED. Error:{err}")
        return SUCCESS_RESTART

    def shutdown(self) -> str:
        self.runner.run(LINUX_POWER + LINUX_SHUTDOWN)
        return SUCCESS_SHUTDOWN

    def decommission(self) -> str:
        try:
            os.remove(LINUX_SECRETS_FILE)
        except OSError as e:
            raise DispatcherException(
                f"Decommission failed: unable to remove {LINUX_SECRETS_FILE}") from e
        self.shutdown()
        return SUCCESS_DECOMMISSION


class WindowsDeviceManager(DeviceManager):

    def __init__(self) -> None:
        self.runner = PseudoShellRunner()

    def restart(self) -> str:
        (out, err, code) = self.runner.run(WIN_POWER + WIN_RESTART)
        return SUCCESS_RESTART

    def shutdown(self) -> str:
        self.runner.run(WIN_RESTART + WIN_SHUTDOWN)
        return SUCCESS_SHUTDOWN

    def decommission(self):
        raise NotImplementedError("Decommissioning not supported")


def get_device_manager() -> DeviceManager:
    """Get an OS specific DeviceManager

    @return: (DeviceManager)
    @exception NotImplementedError: If OS is not supported
    """
    win32 = sys.platform.startswith('win32')
    linux = sys.platform.startswith('linux')

    if linux:
        return LinuxDeviceManager()
    elif win32:
        return WindowsDeviceManager()
    else:
        raise NotImplementedError("OS not supported!")
