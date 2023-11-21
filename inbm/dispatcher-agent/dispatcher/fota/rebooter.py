"""
    FOTA update tool which is called from the dispatcher during installation

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
import time
import os
from abc import ABC, abstractmethod

from ..device_manager.constants import WIN_POWER, WIN_RESTART, LINUX_POWER, LINUX_RESTART
from ..dispatcher_callbacks import DispatcherCallbacks
from ..dispatcher_broker import DispatcherBroker
from inbm_common_lib.shell_runner import PseudoShellRunner
from inbm_lib.constants import DOCKER_CHROOT_PREFIX

logger = logging.getLogger(__name__)


class Rebooter(ABC):
    """Base class for rebooting the system.

    """

    def __init__(self) -> None:
        pass

    @abstractmethod
    def reboot(self) -> None:
        pass


class LinuxRebooter(Rebooter):
    """Derived class. Reboots the system on a Linux OS

    @param broker_core: MQTT broker to other INBM services
    """

    def __init__(self, broker_core: DispatcherBroker) -> None:
        super().__init__()
        self._broker_core = broker_core

    def reboot(self) -> None:
        """reboots the gateway"""
        logger.debug("")
        self._broker_core.telemetry('Rebooting platform in 2 seconds......')
        time.sleep(2)
        is_docker_app = os.environ.get("container", False)
        if is_docker_app:
            logger.debug("APP ENV : {}".format(is_docker_app))
            (output, err, code) = PseudoShellRunner.run(
                DOCKER_CHROOT_PREFIX + LINUX_POWER + LINUX_RESTART)
        else:
            (output, err, code) = PseudoShellRunner.run(LINUX_POWER + LINUX_RESTART)

        if code != 0:
            self._broker_core.telemetry(
                f"Firmware Update Aborted: Reboot Failed: {err}")  # pragma: no cover


class WindowsRebooter(Rebooter):
    """Derived class. Reboots the system on a Windows OS

    @param broker_core: MQTT broker to other INBM services
    """

    def __init__(self,  broker_core: DispatcherBroker) -> None:
        super().__init__()
        self._broker_core = broker_core

    def reboot(self) -> None:  # pragma: no cover
        """reboots the gateway"""
        logger.debug("")
        self._broker_core.telemetry('Rebooting platform in 2 seconds......')
        time.sleep(2)
        (output, err, code) = PseudoShellRunner.run(WIN_POWER + WIN_RESTART)

        if code != 0:
            self._broker_core.telemetry(
                f"Firmware Update Aborted: Reboot Failed: {err}")  # pragma: no cover
