"""
    SOTA reboot classes.  Abstract class and concrete classes.

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
import time
import os

from ..dispatcher_broker import DispatcherBroker
from inbm_common_lib.shell_runner import PseudoShellRunner
from inbm_lib.constants import DOCKER_CHROOT_PREFIX

logger = logging.getLogger(__name__)


class Rebooter:
    """Base class for rebooting the system."""

    def __init__(self,  dispatcher_broker: DispatcherBroker) -> None:
        """Initializes the Rebooter base class

        @param dispatcher_broker: DispatcherBroker object used to communicate with other INBM services
        """
        self._dispatcher_broker = dispatcher_broker

    def reboot(self) -> None:
        """Reboots the system."""
        logger.debug("")
        self._dispatcher_broker.telemetry("Rebooting ")
        time.sleep(2)


class LinuxRebooter(Rebooter):
    """Reboots the system on a Linux OS

    @param dispatcher_broker: DispatcherBroker object used to communicate with other INBM services
    """

    def __init__(self,  dispatcher_broker: DispatcherBroker) -> None:
        super().__init__(dispatcher_broker=dispatcher_broker)
        self._dispatcher_broker = dispatcher_broker

    def reboot(self) -> None:
        super().reboot()
        is_docker_app = os.environ.get("container", False)

        cmd = "/sbin/reboot"
        if is_docker_app:
            logger.debug("APP ENV : {}".format(is_docker_app))
            (output, err, code) = PseudoShellRunner().run(DOCKER_CHROOT_PREFIX + cmd)
        else:
            (output, err, code) = PseudoShellRunner().run(cmd)
        # return code will be None if reboot is submitted but not yet executed.
        # In case of signal interruptions, it will be negative
        if code and code < 0:
            self._dispatcher_broker.telemetry(
                f"SOTA Aborted: Reboot Failed: {err}")


class WindowsRebooter(Rebooter):
    """Reboots the system on a Windows OS

    @param dispatcher_broker: DispatcherBroker object used to communicate with other INBM services
    """

    def __init__(self,  dispatcher_broker: DispatcherBroker) -> None:
        super().__init__(dispatcher_broker=dispatcher_broker)

    def reboot(self) -> None:
        pass
