"""
    Implementation of Command Pattern to check health of system

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
from abc import ABC

import netifaces
import psutil
import os
from typing import Dict, Union, Any

from .filesystem_utilities import get_free_space
from .util import get_free_memory

from inbm_common_lib.utility import get_canonical_representation_of_path

from inbm_lib.constants import TRTL_PATH
from inbm_lib.trtl import Trtl
from inbm_common_lib.shell_runner import PseudoShellRunner

logger = logging.getLogger(__name__)


class Command(ABC):
    """Abstract /Interface base class for commands.

    @param name: name of the command
    @param value: value used in the command
    """

    def __init__(self, name: str, value: Any) -> None:
        self._name = name
        self._value = value
        self._result: Dict[str, Any] = {}

    def execute(self) -> Dict[str, Union[str, int]]:
        logger.info(f'Running command: {self._name}')
        self._result = {'cmd': self._name, 'rc': 0}
        return self._result


class DeviceBatteryHealthChecker(Command):
    """Get the health status of the device battery

    @param value: current power percent
    """

    def __init__(self, value: Any) -> None:
        super().__init__("health_device_battery", value)

    def execute(self) -> Dict[str, Union[str, int]]:
        """executes the health_device_battery command.

        @return: Dictionary representing output of command:
        {'cmd': <command executed, 'rc': <return code - 0/1>,
         'message': <user friendly message>
        """
        super().execute()
        if self._value <= 100:
            min_power = self._value
        else:
            self._result['rc'] = 1
            self._result['message'] = 'Invalid power sent. Must be in percent'
            return self._result

        battery = psutil.sensors_battery()
        logger.debug("BATTERY : {} BATTERY Type: {}".format(battery, type(battery)))
        if battery is None:
            self._result['message'] = 'Device has no battery installed. '

        elif battery.percent < min_power and not battery.power_plugged:
            self._result['rc'] = 1
            self._result['message'] = 'Battery check failed. Charge to at least {}' \
                                      ' percent before update. Current charge %: {}' \
                .format(min_power, battery.percent)

        else:
            self._result['message'] = 'Battery check passed. Device OK for update. '

        logger.debug("BATTERY check message : {}".format(self._result['message']))
        return self._result


class NetworkChecker(Command):
    """Check health of active network interface

    @param value: networkCheck value to determine whether network check is required on a platform
    """

    def __init__(self, value: Any) -> None:
        super().__init__("check_network", value)

    def execute(self) -> Dict[str, Union[str, int]]:
        """executes the check_network command.

        @return {'rc': X, 'message': Y} where X is 0 for success, 1 for failure; Y is the associated message
        """
        super().execute()
        if self._value == 'false':
            self._result['message'] = 'Network check is disabled for the platform.'
            logger.debug(self._result)
            return self._result
        else:
            gateways = netifaces.gateways()
            if 'default' in gateways and len(gateways['default']) > 0:
                self._result['message'] = 'At least one network interface is healthy (has a default route).'
                logger.debug(self._result)
                return self._result
            else:
                self._result['rc'] = 1
                self._result['message'] = 'Network interfaces down.  Cannot find network interface with a default route.'
                logger.debug(self._result)
                return self._result


class MemoryChecker(Command):
    """Check if minimum amount of memory is present

    @param value: size of memory required
    """

    def __init__(self, value: Any) -> None:
        super().__init__("check_memory", value)

    def execute(self) -> Dict[str, Union[str, int]]:
        """executes the check_memory command.

        @return: Dictionary representing output of command:
            {'cmd': <command executed, 'rc': <return code - 0/1>,
             'message': <user friendly message>
        """
        super().execute()
        if isinstance(self._value, int):
            min_memory = self._value * 1024 * 1024
        else:
            self._result['rc'] = 1
            self._result['message'] = 'Invalid memory sent. Must be in MBs'
            return self._result

        available = get_free_memory()

        if available > min_memory:
            self._result['message'] = f'Min memory check passed. Available: {available}. '

        else:
            self._result['rc'] = 1
            self._result['message'] = 'Less than {} bytes free. Available: {}. '.format(
                min_memory, available)

        return self._result


class StorageChecker(Command):
    """Check if minimum storage is present

    @param size_required: size of the space required
    @param path: path to check
    """

    def __init__(self, size_required: int, path: str) -> None:
        super().__init__("check_storage", (size_required, path))

    def execute(self) -> Dict[str, Union[str, int]]:
        """executes the check_storage command.

        @return {'rc': X, 'message': Y} where X is 0 for success, 1 for failure; Y is the associated message
        """
        super().execute()

        (size_required, path) = self._value
        path = get_canonical_representation_of_path(path)
        if isinstance(size_required, int) or isinstance(size_required, float):
            min_storage = size_required * 1024 * 1024
        else:
            self._result['rc'] = 1
            self._result['message'] = 'Invalid size sent. Must be in MBs'
            return self._result

        free = get_free_space(path)

        if free > min_storage:
            self._result['message'] = f'Min storage check passed.  Available: {free}. '
        else:
            self._result['rc'] = 1
            self._result['message'] = 'Less than {} bytes free. Available: {}. '.format(
                min_storage, free)

        return self._result


class SoftwareChecker(Command):
    """Checks the health of the software

    @param value: software to check is installed
    """

    def __init__(self, value: Any) -> None:
        super().__init__("swCheck", value)

    def execute(self) -> Dict[str, Union[str, int]]:
        """executes the swCheck command.

        @return: Dictionary representing output of command:
            {'cmd': <command executed, 'rc': <return code - 0/1>,
             'message': <user friendly message>
        """
        super().execute()

        self._result['message'] = 'All required software present '

        if self._value is None:
            self._result['message'] = 'No required software list was found '
            return self._result

        sw_list = self._value.strip().splitlines()
        for s in sw_list:
            s = s.strip()
            if s == 'trtl':
                if not os.path.exists(TRTL_PATH):
                    self._result['rc'] = 1
                    self._result['message'] = 'Trtl not present '
                    return self._result
            else:
                command = f"systemctl is-active --quiet {s}"
                (out, err, code) = PseudoShellRunner().run(command)
                if code != 0:
                    self._result['message'] = s + ' not present'
                    self._result['rc'] = code

        return self._result


class ContainerHealthChecker(Command):
    """Checks the health of the containers

    @param value: None
    """

    def __init__(self, value=None):
        super().__init__("container_health_check", value)

    def execute(self) -> Dict[str, Union[str, int]]:
        """executes the container_health_check command.

        @return: Dictionary representing output of command:
            {'cmd': <command executed, 'rc': <return code - 0/1>,
             'message': <user friendly message>
        """
        super().execute()

        err, out = Trtl(PseudoShellRunner()).list()
        if err is None or len(err) == 0:
            self._result['rc'] = 0
            self._result['message'] = out
        else:
            self._result['rc'] = 1
            self._result['message'] = err

        return self._result
