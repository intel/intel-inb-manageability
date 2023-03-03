"""
    Agent which monitors and reports the state of critical components of the framework

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


import logging
from typing import Optional, Dict

from .commands import Commands
from .health_checker import HealthChecker
from .command_pattern import DeviceBatteryHealthChecker, NetworkChecker, \
    StorageChecker, MemoryChecker, ContainerHealthChecker, SoftwareChecker

logger = logging.getLogger(__name__)

UNKNOWN = {'rc': 1, 'message': 'Unknown command invoked'}


def dispatch_command(command: str,
                     size: int,
                     size_path: str,
                     min_memory_mb: int,
                     min_power_percent: int,
                     min_storage_mb: int,
                     sw_list: str,
                     network_check: str) -> Optional[Dict[str, object]]:
    """Dispatches the correct command(s) based on the request

    @param command: command sent via MQTT from another agent.
    @param size: storage size required for storage command
    @param size_path: path to check storage size
    @param min_memory_mb: minimum memory required in MB for memory command
    @param min_power_percent: minimum power percent required when running on battery
    @param min_storage_mb: minimum memory required in MB for storage command
    @param sw_list: list of mandatory software
    @param network_check: value to determine network_check need
    """
    check = HealthChecker()
    if command == Commands.install_check.name:
        check.add(NetworkChecker(network_check))
        s = min_storage_mb if size is None else size
        check.add(StorageChecker(s, size_path))
        check.add(MemoryChecker(min_memory_mb))
        check.add(DeviceBatteryHealthChecker(min_power_percent))
        check.add(SoftwareChecker(sw_list))
    elif command == Commands.health_device_battery.name:
        check.add(DeviceBatteryHealthChecker(min_power_percent))
    elif command == Commands.check_storage.name:
        s = min_storage_mb if size is None else size
        check.add(StorageChecker(s, size_path))
    elif command == Commands.check_memory.name:
        check.add(MemoryChecker(min_memory_mb))
    elif command == Commands.check_network.name:
        check.add(NetworkChecker(network_check))
    elif command == Commands.container_health_check.name:
        check.add(ContainerHealthChecker())
    elif command == Commands.swCheck.name:
        check.add(SoftwareChecker(sw_list))
    else:
        logger.error('Unknown command: %s invoked', command)
        return UNKNOWN

    return check.run()
