"""
    Gets the current power state of the system.
    Copyright (C) 2017-2025 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import dbus
import logging
from typing import Any, Optional, Tuple
from ..dispatcher_exception import DispatcherException

logger = logging.getLogger(__name__)

def _is_system_sleeping() -> Any:
    try:
        bus = dbus.SystemBus()
        proxy = bus.get_object('org.freedesktop.login1', '/org/freedesktop/login1')
        interface = dbus.Interface(proxy, 'org.freedesktop.DBus.Properties')
        sleep_state = interface.Get('org.freedesktop.login1.Manager', 'PreparingForSleep')
        return sleep_state
    except dbus.DBusException as e:
        raise DispatcherException(f"Failed to get sleep state: {e}")

def _get_sleep_state() -> Tuple[list[str], Optional[str]]:
    try:
        with open('/sys/power/state', 'r') as f:
            states = f.read().strip().split()
        with open('/sys/power/mem_sleep', 'r') as f:
            mem_sleep_states = f.read().strip().split()
            current_mem_sleep_state = None
            for state in mem_sleep_states:
                if state.startswith('[') and state.endswith(']'):
                    current_mem_sleep_state = state.strip('[]')
                    break
        return states, current_mem_sleep_state
    except FileNotFoundError as e:
        logger.error(f"Failed to get sleep state: {e}")
        return [], None

def get_current_power_state() -> str:
    sleep_state = _is_system_sleeping()
    if sleep_state:
        logger.info("The system is preparing to sleep or is currently sleeping")
        states, current_mem_sleep_state = _get_sleep_state()
        if len(states) > 0:
            logger.info(f"Available sleep states: {states}")
        if current_mem_sleep_state:
            return current_mem_sleep_state
        else:
            return "sleeping"
    else:
        return "on"
