"""
    Handles retrieving power state capabities on the system.

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import dbus
import logging

logger = logging.getLogger(__name__)

def get_power_capabilities() -> dict[str, bool]:
    power_states = {
    "shutdown": False,
    "reboot": False,
    "suspend": False,
    "hibernate": False
    }

    bus = dbus.SystemBus()
    try:
        proxy = bus.get_object('org.freedesktop.login1', '/org/freedesktop/login1')
        interface = dbus.Interface(proxy, 'org.freedesktop.login1.Manager')

        power_states["shutdown"] = str(interface.CanPowerOff()) == 'yes'
        power_states["reboot"] = str(interface.CanReboot()) == 'yes'
        power_states["suspend"] = str(interface.CanSuspend()) == 'yes'
        power_states["hibernate"] = str(interface.CanHibernate()) == 'yes'
    except dbus.DBusException as e:
        logger.error("DBus error gathering power capabilities: {e}")

    return power_states
        