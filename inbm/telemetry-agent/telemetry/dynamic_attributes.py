"""
    Retrieves dynamic telemetry data

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import platform
from typing import Any, Dict, Optional, Union
from .constants import TEST_URL, TEMPERATURE_KEYS
from inbm_common_lib.constants import UNKNOWN
import psutil
import netifaces
import socket
import os
import logging
import json


logger = logging.getLogger(__name__)


def get_percent_disk_used() -> float:
    """Get percentage of disk space used.

    @return: Percentage of disk (measuring from working directory) used
    """
    return psutil.disk_usage('.').percent


def get_available_memory() -> int:
    """Get amount of memory available

    @return: Available virtual memory in bytes.
    """
    return psutil.virtual_memory().available


def get_battery_status() -> Optional[int]:
    """Get device battery percent.

    @return: The percentage.
    """
    battery = psutil.sensors_battery()
    return battery.percent if battery else None


def get_cpu_percent() -> float:
    """Get percentage of CPU used in a short interval.

    @return: The percentage.
    """
    return psutil.cpu_percent(interval=0.1)


def get_core_temp_celsius() -> Union[str, dict, float]:
    """Attempt to get the system's core temperature in celsius.

    @return: Core temp in celsius if known, otherwise Unknown
    """
    if platform.system() == 'Windows':
        return UNKNOWN  # psutil does not support this sensor in Windows

    core_temp_celsius = UNKNOWN
    try:
        sensors = psutil.sensors_temperatures(fahrenheit=False)
        if sensors == {}:
            return core_temp_celsius

        sensor_key_list = [key for key in TEMPERATURE_KEYS if key in sensors.keys()]
        temp_celsius = []
        for key in sensor_key_list:
            temp_celsius.append(sensors[key][0].current)
            logger.debug(temp_celsius)
            core_temp_celsius = max(temp_celsius)

        return core_temp_celsius
    except Exception as e:
        logger.error('get_core_temp_celsius failed: %s', e)
        return core_temp_celsius


def get_network_telemetry() -> str:
    """Construct a string with JSON-encoded system network information.

    @return: network information in JSON
    """
    result: Dict[str, Any] = {'cards': {}}

    gateways = netifaces.gateways()['default']
    gateways_af_inet = gateways.get(netifaces.AF_INET)
    if gateways_af_inet is not None:
        result['default_gateways_ipv4'] = gateways_af_inet

    gateways_af_inet6 = gateways.get(netifaces.AF_INET6)
    if gateways_af_inet6 is not None:
        result['default_gateways_ipv6'] = gateways_af_inet6

    # Ensure telemetry service never errors if network is down
    try:
        result['google.com_resolves_to'] = socket.gethostbyname(TEST_URL)
    except socket.gaierror as e:
        result['google.com_resolves_to'] = f"CANNOT BE RESOLVED: {e}"

    net = psutil.net_if_addrs()
    for card_key in list(net.keys()):
        addresses = net[card_key]
        result['cards'][card_key] = []
        for address in addresses:
            attributes = {'address': address.address,
                          'netmask': address.netmask,
                          'broadcast': address.broadcast}
            result['cards'][card_key].append(attributes)

    for var in ['http_proxy', 'HTTP_PROXY', 'https_proxy', 'HTTPS_PROXY']:
        value = os.environ.get(var)
        if value is not None:
            result[var] = value
    return json.dumps(result)
