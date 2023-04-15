"""
    Central telemetry/logging service for the manageability framework

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import platform
import threading
import time
import os
import logging
import json
from datetime import datetime
from typing import Union, Dict, Optional, Any

from inbm_lib import wmi
from inbm_lib.count_down_latch import CountDownLatch
from inbm_lib.constants import TRTL_PATH, DOCKER_STATS
from inbm_common_lib.shell_runner import PseudoShellRunner
from inbm_lib.trtl import Trtl
from inbm_lib.wmi_exception import WmiException

from inbm_common_lib.device_tree import is_device_tree_exists, get_device_tree_system_info, get_device_tree_cpu_id
from inbm_common_lib.dmi import get_dmi_system_info
from inbm_common_lib.platform_info import PlatformInformation
from inbm_common_lib.constants import UNKNOWN, TELEMETRY_CHANNEL
from inbm_common_lib.pms.pms_helper import PMSHelper, PmsException

from .static_attributes import get_total_physical_memory, get_cpu_id, get_os_information, \
    get_disk_information
from .dynamic_attributes import get_cpu_percent, get_available_memory, get_percent_disk_used, \
    get_core_temp_celsius, get_network_telemetry, get_battery_status
from .command import Command
from .telemetry_exception import TelemetryException
from inbm_lib.version import get_friendly_inbm_version_commit, get_friendly_inbm_vision_version_commit
from telemetry import software_bom_list

logger = logging.getLogger(__name__)


def _set_timestamp(telemetry, telemetry_type):
    return {'timestamp': time.time(), 'type': telemetry_type, 'values': telemetry}


def get_pms_rm_telemetry() -> str:
    """Get the PMS RM telemetry data from the device 

    @return: The telemetry information
    """
    try:
        pms = PMSHelper()
        return pms.get_rm_telemetry()
    except PmsException as e:
        return str(e)


class TelemetryTimer:
    """Handles waiting for collection and publishing."""

    def __init__(self, collect_time, publish_time, with_docker=True) -> None:
        self.__publish_slept_counter = 0
        self.__collect_slept_counter = 0
        self.__collect_time = collect_time
        self.__collect_counter = 0
        self.__publish_time = publish_time
        self.__with_docker = with_docker
        self.__publish_counter = 0
        # this lock is intended to protect config items:
        # collect_time and publish_time
        self._config_lock = threading.Lock()

    def set_collect_time(self, collect_time) -> None:
        """Sets the collection time

        @param collect_time: Time collected
        """
        self._config_lock.acquire()
        try:
            self.__collect_time = collect_time
        finally:
            self._config_lock.release()

    def set_publish_time(self, publish_time) -> None:
        """Sets the publish time

        @param publish_time: Time published"""
        self._config_lock.acquire()
        try:
            self.__publish_time = publish_time
        finally:
            self._config_lock.release()

    def wait_collect(self, max_sleep_time=0) -> None:
        """Sleep until time to collect.  If max time is not specified, use the collection time.

        @param max_sleep_time: Maximum time to sleep
        """

        self._config_lock.acquire()
        try:
            collect_time = self.__collect_time
            publish_time = self.__publish_time
        finally:
            self._config_lock.release()

        if max_sleep_time > 0:
            to_sleep = min(max_sleep_time, collect_time)
        else:
            to_sleep = collect_time

        time.sleep(to_sleep)
        self.__publish_slept_counter += to_sleep
        self.__collect_slept_counter += to_sleep

        while self.__publish_slept_counter >= publish_time:
            self.__publish_slept_counter -= publish_time
            self.__publish_counter += 1

        while self.__collect_slept_counter >= collect_time:
            self.__collect_slept_counter -= collect_time
            self.__collect_counter += 1

    def time_to_publish(self) -> bool:
        """Check if time to publish

        @return true if time to publish; otherwise, false.
        """
        if self.__publish_counter > 0:
            self.__publish_counter -= 1
            return True
        else:
            return False

    def time_to_collect(self) -> bool:
        """Check if time to collect telemetry data

        @return true if time to collect; otherwise, false
        """
        if self.__collect_counter > 0:
            self.__collect_counter -= 1
            return True
        else:
            return False


def get_container_health(client, send_topic) -> None:  # pragma: no cover
    """Collect container health.

    @param client: MQTT client
    @param send_topic: Topic to use while publishing
    """
    logger.debug("Querying diagnostic for container health.")
    cmd_lock = threading.Lock()
    latch = CountDownLatch(1)

    def on_command(topic, payload, qos):
        logger.info('Message received: %s on topic: %s', payload, topic)

        if not cmd_lock.acquire(False):
            logger.debug(
                'Received an unexpected second response to container health command. Ignoring.')
            return
        try:
            cmd.response = json.loads(payload)

        except ValueError as error:
            logger.error(f'Unable to parse payload: {error}')

        finally:
            # Release locks
            cmd_lock.release()
            latch.count_down()

    cmd = Command('container_health_check', 'cloud')

    # Subscribe to response channel using the same request ID
    client.subscribe(cmd.create_response_topic(), on_command)

    # Publish command request
    client.publish(cmd.create_request_topic(), cmd.create_payload())

    latch.await_()

    cmd_lock.acquire()
    try:
        if cmd.response is None:
            client.publish(send_topic, 'Container Health check timed out. Please '
                                       'check health of the diagnostic agent')
            return

        if cmd.response['rc'] == 0:
            client.publish(send_topic, 'Command: {} passed. Message: {}'
                           .format(cmd.command, cmd.response['message']))
            logger.info('Container Health check passed')
        else:
            client.publish(send_topic, 'Command: {} failed. Message: {}'
                           .format(cmd.command, cmd.response['message']))
    finally:
        cmd_lock.release()


def get_dynamic_telemetry(is_docker_installed: bool, rm_active: bool = False) -> Dict:
    """Collect dynamic telemetry in a dictionary.

    @param is_docker_installed: true if docker is on the system; else false.
    @param rm_active: true if resource manager is active; otherwise, false.
    @return: dynamic telemetry data
    """
    logger.debug("Collecting dynamic telemetry.")

    # several types possible in dictionary
    dynamic_telemetry: Dict[str, Optional[Any]] \
        = {'systemCpuPercent': get_cpu_percent(),
            DOCKER_STATS: get_docker_stats(is_docker_installed),
           'availableMemory': get_available_memory(),
           'percentDiskUsed': get_percent_disk_used(),
           'coreTempCelsius': get_core_temp_celsius(),
           'networkInformation': get_network_telemetry(),
           'friendlyINBMVersionCommit': get_friendly_inbm_version_commit(),
           'friendlyINBMVisionVersionCommit': get_friendly_inbm_vision_version_commit()}

    if rm_active:
        dynamic_telemetry['resourceMonitoring'] = get_pms_rm_telemetry()

    battery_status = get_battery_status()
    if battery_status:
        dynamic_telemetry['batteryStatus'] = battery_status

    return _set_timestamp(dynamic_telemetry, telemetry_type="dynamic_telemetry")


def get_docker_stats(is_docker_installed) -> Optional[str]:
    """Get the Docker stats if possible

    @param is_docker_installed: true if docker is on the system; else false
    @return: (str) The container usage information.
    """

    if not is_docker_installed:
        return "Docker is not installed"
    if not os.path.exists(TRTL_PATH):
        return "TRTL is not installed"

    return Trtl(PseudoShellRunner()).stats()


def publish_telemetry_update(client, topic, with_docker, to_update) -> None:
    """Update a specific telemetry item

    @param client: MQTT client exposing a publish method
    @param topic: topic on which to publish system telemetry
    @param with_docker: true if docker is on the system; else false
    @param to_update: telemetry key to update
    """
    logger.info("Got telemetry update request for: %s", to_update)
    telemetry = get_dynamic_telemetry(with_docker)
    values = {}
    for v in telemetry["values"]:
        if v == to_update:
            values[to_update] = telemetry["values"][v]
    telemetry["values"] = values
    publish_dynamic_telemetry(client, topic, telemetry)


def publish_dynamic_telemetry(client, topic, telemetry) -> None:
    """Publish dynamic (recurring) telemetry bundle.

    @param client: MQTT client exposing a publish method
    @param topic: topic on which to publish system telemetry
    @param telemetry: telemetry to publish in dictionary with special
      entry 'timestamp' to signify time
    """
    logger.debug("Publishing dynamic telemetry.")
    client.publish(topic, json.dumps(telemetry))
    logger.debug(
        "Telemetry agent published dynamic telemetry: " +
        str(telemetry))


def get_query_related_info(option: str, info: Dict) -> Dict:
    """Return query specific information by filtering the static telemetry info
    as per the query specific request.

    @param option: specifies what kind of query command is requested
    @param info: Dict containing all the static telemetry info
    @return: requested query details
    """
    del info['type']
    del info['timestamp']
    if option == "hw":
        for elem in list(info['values'].keys()):
            if elem in ['biosVendor', 'biosVersion', 'biosReleaseDate', 'osInformation']:
                del info['values'][elem]
    elif option == "fw":
        for elem in list(info['values'].keys()):
            if elem in ['diskInformation', 'totalPhysicalMemory', 'cpuId', 'osInformation', 'systemManufacturer',
                        'systemProductName']:
                del info['values'][elem]
    elif option == "os":
        for elem in list(info['values'].keys()):
            if elem in ['totalPhysicalMemory', 'cpuId', 'biosVendor', 'biosVersion', 'biosReleaseDate',
                        'systemManufacturer', 'systemProductName', 'diskInformation']:
                del info['values'][elem]
    elif option == "version":
        info = {}
        info['INBMVersionCommit'] = get_friendly_inbm_version_commit()
        info['INBMVisionVersionCommit'] = get_friendly_inbm_vision_version_commit()
    elif option == "all":
        info['INBMVersionCommit'] = get_friendly_inbm_version_commit()
        info['INBMVisionVersionCommit'] = get_friendly_inbm_vision_version_commit()
    return info


def get_static_telemetry_info() -> Dict:
    """Publish static (one time) telemetry.
    @return dictionary of static telemetry data
    """
    logger.debug("Publishing static telemetry.")
    platform_info = PlatformInformation()
    try:
        bios_release_date: Union[datetime, str]
        if platform.system() == 'Windows':
            cpu_id = get_cpu_id()
            platform_info.bios_vendor = wmi.wmic_query(
                'bios', 'manufacturer')['Manufacturer']
            platform_info.bios_version = wmi.wmic_query('bios', 'caption')[
                'Caption']
            platform_info.bios_release_date = wmi.wmic_query(
                'bios', 'releasedate')['ReleaseDate']
            platform_info.platform_mfg = wmi.wmic_query(
                'csproduct', 'vendor')['Vendor']
            platform_info.platform_product = wmi.wmic_query('csproduct', 'name')[
                'Name']
        elif is_device_tree_exists():
            platform_info = get_device_tree_system_info()
            cpu_id = get_device_tree_cpu_id()
        else:
            platform_info = get_dmi_system_info()
            cpu_id = get_cpu_id()
    except (KeyError, ValueError, WmiException) as e:
        raise TelemetryException(f"Error gathering BIOS information: {e}")

    telemetry = {'totalPhysicalMemory': str(get_total_physical_memory()),
                 'cpuId': cpu_id,
                 'biosVendor': platform_info.bios_vendor,
                 'biosVersion': platform_info.bios_version,
                 'biosReleaseDate': str(platform_info.bios_release_date),
                 'systemManufacturer': platform_info.platform_mfg,
                 'systemProductName': platform_info.platform_product,
                 'osInformation': get_os_information(),
                 'diskInformation': get_disk_information()}

    clean_telemetry = {k: (UNKNOWN if v == [] else v)
                       for k, v in telemetry.items()}
    telemetry = _set_timestamp(clean_telemetry, telemetry_type="static_telemetry")
    return telemetry


def publish_static_telemetry(client, topic) -> None:
    """Publish static (one time) telemetry.

    @param client: MQTT client exposing a publish method
    @param topic: topic on which to publish system telemetry
    """
    telemetry = get_static_telemetry_info()

    client.publish(topic, json.dumps(telemetry))
    logger.debug(
        "Telemetry agent published static telemetry: " +
        str(telemetry))


def send_initial_telemetry(client, with_docker) -> None:
    """Collect and send current static and dynamic telemetry.

    @param client: broker client
    @param with_docker: true if docker is on the system; else false.
    """
    static_succeeded = False
    max_retry_count = 5
    current_retry_count = 0
    while not static_succeeded and current_retry_count < max_retry_count:
        try:
            current_retry_count += 1
            publish_static_telemetry(client, TELEMETRY_CHANNEL)
            static_succeeded = True
        except TelemetryException as e:
            logger.error(
                "Unable to publish static telemetry: {}.  Retrying.".format(str(e)))
            time.sleep(5)

    publish_dynamic_telemetry(client, TELEMETRY_CHANNEL,
                              get_dynamic_telemetry(with_docker))

    # SWBOM
    software_bom_list.publish_software_bom(client, False)
