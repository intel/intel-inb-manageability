"""
    Registry Manager is used to store and manage the node agents.

    Internal_clock explanation:
    When the registry manager is initialized, it gets the current
    timestamp in the system and stored it inside self._internal_clock.
    Then, there is a thread that run the internal clock by adding the
    second to it. Every registered node and heartbeat received from node
    will be recorded by referring to the internal clock. To determine the
    node heartbeat is expired, the registry manager will check the time
    interval between the current internal clock timestamp and the heartbeat
    timestamp(which is recorded based on internal clock, not system time.).
    This way removes the dependency on the system time.

    Copyright (C) 2019-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Optional, Tuple, List
from threading import Lock
from time import sleep

from .constant import HEARTBEAT_ACTIVE_STATE, HEARTBEAT_IDLE_STATE, INTERNAL_CLOCK_INTERVAL
from .configuration_constant import CONFIG_HEARTBEAT_CHECK_INTERVAL_SECS, CONFIG_HEARTBEAT_RETRY_LIMIT, \
    CONFIG_IS_ALIVE_TIMER_SECS
from .data_handler.idata_handler import IDataHandler
from inbm_vision_lib.timer import Timer
from inbm_vision_lib.xlink.ixlink_wrapper import check_platform_type

logger = logging.getLogger(__name__)


class Firmware(object):
    """Node registration information.

    @param boot_fw_date: Firmware Date
    @param boot_fw_vendor: Firmware Vendor
    @param boot_fw_version: Firmware Version
    """

    def __init__(self, boot_fw_date: datetime, boot_fw_vendor: str, boot_fw_version: str) -> None:
        self.boot_fw_date = boot_fw_date
        self.boot_fw_vendor = boot_fw_vendor
        self.boot_fw_version = boot_fw_version


class OperatingSystem(object):
    """Node registration information.

    @param os_type: Operating System on the node
    @param os_version: Operating System version
    @param os_release_date: Operating System release date
    """

    def __init__(self, os_type: str, os_version: str, os_release_date: datetime) -> None:
        self.os_type = os_type
        self.os_version = os_version
        self.os_release_date = os_release_date


class Hardware(object):
    """Node registration information.

    @param manufacturer: Board manufacturer
    @param platform_type: Type of platform. E.g. KMB, TBH
    @param flashless: True if platform is flashless; otherwise, false.
    @param stepping: stepping of SKU
    @param sku: soc version
    @param model: board model
    @param serial_num: board serial number
    @param platform_product: platform product
    """

    def __init__(self, flashless: bool, manufacturer: str, platform_type: str, stepping: str, sku: str, model: str,
                 serial_num: str, platform_product: str, version: str) -> None:
        self.is_flashless = flashless
        self.manufacturer = manufacturer
        self.platform_type = platform_type
        self.stepping = stepping
        self.sku = sku
        self.model = model
        self.serial_num = serial_num
        self.platform_product = platform_product
        self.version = version


class Security(object):
    """Node registration information.

    @param dm_verity_enabled: True if DM_Verity enabled; otherwise, false.
    @param measured_boot_enabled: True if measured boot enabled; otherwise, false.
    @param is_provisioned: True if provisioned; otherwise, false.
    @param is_xlink_secured: True if use secure xlink; otherwise, false.
    @param guid: GUID of tbh. Retrieve the value from secure xlink library.
    """

    def __init__(self,  dm_verity_enabled: bool, measured_boot_enabled: bool, is_provisioned: Optional[bool],
                 is_xlink_secured: bool, guid: int) -> None:
        self.dm_verity_enabled = dm_verity_enabled
        self.measured_boot_enabled = measured_boot_enabled
        self.is_provisioned = is_provisioned
        self.is_xlink_secured = is_xlink_secured
        self.guid = guid


class Status(object):
    """Node registration information.

    @param heartbeat_timestamp: Timestamp of the last heartbeat sent from node.
    """

    def __init__(self, heartbeat_timestamp: datetime) -> None:
        self.heartbeat_retries = 0
        self.heartbeat_timestamp = heartbeat_timestamp
        self.heartbeat_status = HEARTBEAT_ACTIVE_STATE


class Registry(object):
    """Node registration information.
    @param device_id: ID of the node

    """

    def __init__(self, device_id: str, firmware: Firmware, hardware: Hardware, os: OperatingSystem,
                 security: Security, status: Status) -> None:
        self.device_id = device_id
        self.firmware = firmware
        self.hardware = hardware
        self.os = os
        self.security = security
        self.status = status


class RegistryManager(object):
    """Stores and manages the node agent's registry information

    @param data_handler: instance of data_handler object
    @param hb_check_interval: time between checking for node heartbeats
    """

    def __init__(self, data_handler: IDataHandler,
                 hb_check_interval: int = CONFIG_HEARTBEAT_CHECK_INTERVAL_SECS.default_value) -> None:
        self._data_handler_callback = data_handler
        self._heartbeat_check_interval: int = hb_check_interval
        self._heartbeat_retry_limit: int = CONFIG_HEARTBEAT_RETRY_LIMIT.default_value
        self._is_alive_interval: int = CONFIG_IS_ALIVE_TIMER_SECS.default_value
        self._registries: List[Registry] = []
        self._internal_clock: datetime = datetime.now()
        self._interval_clock_run = Timer(INTERNAL_CLOCK_INTERVAL, self._start_internal_clock)
        self._interval_clock_run.start()
        logger.info("Checking heartbeat every %i seconds.", self._heartbeat_check_interval)
        self.HB_interval_check = Timer(self._heartbeat_check_interval, self._start_heartbeat_timer)
        self.HB_interval_check.start()
        self._register_lock = Lock()
        self._delete_node_lock = Lock()

    def _start_internal_clock(self) -> None:
        """Start running the internal clock."""
        self._internal_clock = self._internal_clock + timedelta(seconds=INTERNAL_CLOCK_INTERVAL)
        self._interval_clock_run = Timer(INTERNAL_CLOCK_INTERVAL, self._start_internal_clock)
        self._interval_clock_run.start()

    def _add_registry(self, registry) -> None:
        """Add a node agent to registry list

        @param registry: a registry object that contains the node agent information
        """
        logger.debug("Request to add node-agent's registry.")
        logger.debug("Check the existence of node-agent...")
        # Add mutex lock to prevent duplicate node registration in the list
        while not self._register_lock.acquire():
            sleep(1)
        node_device, device_index = self.get_device(registry.device_id)
        if node_device:
            logger.debug("Node-agent exist.")
            # Check if the new registration has different fw/os date/version
            if registry.firmware.boot_fw_date != node_device.firmware.boot_fw_date or \
                    registry.firmware.boot_fw_version != node_device.firmware.boot_fw_version or \
                    registry.os.os_version != node_device.os.os_version or \
                    registry.os.os_release_date != node_device.os.os_release_date:

                message = "Platform with node id-{0} has been updated. " \
                          "Firmware version from {1} {2} to {3} {4}. " \
                          "OS from version-{5} {6} to version-{7} {8}".format(
                              node_device.device_id, node_device.firmware.boot_fw_date, node_device.firmware.boot_fw_version,
                              registry.firmware.boot_fw_date, registry.firmware.boot_fw_version, node_device.os.os_version,
                              node_device.os.os_release_date, registry.os.os_version, registry.os.os_release_date)
                self._data_handler_callback.create_telemetry_event(node_device.device_id, message)

            self.delete_registry(node_device, device_index)

        logger.debug('One node-agent added with information:')
        firmware_readable_info = str(vars(registry.firmware))
        hardware_readable_info = str(vars(registry.hardware))
        os_readable_info = str(vars(registry.os))
        security_readable_info = str(vars(registry.security))
        status_readable_info = str(vars(registry.status))
        node_readable_info = f'{firmware_readable_info} {hardware_readable_info} {os_readable_info} {security_readable_info} {status_readable_info}'
        logger.debug(node_readable_info)
        self._registries.append(registry)
        self._data_handler_callback.send_node_register_response(registry.device_id)
        self._data_handler_callback.create_telemetry_event(registry.device_id, f'One node-agent added with information: '
                                                           + node_readable_info)

        self._register_lock.release()

    def add(self, node_info, node_id) -> None:
        """Create Registry object and add it to the list

        @param node_info: a directory representing node agent information
        @param node_id: string representing node device id
        """
        boot_fw_date = node_info["bootFwDate"]
        boot_fw_vendor = node_info["bootFwVendor"]
        boot_fw_version = node_info["bootFwVersion"]
        device_id = node_id
        heartbeat_timestamp = self._internal_clock
        os_type = node_info["osType"]
        os_version = node_info["osVersion"]
        os_release_date = node_info["osReleaseDate"]
        manufacturer = node_info["manufacturer"]
        dm_verity_enabled = node_info["dmVerityEnabled"]
        measured_boot_enabled = node_info["measuredBootEnabled"]
        is_flashless = node_info["flashless"]
        is_xlink_secured = node_info["is_xlink_secure"]
        stepping = node_info["stepping"]
        is_provisioned = node_info["is_provisioned"]
        sku = node_info["sku"]
        model = node_info["model"]
        serial_num = node_info["serialNumber"]
        platform_product = node_info["product"]
        guid = node_info["guid"]

        new_firmware = Firmware(boot_fw_date=boot_fw_date,
                                boot_fw_vendor=boot_fw_vendor,
                                boot_fw_version=boot_fw_version)
        new_os = OperatingSystem(os_type=os_type,
                                 os_version=os_version,
                                 os_release_date=os_release_date)
        new_hardware = Hardware(flashless=is_flashless,
                                manufacturer=manufacturer,
                                platform_type=check_platform_type(node_id.split('-')[-1]),
                                stepping=stepping,
                                sku=sku,
                                model=model,
                                serial_num=serial_num,
                                platform_product=platform_product,
                                version=node_info["version"])

        new_security = Security(dm_verity_enabled=dm_verity_enabled,
                                measured_boot_enabled=measured_boot_enabled,
                                is_provisioned=is_provisioned,
                                is_xlink_secured=is_xlink_secured,
                                guid=guid)
        new_status = Status(heartbeat_timestamp=heartbeat_timestamp)
        new_node_registry = Registry(device_id=device_id,
                                     firmware=new_firmware,
                                     hardware=new_hardware,
                                     os=new_os,
                                     security=new_security,
                                     status=new_status)

        self._add_registry(new_node_registry)

    def delete_registry(self, node_device, device_index) -> None:
        """Delete a node agent from registry list

        @param node_device: a registry object representing the node agent to be deleted
        @param device_index: an integer representing the index of targeted node agent in list
        """
        logger.debug("Delete node with deviceID: %s", node_device.device_id)
        self._registries.pop(device_index)

    def get_device(self, device_id) -> Tuple[Any, Optional[int]]:
        """Gets node information from registry list

        @param device_id: a string contains the device id of targeted node agent
        @return: returns registry object and its index or None
        """
        logger.debug("Get information of node-agent with deviceID: %s", device_id)
        if len(self._registries) != 0:
            for index, registry_object in enumerate(self._registries):
                if registry_object.device_id == device_id:
                    logger.debug("Device found.")
                    return registry_object, index
        logger.debug("No device found.")
        return None, None

    def get_target_ids(self, targets: List[str]) -> List[str]:
        """Get the list of active node ids.  If target is None, return all active nodes.

        @param targets: list of nodes to be checked
        @return: list of active nodes ids
        """
        node_ids = []
        nodes = self.get_targets(targets)

        for node in nodes:
            node_ids.append(node.device_id)
        return node_ids

    def get_targets(self, targets: Optional[List[str]]) -> List[Registry]:
        """Get the list of active nodes. If target is None, return all active nodes.

        @param targets: list of nodes to be obtained
        @return: list of active nodes
        """
        return self._check_targets_active(targets) if targets else self._get_all_active_nodes()

    def _check_targets_active(self, targets: List[str]) -> List[Registry]:
        active_nodes = []
        if targets:
            for target in targets:
                target_node, target_num = self.get_device(target)
                if target_node and target_node.status.heartbeat_status is HEARTBEAT_ACTIVE_STATE:
                    active_nodes.append(target_node)
        return active_nodes

    def _get_all_active_nodes(self) -> List[Registry]:
        """Gets the list of all active nodes.

        @return: list of active nodes
        """
        active_nodes = []
        if len(self._registries) > 0:
            for node in self._registries:
                if node.status.heartbeat_status is HEARTBEAT_ACTIVE_STATE:
                    active_nodes.append(node)
        return active_nodes

    @staticmethod
    def _calculate_time_interval(previous_timestamp, current_timestamp):
        """Calculates the time interval between two timestamps

        @param previous_timestamp: datetime object that represents previous timestamp
        @param current_timestamp: datetime object that represents current timestamp
        @return: returns float that represents time interval in seconds
        """
        time_interval = abs((previous_timestamp - current_timestamp).total_seconds())
        logger.debug("Time interval: %d", time_interval)
        return time_interval

    def _is_heartbeat_active(self, heartbeat_timestamp) -> bool:
        """Determine whether the heartbeat of a node agent is still active.

        @param heartbeat_timestamp: A datetime object represent the previous heartbeat timestamp.
        @return: returns boolean values
        """
        logger.debug("Current HEARTBEAT CHECK INTERVAL is %i seconds",
                     self._heartbeat_check_interval)
        if (self._heartbeat_check_interval - self._calculate_time_interval(heartbeat_timestamp,
                                                                           self._internal_clock)) > 0.0:
            logger.debug("Heartbeat is in good condition.")
            return True
        else:
            logger.debug("Heartbeat expired.")
            return False

    def is_node_flashless(self, node_id: str) -> Optional[bool]:
        """Determine whether the node is flashless.

        @param node_id: node device id to be checked
        @return: True for flashless device. False for non-flashless device.
        """
        if len(self._registries) != 0:
            for index, registry_object in enumerate(self._registries):
                if registry_object.device_id == node_id:
                    return registry_object.hardware.is_flashless
        logger.debug("No device found.")
        return None

    def check_heartbeat(self) -> None:
        """Check every node agents' heartbeat in registry list.
        This method starts periodically based on the time(s) defined in HEARTBEAT_CHECK_INTERVAL.
        """
        logger.debug("Checking heartbeat.")
        if len(self._registries) != 0:
            logger.debug("Detected %i node-agents.", len(self._registries))
            for index, registry_object in enumerate(self._registries[:]):
                logger.info(
                    "__________________________________________________________________________")
                logger.info("Node-agent %i deviceID: %s.", index, registry_object.device_id)
                if self._is_heartbeat_active(registry_object.status.heartbeat_timestamp):
                    logger.info("Update heartbeat to " + HEARTBEAT_ACTIVE_STATE + ".")
                    self._update_heartbeat_status(registry_object, HEARTBEAT_ACTIVE_STATE)
                else:
                    self._handle_inactive_heartbeat(registry_object)
                logger.info(
                    "__________________________________________________________________________")
        elif len(self._registries) == 0:
            logger.info("No device exist. Skip check heartbeat.")

    def _handle_inactive_heartbeat(self, node_device) -> None:
        """Method to handle unresponsive node agent. It has following functions:
        - Update the heartbeat to Idle state
        - Increase the heartbeat retries
        - Send the IsAlive request to node agent if it reaches heartbeat retries limit

        @param node_device: A registry object contains the node agent's information.
        """
        logger.info("Update heartbeat to " + HEARTBEAT_IDLE_STATE + ".")
        self._update_heartbeat_status(node_device, HEARTBEAT_IDLE_STATE)
        node_device.status.heartbeat_retries = node_device.status.heartbeat_retries + 1
        logger.info("heartbeat_retries increased by 1. The current heartbeat retries of %s is %i.",
                    node_device.device_id, node_device.status.heartbeat_retries)
        if node_device.status.heartbeat_retries == self._heartbeat_retry_limit:
            logger.info("Exceed heartbeat retry limit. IsAlive request sent.")
            self._data_handler_callback.send_is_alive(node_device.device_id)
            is_alive_timer = Timer(self._is_alive_interval,
                                   self.manage_is_alive_response, node_device.device_id)
            is_alive_timer.start()

    def _start_heartbeat_timer(self) -> None:
        """Timer to start the heartbeat checking periodically."""
        self.HB_interval_check = Timer(self._heartbeat_check_interval, self._start_heartbeat_timer)
        self.HB_interval_check.start()
        self.check_heartbeat()

    def stop_heartbeat_timer(self) -> None:
        """Stops the on-going heartbeat timer"""
        if self.HB_interval_check:
            self.HB_interval_check.stop()
            logger.info("Stop checking heartbeat.")

    def stop_internal_clock(self) -> None:
        """Stops the internal clock timer"""
        if self._interval_clock_run:
            self._interval_clock_run.stop()
            logger.debug("Stop internal clock.")

    def stop(self) -> None:
        """Stops all timer in Register Manager"""
        self.stop_heartbeat_timer()
        self.stop_internal_clock()

    def _update_heartbeat_status(self, node_device, status) -> None:
        """Update the heartbeat status of a node agent

        @param node_device: a registry object representing the node agent to be updated
        @param status: status to be updated, either HEARTBEAT_ACTIVE_STATE or HEARTBEAT_IDLE_STATE
        """
        logger.debug(f'Heartbeat status of {node_device.device_id} updated from {node_device.status.heartbeat_status} '
                     f'to {status}.')
        node_device.status.heartbeat_status = status

    def update_heartbeat_timestamp(self, node_id: str) -> None:
        """Update the heartbeat timestamp of a node agent

        @param node_id: a string contains the device id of targeted node agent to be updated
        """
        node_device, device_index = self.get_device(node_id)
        if node_device:
            logger.debug("Device exist. Update heartbeat.")
            node_device.status.heartbeat_timestamp = self._internal_clock
            node_device.status.heartbeat_status = HEARTBEAT_ACTIVE_STATE
            node_device.status.heartbeat_retries = 0
            self._data_handler_callback.send_heartbeat_response(node_id)
        else:
            error_msg = "Device with id '{}' not found. Update heartbeat failed.".format(node_id)
            logger.error(error_msg)
            self._data_handler_callback.create_telemetry_event(node_id, error_msg)
            logger.info("Send Reregister request to node {0}.".format(node_id))
            self._data_handler_callback.send_reregister_request(node_id)

    def manage_is_alive_response(self, node_id) -> None:
        """Callback method to handle isAlive response of a node after the timer expired
        - Remove the node agent from list if it doesn't response after the timer expired
        - If the heartbeat status is updated, do nothing
        - If the heartbeat status is Idle but the heartbeat retry is not reach the limit, do nothing

        @param node_id: a string contains the device id of targeted node agent
        """
        node_device, device_index = self.get_device(node_id)
        if node_device:
            if node_device.status.heartbeat_status is HEARTBEAT_IDLE_STATE and node_device.status.heartbeat_retries \
                    >= self._heartbeat_retry_limit:
                logger.info("Exceed heartbeat retry limit. No response received from node.")
                while not self._delete_node_lock.acquire():
                    sleep(1)
                self.delete_registry(node_device, device_index)
                self._delete_node_lock.release()
                # If node no longer active, try to reset it as a last ditch effort to get the node to respond.
                self._data_handler_callback.reset_device(node_device.device_id)
        else:
            logger.error(f"Device with id '{node_id}' not found.")

    def update_heartbeat_check_interval(self, value: int) -> None:
        """ Method to update heartbeat check interval

        @param value: (int) new value of HB_interval_check
        """
        logger.info(
            f'Vision-agent heartbeat check interval updates from {self._heartbeat_check_interval} to {value}.')
        self._heartbeat_check_interval = value
        self.stop_heartbeat_timer()
        self._start_heartbeat_timer()

    def update_heartbeat_retry_limit(self, value: int) -> None:
        """ Method to update heartbeat retry limit

        @param value: (int) new value of heartbeat_retry_limit
        """
        logger.info(
            f'Vision-agent heartbeat retry limit updates from {self._heartbeat_retry_limit} to {value}.')
        self._heartbeat_retry_limit = value

    def update_is_alive_interval(self, value: int) -> None:
        """ Method to update isAlive check interval value

        @param value: (int) new value of isAlive check interval value
        """
        logger.info(f'isAlive check interval updates from {self._is_alive_interval} to {value}.')
        self._is_alive_interval = value

    def find_fota_targets(self, registry_info: dict) -> List[str]:
        """Find the targets that matches the following registry information.
        1. Check Vendor, Manufacturer and Product matches
        2. Check release date of update is ahead of release date in registry

        @param registry_info: the information of registry in manifest
        @return: a list of nodes that fulfill the requirements
        """
        targets = []
        release_date = datetime.strptime(registry_info["releasedate"], '%Y-%m-%d')
        for index, registry_object in enumerate(self._registries):
            if registry_object.firmware.boot_fw_vendor == registry_info["vendor"] and \
                    registry_object.hardware.manufacturer == registry_info["manufacturer"]:
                # compare release date and firmware date in registry
                if release_date > registry_object.firmware.boot_fw_date:
                    logger.info("Node {0} has same vendor and manufacturer with firmware date {1}.".format(
                        registry_object.device_id, registry_object.firmware.boot_fw_date))
                    targets.append(registry_object.device_id)

        logger.info("Similar targets found: {0}".format(targets if targets else "0"))
        return targets
