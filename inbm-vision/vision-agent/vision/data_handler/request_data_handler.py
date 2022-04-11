"""
    Handles requests from data handler.
    - Validates request and checks for valid nodes

    @copyright: Copyright 2021-2022 Intel Corporation All Rights Reserved.
    @license: Intel, see licenses/LICENSE for more details.
"""

import logging
import datetime
from abc import ABC, abstractmethod
from typing import List

from ..parser import XLinkParser
from ..registry_manager import RegistryManager, Registry
from ..constant import NO_ACTIVE_NODES_FOUND_ERROR, HEARTBEAT_ACTIVE_STATE, VisionException

from inbm_vision_lib.constants import FOTA, SOTA, POTA, YOCTO
from inbm_common_lib.utility import remove_file

logger = logging.getLogger(__name__)


class RequestDataHandler(ABC):
    """Base class for handling OTA data
    @param registry_manager: Registry manager object.
    @param parsed_params: parameters from manifest
    """

    def __init__(self, registry_manager: RegistryManager, parsed_params: dict) -> None:
        self._registry_manager = registry_manager
        self._parsed_params = parsed_params

    @abstractmethod
    def get_validated_node_ids(self) -> List[str]:
        """Retrieves valid nodes which are active and meeting required specifications.
        @return: List of valid nodes
        """
        pass

    def _check_active_node(self, target_list: List[str]) -> List[str]:
        """Check the status of node.

        @param target_list: a list of target to be checked
        @return: a list of active node
        """
        active_nodes = []
        for node_id in target_list:
            node = self._registry_manager.get_device(node_id)[0]
            if node and node.status.heartbeat_status == HEARTBEAT_ACTIVE_STATE:
                active_nodes.append(node_id)
            else:
                error_message = "Target {0} not active.".format(node_id) \
                    if node else "Target {0} not found in the list.".format(node_id)
                logger.error(error_message)
        return active_nodes

    def _is_correct_os(self, node: Registry) -> bool:
        if node.os.os_type != YOCTO:
            logger.debug("Node OS type is different than what is in manifest.")
            self.remove_ota_file()
            return False
        return True

    def _is_newer_release(self, manifest_release_tag: str, system_release_date: datetime.datetime) -> bool:
        if system_release_date:
            manifest_date_time = XLinkParser.create_date_time_from_string(
                str(self._parsed_params[manifest_release_tag]), "%Y-%m-%d")
            if not manifest_date_time or manifest_date_time <= system_release_date:
                logger.debug("Date in manifest is unknown or not after system (node) release date.")
                self.remove_ota_file()
                return False
        return True

    def _is_correct_platform(self, manufacturer: str, vendor: str, product: str) -> bool:
        if product and product != self._parsed_params["product"]:
            logger.debug("Product registered={0}, manifest={1}".format(
                product, self._parsed_params["product"]))
            self.remove_ota_file()
            return False
        if manufacturer != self._parsed_params["manufacturer"] or vendor != self._parsed_params["vendor"]:
            logger.debug("Manufacturer registered={0}, manifest={1}".format(
                manufacturer, self._parsed_params["manufacturer"]))
            logger.debug("Vendor registered={0}, manifest={1}".format(
                vendor, self._parsed_params["vendor"]))
            self.remove_ota_file()
            return False
        return True

    def remove_ota_file(self) -> None:
        """remove ota file"""
        try:
            remove_file(self._parsed_params["path"])
        except KeyError:
            # POTA have two paths
            remove_file(self._parsed_params["fota_path"])
            remove_file(self._parsed_params["sota_path"])


class GeneralDataHandler(RequestDataHandler):
    """Concrete class for handling other requests such as Configuration and Restart

    @param registry_manager: Registry manager object.
    @param parsed_params: parameters from manifest
    @param nodes: requested nodes to receive request
    """

    def __init__(self, registry_manager: RegistryManager, parsed_params: dict, nodes: List[str]) -> None:
        super().__init__(registry_manager, parsed_params)
        if not nodes:
            self._targets = self._registry_manager.get_target_ids([])
        else:
            self._targets = self._check_active_node(nodes)

    def get_validated_node_ids(self) -> List[str]:
        """Retrieves valid node ids which are active and meeting required specifications.

        @return: Valid nodes
        """
        if not self._targets:
            raise VisionException(NO_ACTIVE_NODES_FOUND_ERROR + "  request failed.")
        return self._targets

    def get_validated_nodes(self) -> List[Registry]:
        """Retrieves valid nodes which are active and meeting required specifications.

        @return: Valid nodes
        """
        if not self._targets:
            raise VisionException(NO_ACTIVE_NODES_FOUND_ERROR + "  request failed.")
        return self._registry_manager.get_targets(self._targets)


class FotaDataHandler(RequestDataHandler):
    """Concrete class for handling FOTA requests

    @param registry_manager: Registry manager object.
    @param parsed_params: parameters from manifest
    @param nodes: requested nodes to receive request
    """

    def __init__(self, registry_manager: RegistryManager, parsed_params: dict, nodes: List[str]) -> None:
        super().__init__(registry_manager, parsed_params)
        if not nodes:
            self._targets = self._registry_manager.get_target_ids([])
        else:
            self._targets = self._check_active_node(nodes)

    def get_validated_node_ids(self) -> List[str]:
        """Retrieves valid nodes which are active and meeting required specifications.
        @return: List of valid nodes
        """
        valid_targets = self._targets.copy()
        for node_id in self._targets:
            node = self._registry_manager.get_device(node_id)[0]
            if node and valid_targets:
                if not self._is_correct_platform(node.hardware.manufacturer,
                                                 node.firmware.boot_fw_vendor, node.hardware.platform_product):
                    valid_targets.remove(node_id)
                elif not self._is_newer_release("releasedate", node.os.os_release_date):
                    valid_targets.remove(node_id)
        return valid_targets


class SotaDataHandler(RequestDataHandler):
    """Concrete class for handling SOTA requests

    @param registry_manager: Registry manager object.
    @param parsed_params: parameters from manifest
    @param nodes: requested nodes to receive request
    """

    def __init__(self, registry_manager: RegistryManager, parsed_params: dict, nodes: List[str]) -> None:
        super().__init__(registry_manager, parsed_params)
        if not nodes:
            # if the targets not found inside the list, vision-agent determine the targets on its own.
            nodes = self._registry_manager.get_target_ids([])
        self._targets = self._check_active_node(nodes)

    def get_validated_node_ids(self) -> List[str]:
        """Retrieves valid nodes which are active and meeting required specifications.

        @return: Valid nodes
        """
        valid_targets = self._targets.copy()
        for node_id in self._targets:
            node = self._registry_manager.get_device(node_id)[0]
            if not node:
                logger.info(
                    "Node {0} is not a registered node, removed from OTA target list.".format(node_id))
                valid_targets.remove(node_id)
            elif not self._is_correct_os(node):
                valid_targets.remove(node_id)
            elif not self._is_newer_release("release_date", node.os.os_release_date):
                valid_targets.remove(node_id)
        return valid_targets


class PotaDataHandler(RequestDataHandler):
    """Concrete class for handling POTA requests

    @param registry_manager: Registry manager object.
    @param parsed_params: parameters from manifest
    @param nodes: requested nodes to receive request
    """

    def __init__(self, registry_manager: RegistryManager, parsed_params: dict, nodes: List[str]) -> None:
        super().__init__(registry_manager, parsed_params)
        if not nodes:
            # if the targets not found inside the list, vision-agent determines the targets on its own.
            nodes = self._registry_manager.get_target_ids([])
        self._targets = self._check_active_node(nodes)

    def get_validated_node_ids(self) -> List[str]:
        """Retrieves valid nodes which are active and meeting required specifications.

        @return: Valid nodes
        """
        valid_targets = self._targets.copy()
        for node_id in self._targets:
            node = self._registry_manager.get_device(node_id)[0]
            if node and valid_targets:
                if not node:
                    logger.info(
                        "Node {0} is not a registered node, removed from OTA target list.".format(node_id))
                    valid_targets.remove(node_id)
                elif not self._is_correct_os(node):
                    valid_targets.remove(node_id)
                elif not self._is_newer_release("release_date", node.os.os_release_date):
                    valid_targets.remove(node_id)
                elif not self._is_correct_platform(node.hardware.manufacturer,
                                                   node.firmware.boot_fw_vendor, node.hardware.platform_product):
                    valid_targets.remove(node_id)
                elif not self._is_newer_release("releasedate", node.firmware.boot_fw_date):
                    valid_targets.remove(node_id)
        return valid_targets


def get_dh_factory(request_type: str, registry_manager: RegistryManager, parsed_params: dict, nodes: List[str]) \
        -> RequestDataHandler:
    """Create an OTA factory of a specified OTA type

    @param request_type: Type of request (FOTA, SOTA, POTA)
    @param registry_manager: Registry manager object.
    @param parsed_params: parameters from manifest
    @param nodes: requested nodes to receive request

    @raise ValueError: Unsupported OTA type
    """

    logger.debug("ota_type: {}".format(request_type))
    if request_type == FOTA:
        return FotaDataHandler(registry_manager, parsed_params, nodes)
    if request_type == SOTA:
        return SotaDataHandler(registry_manager, parsed_params, nodes)
    if request_type == POTA:
        return PotaDataHandler(registry_manager, parsed_params, nodes)
    raise VisionException('Unsupported update type: {}'.format(str(request_type)))
