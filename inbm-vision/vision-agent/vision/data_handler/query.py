"""
    Handle Query request from cloud or INBC tool
    @copyright: Copyright 2019-2022 Intel Corporation All Rights Reserved.
    @license: Intel, see licenses/LICENSE for more details.
"""
from typing import List, Optional, Dict
from inbm_vision_lib.utility import create_date
from vision.node_communicator.node_connector import NodeConnector

from ..registry_manager import Registry
from ..constant import VisionException


def _create_query_response(query_type: str, target: Registry):
    msg = None
    if query_type == "all":
        msg = {"boot_fw_date": create_date(target.firmware.boot_fw_date),
               "boot_fw_vendor": target.firmware.boot_fw_vendor,
               "boot_fw_version": target.firmware.boot_fw_version,
               "version": target.hardware.version,
               "os_type": target.os.os_type,
               "os_version": target.os.os_version,
               "os_release_date": create_date(target.os.os_release_date),
               "heartbeat_status": target.status.heartbeat_status,
               "heartbeat_retries": str(target.status.heartbeat_retries),
               "is_flashless": str(target.hardware.is_flashless),
               "manufacturer": target.hardware.manufacturer,
               "platform_type": target.hardware.platform_type,
               "product": target.hardware.platform_product,
               "stepping": target.hardware.stepping,
               "sku": target.hardware.sku,
               "model": target.hardware.model,
               "serial_num": target.hardware.serial_num,
               "dm_verity_enabled": str(target.security.dm_verity_enabled),
               "measured_boot_enabled": str(target.security.measured_boot_enabled),
               "is_provisioned": str(target.security.is_provisioned),
               "is_xlink_secured": str(target.security.is_xlink_secured),
               "guid": str(target.security.guid)
               }

    if query_type == "fw":
        msg = {"boot_fw_date": create_date(target.firmware.boot_fw_date),
               "boot_fw_vendor": target.firmware.boot_fw_vendor,
               "boot_fw_version": target.firmware.boot_fw_version
               }

    if query_type == "os":
        msg = {"os_type": target.os.os_type,
               "os_version": target.os.os_version,
               "os_release_date": create_date(target.os.os_release_date)
               }

    if query_type == "status":
        msg = {"heartbeat_status": target.status.heartbeat_status,
               "heartbeat_retries": str(target.status.heartbeat_retries)
               }

    if query_type == "hw":
        msg = {"is_flashless": str(target.hardware.is_flashless),
               "manufacturer": target.hardware.manufacturer,
               "platform_type": target.hardware.platform_type,
               "product": target.hardware.platform_product,
               "stepping": target.hardware.stepping,
               "sku": target.hardware.sku,
               "model": target.hardware.model,
               "serial_num": target.hardware.serial_num
               }

    if query_type == "security":
        msg = {"dm_verity_enabled": str(target.security.dm_verity_enabled),
               "measured_boot_enabled": str(target.security.measured_boot_enabled),
               "is_provisioned": str(target.security.is_provisioned),
               "is_xlink_secured": str(target.security.is_xlink_secured),
               "guid": str(target.security.guid)
               }

    if query_type == "guid":
        msg = {"guid": str(target.security.guid),
               "is_provisioned": str(target.security.is_provisioned),
               }

    if msg:
        return str(msg)
    else:
        raise VisionException("Unsupported query.")


def _create_query_guid_response(node_connector: Optional[NodeConnector]) -> List[Dict]:
    """Check all the guid of nodes and its provisioned status.

    @param node_connector: node connector object
    @return: guid of node and its provisioned status
    """
    return node_connector.get_all_guid() if node_connector else []
