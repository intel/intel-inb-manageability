"""
    DataHandler for manifests received using the type: command (provision_node)
    TODO:  move restart, etc. here too

    @copyright: Copyright 2021 Intel Corporation All Rights Reserved.
    @license: Intel, see licenses/LICENSE for more details.
"""


import logging

import inbm_vision_lib
import master.manifest_parser

from inbm_vision_lib.constants import XmlException
from inbm_vision_lib.ota_parser import ParseException
from .idata_handler import IDataHandler

from inbm_common_lib.pms.pms_helper import PMSHelper, PmsException
from inbm_vision_lib.xlink.xlink_utility import get_all_xlink_pcie_device_ids, filter_first_slice_from_list
from inbm_vision_lib.path_prefixes import IS_WINDOWS
from inbm_vision_lib.xlink.xlink_secure_wrapper import XlinkSecureWrapper

from ..constant import MASTER_ID, MasterException, XLINK_PROVISION_PATH

logger = logging.getLogger(__name__)


def receive_provision_node_request(manifest: str, data_handler: IDataHandler) -> None:
    """Handles a provision node request received via MQTT.

    @param manifest: manifest received via MQTT
    @param data_handler: DataHandler object
    """
    try:
        parsed_manifest = master.manifest_parser.ParsedManifest.from_instance(
            master.manifest_parser.parse_manifest(manifest))
        logger.debug("Execute provisionNode command.")
        for path in parsed_manifest.info:
            inbm_vision_lib.utility.move_file(
                parsed_manifest.info[path], XLINK_PROVISION_PATH)
        data_handler.send_telemetry_response(
            MASTER_ID, inbm_vision_lib.constants.create_success_message("Provision command: COMPLETE"))

        # Restart device after storing blob and cert file.
        _restart_device_after_provision_node_command(
            parsed_manifest.info["blob_path"].rsplit("/")[-1])

    except (XmlException, OSError, MasterException, ParseException) as error:
        data_handler.send_telemetry_response(MASTER_ID, inbm_vision_lib.constants.create_error_message(
            f"Command PROVISION_NODE FAILED: {error}"))


def _restart_device_after_provision_node_command(file_name: str) -> None:
    """ After downloading Blob & Cert and storing it at /opt/xlink_provision, reset the device to corresponding driver.
    Before secure xlink provisioning, it will not function. No nodes will be able to connect with the vision-agent.
    The restart command will not work.
    To reset device, we need sw_device_id. The only way to identify sw_device_id in current scenario is by getting the
    sw_device_id from blob/cert name.
    1. Get the GUID from read_guid API in secure xlink library.
    2. Compare the GUID with the GUID in blob file's name.
    3. If both GUIDs match, we get the matching sw device id.
    4. Pass the sw device id to PMS reset API to reset device.

    @param file_name: file name of the blob file
    """
    is_device_reset = False
    file_guid = file_name.rsplit("_")[0]
    all_xlink_dev_list = get_all_xlink_pcie_device_ids(0) \
        if not IS_WINDOWS else get_all_xlink_pcie_device_ids(64)
    xlink_first_slice_list = filter_first_slice_from_list(all_xlink_dev_list)

    logger.debug(f"SW ID to be checked = {xlink_first_slice_list}")
    for xlink in xlink_first_slice_list:
        try:
            guid, svn = XlinkSecureWrapper.get_guid(xlink)  # type: ignore
            if guid == file_guid:
                PMSHelper().reset_device(str(xlink))
                is_device_reset = True
                break
        except (AttributeError, PmsException) as error:
            logger.error(f"Failed to reset device: {error}")

    if not is_device_reset:
        raise MasterException(f"Failed to reset device due to no matching device id - {file_guid}.")
