"""
    FOTA update tool which is called from the dispatcher during installation

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
import datetime
from typing import Dict, Optional
from inbm_common_lib.platform_info import PlatformInformation


logger = logging.getLogger(__name__)


def parse(ota_element: Dict[str, str]) -> PlatformInformation:
    """Helper function for check_current_version which extracts elements from
    manifest file

    @return: Platform information parsed from manifest
    """
    logger.debug(" ")
    manifest_info = PlatformInformation()
    manifest_info.bios_release_date = datetime.datetime.strptime(
        ota_element['releasedate'], "%Y-%m-%d")
    manifest_info.bios_version = ota_element['biosversion']
    manifest_info.bios_vendor = ota_element['vendor']
    manifest_info.platform_mfg = ota_element['manufacturer']
    manifest_info.platform_product = ota_element['product']
    return manifest_info


def parse_tool_options(ota_element: Dict) -> Optional[str]:
    """Helper function for installer to extract the tool options from the manifest file

    @return: tooloptions value if tooloptions present else None
    """
    return ota_element['tooloptions'] if 'tooloptions' in ota_element else None


def parse_guid(ota_element: Dict) -> Optional[str]:
    """Helper function for installer to extract the tool options from the manifest file

    @return: guid value if guid key present else None
    """
    return ota_element['guid'] if 'guid' in ota_element else None


def parse_hold_reboot_flag(ota_element: Dict) -> bool:
    """Helper function for installer to check holdReboot flag from the manifest file

    @return: holdReboot value if holdReboot key present else None
    """
    return ota_element['holdReboot'] if 'holdReboot' in ota_element else False
