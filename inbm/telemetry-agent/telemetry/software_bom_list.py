"""
    Retrieves Software BOM information.

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import os
import sys
import math
import logging
from typing import Any, List
from . import telemetry_handling
from inbm_lib.mqttclient.mqtt import MQTT
from inbm_lib.detect_os import detect_os, LinuxDistType
from inbm_common_lib.shell_runner import PseudoShellRunner
from .constants import MENDER_PATH, UNKNOWN, SWBOM_BYTES_SIZE, EVENTS_CHANNEL

logger = logging.getLogger(__name__)


class SoftwareBomError(Exception):
    """Class exception Module"""
    pass


def get_sw_bom_list() -> List[Any]:
    """Returns the software BOM list on the platform based on it's OS type. 

    @return: Software BOM list.
    """
    try:
        os_type = detect_os()
        output = ""
        if os_type in [LinuxDistType.Ubuntu.name, LinuxDistType.Deby.name]:
            (output, err, code) = PseudoShellRunner.run(
                "dpkg-query -f '${Package} ${Version}\n' -W")
            if code != 0:
                raise SoftwareBomError(err)
        elif os_type in [LinuxDistType.YoctoX86_64.name, LinuxDistType.YoctoARM.name]:
            (output, err, code) = PseudoShellRunner.run("rpm -qa")
            if code != 0:
                raise SoftwareBomError(err)
            swbom = " mender version: " + read_mender_file(MENDER_PATH,  UNKNOWN)
            if swbom is not None:
                output = output + swbom
        return output.splitlines()
    except (ValueError, OSError, FileNotFoundError) as e:
        raise SoftwareBomError(str(e))


def read_mender_file(path: str, not_found_default: str) -> str:
    """Checks if the file path exists, to read the mender version from the
    file.

    @param path: file path
    @param not_found_default: default value to use if path is not found.
    @return: value associated with the specified path.
    """
    try:
        if not os.path.exists(path):
            logger.debug(
                "File '%s' does not exist.", path)
            return not_found_default

        with open(path) as f:
            return f.readline().rstrip('\n').split('\x00')[0]
    except OSError as e:
        return "Error on reading installed mender version "


def publish_software_bom(client: MQTT, query_request: bool) -> None:
    """Publishes the software BOM details chunks according to the specified byte size.
    The last chunk of data has the keyword 'queryEndResult' stating it the last chunk of result 
    while the other chunks have 'queryResult'

    @param client: MQTT
    @param query_request: determines if a query request is made to
        decide on the key of the Dict to be published. The key would be 'queryResult' 
        for query otherwise 'softwareBOM' for regular telemetry.
    """
    try:
        sw_bom_list = get_sw_bom_list()
    except SoftwareBomError as e:
        sw_bom_list = ["Error gathering software BOM information. " + str(e)]
    if len(sw_bom_list) != 0:
        if sys.getsizeof(sw_bom_list) > SWBOM_BYTES_SIZE:
            number_of_swbom_lists = math.ceil(
                SWBOM_BYTES_SIZE/math.ceil(sys.getsizeof(sw_bom_list)/len(sw_bom_list)))
        else:
            number_of_swbom_lists = len(sw_bom_list)
        list_num = 0
        for i in range(0, len(sw_bom_list), number_of_swbom_lists):
            sw_dict = {}
            list_num += 1
            sw_dict[f"swbom_package_list_{list_num}"] = sw_bom_list[i:i+number_of_swbom_lists]
            key = 'queryResult' if query_request else 'softwareBOM'
            # Calculate the final chunk of swbom, to incluce have the keyword "QueryEndResult".
            if (i == 0 and len(sw_bom_list) == number_of_swbom_lists) or \
                    i == math.floor(len(sw_bom_list)/number_of_swbom_lists) * number_of_swbom_lists:
                # Inbc query to exit successfully when it has the keyword "QueryEndResult".
                key = 'queryEndResult'
            swbom = {'values': {key: sw_dict}, 'type': "dynamic_telemetry"}
            telemetry_handling.publish_dynamic_telemetry(client, EVENTS_CHANNEL, swbom)
    else:
        key = 'queryEndResult' if query_request else 'softwareBOM'
        swbom = {'values': {key: 'No Software BOM packages available on platform'},
                 'type': "dynamic_telemetry"}
        telemetry_handling.publish_dynamic_telemetry(client, EVENTS_CHANNEL, swbom)
