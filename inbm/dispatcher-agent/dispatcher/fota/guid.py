"""
    FOTA update tool which is called from the dispatcher during installation

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging

from .fota_error import FotaError
from inbm_common_lib.shell_runner import PseudoShellRunner
from typing import Optional

logger = logging.getLogger(__name__)


def extract_guids(fw_tool: str, types: list[str]) -> list[str]:
    """Method to get system firmware type

    @param fw_tool: Tool to extract the GUID from the FW
    @param types: type of GUID to search
    @return: list of firmware GUIDs found
    """
    runner = PseudoShellRunner()
    cmd = fw_tool + " -l"
    (out, err, code) = runner.run(cmd)
    if code != 0:
        raise FotaError("Firmware Update Aborted: failed to list GUIDs: {}".format(str(err)))
    guids = _parse_guids(out, types)
    logger.debug("GUIDs: " + str(guids))
    if guids == []:
        raise FotaError("Firmware Update Aborted: No GUIDs found matching types: " + str(types))
    return guids


def _parse_guids(output: str, types: list[str]) -> list[str]:
    """Method to parse the shell command output to retrieve the value of system firmware type

    @param output: shell command output from the firmware tool
    @param types: types of GUID to search
    @return: list of GUID values if system firmware types are present, if not return an empty list
    """
    guids: list[str] = []
    for line in output.splitlines():
        if any(type_str in line for type_str in types):
            guids.append(line.split(',')[1].split()[0].strip('{').strip('}'))
    return guids
