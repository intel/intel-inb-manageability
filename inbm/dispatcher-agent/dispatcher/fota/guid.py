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


def extract_guid(fw_tool: str) -> Optional[str]:
    """Method to get system firmware type

    @param fw_tool: Tool to extract the GUID from the FW
    @return: None or guid
    """
    runner = PseudoShellRunner()
    cmd = fw_tool + " -l"
    (out, err, code) = runner.run(cmd)
    if code != 0:
        raise FotaError("Firmware Update Aborted: failed to list GUIDs: {}".format(str(err)))
    guid = _parse_guid(out)
    logger.debug("GUID : " + str(guid))
    if not guid:
        raise FotaError("Firmware Update Aborted: No System Firmware type GUID found")
    return guid


def _parse_guid(output: str) -> Optional[str]:
    """Method to parse the shell command output to retrieve the value of system firmware type

    @param output: shell command output from the firmware tool
    @return: string value if system firmware type is present if not return None
    """
    for line in output.splitlines():
        if "System Firmware type" in line or "system-firmware type" in line:
            return line.split(',')[1].split()[0].strip('{').strip('}')
    return None
