"""
    Handles polling and publishing telemetry data.

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import os
import platform

from inbm_lib.constants import TRTL_PATH
from inbm_common_lib.shell_runner import PseudoShellRunner
import logging

logger = logging.getLogger(__name__)


def are_docker_and_trtl_on_system() -> bool:
    """Checks if Docker and trtl are installed on the system.

    Skip check and return False on Windows.

    @return True if installed; otherwise, false.
    """

    if platform.system() == 'Windows':
        return False
    else:  # Linux
        (out, err, code) = PseudoShellRunner.run("systemctl is-active --quiet docker")
        docker_present = True if err == "" and code == 0 else False
        trtl_present = os.path.exists(TRTL_PATH)
        return docker_present and trtl_present
