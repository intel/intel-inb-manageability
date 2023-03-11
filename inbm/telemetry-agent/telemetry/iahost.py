"""
    Retrieves attached disk information.

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import platform
import os
from inbm_common_lib.shell_runner import PseudoShellRunner
from future import standard_library
from telemetry.constants import RM_PATH
standard_library.install_aliases()


def is_iahost() -> bool:
    """Method to check if it is an IAHost.

    @return: True if IAHost else False
    """
    if platform.system() == 'Linux':
        _, _, _, _, arch = os.uname()
        if arch.startswith("x86_64"):
            return True
    return False


def rm_service_active() -> bool:
    """Checks if Resource Monitor service is active on the system.

    @return True if active; otherwise, false.
    """
    return True if os.path.exists(RM_PATH) else False
