"""
    Update Tool utility functions

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
from .constants import TIBER_UPDATE_TOOL_PATH, SOTA_CACHE
from inbm_common_lib.shell_runner import PseudoShellRunner
from .sota_error import SotaError
logger = logging.getLogger(__name__)


def update_tool_version_command() -> str:
    """Call UT command to get the SHA of current image.

    @return SHA
    """
    logger.debug("")
    (out, err, code) = PseudoShellRunner().run(TIBER_UPDATE_TOOL_PATH + " -v")
    if code != 0:
        raise SotaError(f"Failed to run UT version command. Error:{err}")
    return str(out)


def update_tool_write_command() -> str:
    """Call UT command to write the image into secondary partition.

    @return SHA
    """
    logger.debug("")
    return str(TIBER_UPDATE_TOOL_PATH + " -w" + " -u " + SOTA_CACHE)


def update_tool_commit_command() -> int:
    """Call UT command to commit.
       Type of Code:
        0 - Success
        1 - Fail
        2 - Unable to access image
        3 - write failure to secondary partition
        4 - Boot loader configuration update failure
        5 - Unable to commit an update

    @return code
    """
    logger.debug("")
    (out, err, code) = PseudoShellRunner().run(TIBER_UPDATE_TOOL_PATH + " -c")
    if code != 0:
        raise SotaError(f"Failed to run UT commit command. Error:{err}")
    return code


def update_tool_apply_command() -> str:
    """Call UT command to apply the update. The UT will update required boot order configs.

    @return command to be executed
    """
    logger.debug("")
    return TIBER_UPDATE_TOOL_PATH + " -a"
