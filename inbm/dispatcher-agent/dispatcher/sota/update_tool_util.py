"""
    Update Tool utility functions

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import os
import hashlib
import logging
from typing import Optional
from .constants import TIBER_UPDATE_TOOL_PATH
from inbm_common_lib.shell_runner import PseudoShellRunner
from .sota_error import SotaError
logger = logging.getLogger(__name__)


def update_tool_rollback_command() -> None:
    """Call UT command to perform image rollback.
    """
    logger.debug("")
    (out, err, code) = PseudoShellRunner().run(TIBER_UPDATE_TOOL_PATH + " -r")
    if code != 0:
        raise SotaError(f"Failed to run UT rollback command. Error:{err}")


def update_tool_write_command(signature: Optional[str] = None, file_path: Optional[str] = None) -> str:
    """Call UT command to write the image into secondary partition.
       If signature is provided, it performs signature check and passes the verified file to UT.

    @param signature: signature used to verify image
    @param file_path: raw image file path
    @return: UT command to run
    """
    if signature is None:
        raise SotaError("Signature is None.")

    if file_path is None:
        raise SotaError("Raw image file path is None.")

    if signature and file_path:
        if verify_signature(file_path, signature):
            logger.debug("Signature check passed.")
        else:
            raise SotaError("Signature checks failed.")

    return str(TIBER_UPDATE_TOOL_PATH + " -w" + " -u " + file_path)


def update_tool_commit_command() -> int:
    """Call UT command to commit.
       Type of Code:
        0 - Success
        1 - Fail
        2 - Unable to access image
        3 - write failure to secondary partition
        4 - Boot loader configuration update failure
        5 - Unable to commit an update

    @return: code
    """
    logger.debug("")
    (out, err, code) = PseudoShellRunner().run(TIBER_UPDATE_TOOL_PATH + " -c")
    if code != 0:
        raise SotaError(f"Failed to run UT commit command. Error:{err}")
    return code


def update_tool_apply_command() -> str:
    """Call UT command to apply the update. The UT will update required boot order configs.

    @return: command to be executed
    """
    logger.debug("")
    return TIBER_UPDATE_TOOL_PATH + " -a"


def verify_signature(file_path: str, signature: str) -> bool:
    """Perform signature check. The method will calculate the SHA256sum of the file and
    compare it with the provided signature.

    @param signature: signature used to verify image
    @param file_path: raw image file path
    @return: True if the signature matches; False if the signature verification failed.
    """
    try:
        logger.debug("Perform signature check on the downloaded file.")
        with open(file_path, 'rb') as file:
            file_checksum = hashlib.sha256(file.read()).hexdigest()
            if file_checksum == signature:
                return True

        logger.error("Signature checks failed.")
        return False
    except OSError as err:
        logger.error(f"Error during signature checks: {err}")
        return False
