"""
    Update Tool utility functions

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import os
import hashlib
import logging
from typing import Optional
from ..packagemanager.irepo import IRepo
from .constants import TIBER_UPDATE_TOOL_PATH, SOTA_CACHE
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


def update_tool_write_command(signature: Optional[str] = None, repo: Optional[IRepo] = None) -> str:
    """Call UT command to write the image into secondary partition.
       If signature is provided, it performs signature check and passes the verified file to UT.

    @param signature: signature used to verify image
    @param repo: directory that contains the downloaded artifacts
    @return: UT command to run
    """
    raw_img_path = None
    if signature:
        raw_img_path = verify_signature(repo.get_repo_path(), signature) if repo \
            else verify_signature(SOTA_CACHE, signature)
    logger.debug("")

    if raw_img_path:
        return str(TIBER_UPDATE_TOOL_PATH + " -w" + " -u " + raw_img_path)
    else:
        raise SotaError("Signature checks failed. No matching file found.")


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


def verify_signature(repo: str, signature: str) -> str:
    """Perform signature check. Multiple files may have been downloaded from OCI.
    The method below will iterate over all files in the repo, calculate the SHA256sum for each file,
    and compare it with the provided signature.

    @return: File that matches the signature
    """
    try:
        logger.debug("Perform signature check on the downloaded file.")
        for filename in os.listdir(repo):
            filepath = os.path.join(repo, filename)
            if os.path.isfile(filepath):
                with open(filepath, 'rb') as file:
                    file_checksum = hashlib.sha256(file.read()).hexdigest()
                    if file_checksum == signature:
                        return filepath

        raise SotaError("Signature checks failed. No matching file found.")
    except OSError as err:
        raise SotaError(err)
