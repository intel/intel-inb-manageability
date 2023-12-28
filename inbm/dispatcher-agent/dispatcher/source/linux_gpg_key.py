"""
    Copyright (C) 2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging

from inbm_common_lib.shell_runner import PseudoShellRunner
from dispatcher.source.source_exception import SourceError

logger = logging.getLogger(__name__)


def remove_gpg_key(gpg_key_id: str) -> None:
    """Linux - Removes a GPG key

    @param gpg_key_id: ID of GPG key to remove
    """
    try:
        stdout, stderr, exit_code = PseudoShellRunner().run(
            f"gpg --list-keys {gpg_key_id}"
        )

        # If the key exists, try to remove it
        if exit_code == 0:
            stdout, stderr, exit_code = PseudoShellRunner().run(
                f"gpg --delete-key {gpg_key_id}"
            )
            if exit_code != 0:
                raise SourceError("Error deleting GPG key: " + (stderr or stdout))

    except OSError as e:
        raise SourceError(f"Error checking or deleting GPG key: {e}") from e


def add_gpg_key(remote_key_path: str, key_store_path: str) -> str:
    """Linux - Removes a GPG key

    @param remote_key_path: Remote location of the GPG key to download
    @param key_store_path: Path on local machine to store the GPG key
    """
    try:
        command = f"sudo wget -qO - {remote_key_path} | sudo gpg --dearmor --output {key_store_path}"
        logger.debug(f"add GPG key command: {command}")
        stdout, stderr, exit_code = PseudoShellRunner().run(command)

        # If key add successful, return the key_id
        if exit_code != 0:
            raise SourceError("Error adding GPG key: " + (stderr or stdout))

        logger.info(f"GPG Key ID: {stdout}")
        return stdout

    except OSError as e:
        raise SourceError(f"Error addingGPG key: {e}") from e
