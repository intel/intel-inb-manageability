"""
    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
import subprocess
import os
import requests

from inbm_common_lib.shell_runner import PseudoShellRunner
from .source_exception import SourceError
from .constants import LINUX_GPG_KEY_PATH

logger = logging.getLogger(__name__)


def remove_gpg_key(gpg_key_id: str) -> None:
    """Linux - Removes a GPG key

    @param gpg_key_id: ID of GPG key to remove
    """
    try:
        stdout, stderr, exit_code = PseudoShellRunner().run(f"gpg --list-keys {gpg_key_id}")

        # If the key exists, try to remove it
        if exit_code == 0:
            stdout, stderr, exit_code = PseudoShellRunner().run(f"gpg --delete-key {gpg_key_id}")
            if exit_code != 0:
                raise SourceError("Error deleting GPG key: " + (stderr or stdout))

    except OSError as e:
        raise SourceError(f"Error checking or deleting GPG key: {e}") from e


def add_gpg_key(remote_key_path: str, key_store_name: str) -> None:
    """Linux - Adds a GPG key from a remote source

    Raises SourceError if there are any problems.

    @param remote_key_path: Remote location of the GPG key to download
    @param key_store_name: Name to use to store the GPG under /usr/share/keyrings/
    """

    try:
        # Download the GPG key from the remote source
        response = requests.get(remote_key_path)
        response.raise_for_status()

        decoded_ascii = response.content.decode("utf-8", errors="strict")

        key_path = os.path.join(LINUX_GPG_KEY_PATH, key_store_name)

        # Use gpg to dearmor the key and save it to the key store path
        subprocess.run(
            ["/usr/bin/gpg", "--dearmor", "--output", key_path],
            input=decoded_ascii,
            check=True,
            text=True,
            shell=False,
        )

        logger.info(f"GPG key added to {key_store_name}")

    except requests.exceptions.RequestException as e:
        raise SourceError(f"Error getting GPG key from remote source: {e}")

    except subprocess.CalledProcessError as e:
        raise SourceError(f"Error running gpg command to dearmor key: {e}")
