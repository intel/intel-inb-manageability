"""
    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
import subprocess  # nosec B404
import os
import requests

from .source_exception import SourceError
from .constants import LINUX_GPG_KEY_PATH

logger = logging.getLogger(__name__)


def add_gpg_key(remote_key_path: str, key_store_name: str) -> None:
    """Linux - Adds a GPG key from a remote source

    Raises SourceError if there are any problems.

    @param remote_key_path: Remote location of the GPG key to download
    @param key_store_name: Name to use to store the GPG under LINUX_GPG_KEY_PATH
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
        raise SourceError(f"Error running GPG command to dearmor key: {e}")
