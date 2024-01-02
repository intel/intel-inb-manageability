"""
    Copyright (C) 2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import glob
import logging
import os

from dispatcher.source.source_exception import SourceError
from dispatcher.source.constants import (
    UBUNTU_APT_SOURCES_LIST,
    UBUNTU_APT_SOURCES_LIST_D,
    ApplicationAddSourceParameters,
    ApplicationRemoveSourceParameters,
    ApplicationSourceList,
    ApplicationUpdateSourceParameters,
    SourceParameters,
)
from dispatcher.source.source_manager import ApplicationSourceManager, OsSourceManager
from dispatcher.source.linux_gpg_key import remove_gpg_key, add_gpg_key

from inbm_common_lib.shell_runner import PseudoShellRunner
from inbm_common_lib.utility import (
    get_canonical_representation_of_path,
    remove_file,
    move_file,
    create_file_with_contents,
)

logger = logging.getLogger(__name__)


class UbuntuOsSourceManager(OsSourceManager):
    def __init__(self) -> None:
        pass

    def add(self, parameters: SourceParameters) -> None:
        """Adds a source in the Ubuntu OS source file /etc/apt/sources.list"""
        # TODO: Add functionality to add a source file in Ubuntu to /etc/apt/sources.list file
        logger.debug(f"sources: {parameters.sources}")

    def list(self) -> list[str]:
        """List deb and deb-src lines in /etc/apt/sources.list"""
        try:
            with open(UBUNTU_APT_SOURCES_LIST, "r") as file:
                lines = [
                    line.strip()
                    for line in file.readlines()
                    if line.strip() and not line.startswith("#")
                ]
            return [
                line for line in lines if line.startswith("deb ") or line.startswith("deb-src ")
            ]
        except OSError as e:
            raise SourceError(f"Error opening source file: {e}") from e

    def remove(self, parameters: SourceParameters) -> None:
        """Removes a source in the Ubuntu OS source file /etc/apt/sources.list"""

        sources_list_path = UBUNTU_APT_SOURCES_LIST
        try:
            with open(sources_list_path, "r") as file:
                lines = file.readlines()

            sources_to_remove = set(source.strip() for source in parameters.sources)

            # Filter out any lines that exactly match the given sources
            with open(sources_list_path, "w") as file:
                for line in lines:
                    if line.strip() not in sources_to_remove:
                        file.write(line)
                    else:
                        logger.debug(f"Removed source: {line}")

        except OSError as e:
            raise SourceError(f"Error occurred while trying to remove sources: {e}") from e

    def update(self, parameters: SourceParameters) -> None:
        """Updates a source in the Ubuntu OS source file /etc/apt/sources.list"""
        # TODO: Add functionality to update a source in Ubuntu file under /etc/apt/sources.list file
        try:
            with open(UBUNTU_APT_SOURCES_LIST, "r") as file:
                lines = file.readlines()

            sources_to_update = set(source.strip() for source in parameters.sources)

        except OSError as e:
            raise SourceError(f"Error occurred while trying to update sources: {e}") from e


class UbuntuApplicationSourceManager(ApplicationSourceManager):
    def __init__(self) -> None:
        pass

    def add(self, parameters: ApplicationAddSourceParameters) -> None:
        # Step 1: Add key
        key_id = add_gpg_key(parameters.gpg_key_path, parameters.gpg_key_name)

        # Step 2: Add the source
        try:
            create_file_with_contents(
                os.path.join(UBUNTU_APT_SOURCES_LIST_D, parameters.file_name), parameters.sources
            )
        except (IOError, OSError) as e:
            remove_gpg_key(key_id)
            raise SourceError(f"Error adding application source list: {e}")

    def list(self) -> list[ApplicationSourceList]:
        """List Ubuntu Application source lists under /etc/apt/sources.list.d"""
        sources = []
        try:
            for filepath in glob.glob(UBUNTU_APT_SOURCES_LIST_D + "/*"):
                with open(filepath, "r") as file:
                    lines = [
                        line.strip()
                        for line in file.readlines()
                        if line.strip() and not line.startswith("#")
                    ]
                    new_source = ApplicationSourceList(
                        name=os.path.basename(filepath),
                        sources=[
                            line
                            for line in lines
                            if line.startswith("deb ") or line.startswith("deb-src ")
                        ],
                    )
                    sources.append(new_source)
            return sources
        except OSError as e:
            raise SourceError(f"Error listing application sources: {e}") from e

    def remove(self, parameters: ApplicationRemoveSourceParameters) -> None:
        """Removes a source file from the Ubuntu source file list under /etc/apt/sources.list.d
        @parameters: dataclass parameters for ApplicationRemoveSourceParameters
        """
        # Remove the GPG key
        remove_gpg_key(parameters.gpg_key_id)

        # Remove the file under /etc/apt/sources.list.d
        try:
            if (
                os.path.sep in parameters.file_name
                or parameters.file_name == ".."
                or parameters.file_name == "."
            ):
                raise SourceError(f"Invalid file name: {parameters.file_name}")

            if not remove_file(
                get_canonical_representation_of_path(
                    os.path.join(UBUNTU_APT_SOURCES_LIST_D, parameters.file_name)
                )
            ):
                raise SourceError(f"Error removing file: {parameters.file_name}")
        except OSError as e:
            raise SourceError(f"Error removing file: {e}") from e

    def update(self, parameters: ApplicationUpdateSourceParameters) -> None:
        """Updates a source file in Ubuntu OS source file list under /etc/apt/sources.list.d"""
        try:
            create_file_with_contents(
                os.path.join(UBUNTU_APT_SOURCES_LIST_D, parameters.file_name), parameters.sources
            )
        except IOError as e:
            raise SourceError(f"Error occurred while trying to update sources: {e}") from e
