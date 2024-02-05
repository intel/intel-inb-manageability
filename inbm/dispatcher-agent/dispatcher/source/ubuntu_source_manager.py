"""
    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import glob
import logging
import os

from dispatcher.packagemanager.package_manager import verify_source
from dispatcher.dispatcher_broker import DispatcherBroker
from dispatcher.dispatcher_exception import DispatcherException
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
from .constants import LINUX_GPG_KEY_PATH
from .source_manager import ApplicationSourceManager, OsSourceManager
from .linux_gpg_key import add_gpg_key

from inbm_common_lib.utility import (
    get_canonical_representation_of_path,
    remove_file,
    create_file_with_contents,
)

logger = logging.getLogger(__name__)


class UbuntuOsSourceManager(OsSourceManager):
    def __init__(self) -> None:
        pass

    def add(self, parameters: SourceParameters) -> None:
        """Adds sources in the Ubuntu OS source file /etc/apt/sources.list"""

        try:
            with open(UBUNTU_APT_SOURCES_LIST, "a") as file:
                for source in parameters.sources:
                    file.write(f"{source}\n")
        except OSError as e:
            raise SourceError(f"Error adding sources: {e}") from e

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
        """Updates a source in the Ubuntu OS source file /etc/apt/sources.list

        This will overwrite the file and add the listed sources."""

        try:
            with open(UBUNTU_APT_SOURCES_LIST, "w") as file:
                for source in parameters.sources:
                    file.write(f"{source}\n")
        except OSError as e:
            raise SourceError(f"Error adding sources: {e}") from e


class UbuntuApplicationSourceManager(ApplicationSourceManager):
    def __init__(self, broker: DispatcherBroker) -> None:
        self._dispatcher_broker = broker

    def add(self, parameters: ApplicationAddSourceParameters) -> None:
        """Adds a source file and optional GPG key to be used during Ubuntu application updates."""
        # Step 1: Verify GPG key URI from trusted repo list
        if parameters.gpg_key_name and parameters.gpg_key_uri:
            try:
                url = parameters.gpg_key_uri
                # URL slicing to remove the last segment (filename) from the URL
                source = url[:-(len(url.split('/')[-1]) + 1)]
                verify_source(source=source, dispatcher_broker=self._dispatcher_broker)
            except (DispatcherException, IndexError) as err:
                raise SourceError(f"Source GPG key URI verification check failed: {err}")
            # Step 2: Add key (Optional)
            add_gpg_key(parameters.gpg_key_uri, parameters.gpg_key_name)

        # Step 3: Add the source
        try:
            create_file_with_contents(
                os.path.join(UBUNTU_APT_SOURCES_LIST_D,
                             parameters.source_list_file_name), parameters.sources
            )
        except (IOError, OSError) as e:
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
        """Removes a source file from the Ubuntu source file list under /etc/apt/sources.list.d.  Optionally
        removes the gpg key from /usr/share/keyrings
        @parameters: dataclass parameters for ApplicationRemoveSourceParameters
        """
        if parameters.gpg_key_name:
            # Remove the GPG key (Optional)
            path = os.path.join(LINUX_GPG_KEY_PATH, parameters.gpg_key_name)
            if not remove_file(path):
                logger.warning(f"Unable to remove GPG key: {path}")

        # Remove the file under /etc/apt/sources.list.d
        try:
            if (
                os.path.sep in parameters.source_list_file_name
                or parameters.source_list_file_name == ".."
                or parameters.source_list_file_name == "."
            ):
                raise SourceError(f"Invalid file name: {parameters.source_list_file_name}")

            if not remove_file(
                get_canonical_representation_of_path(
                    os.path.join(UBUNTU_APT_SOURCES_LIST_D, parameters.source_list_file_name)
                )
            ):
                raise SourceError(f"Error removing file: {parameters.source_list_file_name}")
        except OSError as e:
            raise SourceError(f"Error removing file: {e}") from e

    def update(self, parameters: ApplicationUpdateSourceParameters) -> None:
        """Updates a source file in Ubuntu OS source file list under /etc/apt/sources.list.d"""
        try:
            create_file_with_contents(
                os.path.join(UBUNTU_APT_SOURCES_LIST_D,
                             parameters.source_list_file_name), parameters.sources
            )
        except IOError as e:
            raise SourceError(f"Error occurred while trying to update sources: {e}") from e
