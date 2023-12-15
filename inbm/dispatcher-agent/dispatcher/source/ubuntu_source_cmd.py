import glob
import logging
import os
from dispatcher.dispatcher_exception import DispatcherException
from dispatcher.source.constants import (
    ApplicationAddSourceParameters,
    ApplicationRemoveSourceParameters,
    ApplicationSourceList,
    ApplicationUpdateSourceParameters,
    SourceParameters,
)
from dispatcher.source.source_cmd import (
    SourceApplicationCommand,
    SourceOsCommand,
)

logger = logging.getLogger(__name__)


class UbuntuSourceOsCommand(SourceOsCommand):
    def __init__(self) -> None:
        pass

    def add(self, parameters: SourceParameters) -> None:
        """Adds a source in the Ubuntu OS source file /etc/apt/sources.list"""
        # TODO: Add functionality to add a source file in Ubuntu to /etc/apt/sources.list file
        logger.debug(f"sources: {parameters.sources}")

    def list(self) -> list[str]:
        """List deb and deb-src lines in /etc/apt/sources.list"""
        try:
            with open("/etc/apt/sources.list", "r") as file:
                lines = [
                    line.strip()
                    for line in file.readlines()
                    if line.strip() and not line.startswith("#")
                ]
            return [
                line for line in lines if line.startswith("deb ") or line.startswith("deb-src ")
            ]
        except OSError as e:
            logger.error(f"Error opening source file: {e}")
            raise DispatcherException(f"Error opening source file: {e}")

    def remove(self, parameters: SourceParameters) -> None:
        """Removes a source in the Ubuntu OS source file /etc/apt/sources.list"""
        # TODO: Add functionality to remove a source file in Ubuntu to /etc/apt/sources.list file
        logger.debug(f"sources: {parameters.sources}")

    def update(self, parameters: SourceParameters) -> None:
        """Updates a source in the Ubuntu OS source file /etc/apt/sources.list"""
        # TODO: Add functionality to update a source in Ubuntu file under /etc/apt/sources.list file
        pass


class UbuntuSourceApplicationCommand(SourceApplicationCommand):
    def __init__(self) -> None:
        pass

    def add(self, parameters: ApplicationAddSourceParameters) -> None:
        """Adds new application source along with its key"""
        pass

    def list(self) -> list[ApplicationSourceList]:
        """List Ubuntu Application source lists under /etc/apt/sources.list.d"""
        sources = []
        try:
            for filepath in glob.glob("/etc/apt/sources.list.d/*.list"):
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
            logger.error(f"Error listing application sources: {e}")
            raise DispatcherException(f"Error listing application sources: {e}")

    def remove(self, parameters: ApplicationRemoveSourceParameters) -> None:
        """Removes a source file from the Ubuntu source file list under /etc/apt/sources.list.d"""
        # TODO: Add functionality to remove a source file under the Ubuntu source file list
        #  under /etc/apt/sources.list.d
        logger.debug(f"gpg_key_path: {parameters.gpg_key_id}, file_name: {parameters.file_name}")

    def update(self, parameters: ApplicationUpdateSourceParameters) -> None:
        """Updates a source file in Ubuntu OS source file list under /etc/apt/sources.list.d"""
        # TODO: Add functionality to update a Ubuntu source file under /etc/apt/sources.list.d
        logger.debug(f"file_name: {parameters.file_name}, source: {parameters.sources[0]}")
