"""
    On-disk implementation of Repo with simple add, get, list, exists
    functions

    Copyright (C) 2017-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import os
import shutil
from typing import List

import psutil
from inbm_common_lib.utility import get_canonical_representation_of_path
from inbm_common_lib.utility import remove_file
from requests import Response

from .irepo import IRepo
from ..dispatcher_exception import DispatcherException

logger = logging.getLogger(__name__)


class DirectoryRepo(IRepo):  # pragma: no cover
    """On-disk implementation of Repo

    @param directory: Directory to use when creating repo
    """

    def __init__(self, directory: str) -> None:
        self.__directory = get_canonical_representation_of_path(directory)

    def get_repo_path(self) -> str:
        """Gets the repository path

        @return: directory path
        """
        return self.__directory

    def get(self, filename: str) -> bytes:
        """Get file contents

        @param filename: filename of the source
        @return: contents of the file
        """
        with open(os.path.join(self.__directory, filename), 'rb') as f:
            contents: bytes = f.read()
        try:
            # the following line will be optimized out in byte code and only used in unit testing
            assert isinstance(contents, bytes)  # noqa: S101
        except AssertionError as e:
            raise DispatcherException('Got str from file opened as bytes')

        return contents

    def list(self) -> List:
        """List repo entries

        @return: list of files in the repository
        """
        return os.listdir(self.__directory)

    def add(self, filename: str, contents: bytes, umask: int = 0) -> None:
        """Add file contents

        @param filename: filename of target to add contents
        @param contents: contents to add to the file
        @param umask: file permission mask
        """
        saved_umask = os.umask(umask)
        try:
            with open(os.open(os.path.join(self.__directory, filename), os.O_CREAT | os.O_WRONLY), 'wb') as destination_file:
                destination_file.write(contents)
        finally:
            os.umask(saved_umask)

    def add_from_requests_response(self, filename: str, response: Response, umask: int) -> None:
        """Add a file to the repo directly from a request response object. This can be
        useful if the resource is very large and doesn't fit into memory.

        @param filename: filename to place data in
        @param response: requests response object from which to get data
        @param umask: file permission mask
        """
        destination_file_name = os.path.join(self.__directory, filename)
        logger.debug("add_from_requests_response trying to download to " + destination_file_name)
        saved_umask = os.umask(umask)
        try:
            with open(os.open(destination_file_name, os.O_CREAT | os.O_WRONLY), 'wb') as destination_file:
                logger.debug(f"Streaming response to disk: {destination_file.name}")
                shutil.copyfileobj(response.raw, destination_file)
        finally:
            os.umask(saved_umask)

    def exists(self) -> bool:
        """True if directory exists; false otherwise"""
        return os.path.isdir(self.__directory)

    def name(self) -> str:
        """Return repo path"""
        return self.__directory

    def is_present(self, name: str) -> bool:
        """Checks if filename exists in the repo

        @param name: name of the path to check
        @return: returns True if it exists or False if not.
        """
        return os.path.exists(os.path.join(self.__directory, name))

    def delete(self, filename: str) -> None:
        """Deletes file with filename. Does not raise exception if file not found

        @param filename: Filename to be removed
        """
        logger.debug(f"DELETING file {filename}")
        if self.is_present(filename):
            remove_file(os.path.join(self.__directory, filename))

    def get_free_space(self) -> int:
        """Gets the amount of free space where the repo resides

        @return: free space on filesystem backing the repo
        """
        return psutil.disk_usage(self.__directory)[2]

    def delete_all(self) -> None:
        """Remove every object from the repo. For DirectoryRepo, remove all
        files (NOT directories) from the directory.
        """
        repo_path = self.get_repo_path()
        logger.debug("Erasing files directly underneath " + repo_path)
        if not os.path.exists(repo_path):
            raise DispatcherException(f"cannot delete files from {repo_path}: does not exist")
        if not os.path.isdir(repo_path):
            raise DispatcherException(f"cannot delete files from {repo_path}: is not a directory")
        try:
            for the_file in os.listdir(repo_path):
                file_path = os.path.join(self.get_repo_path(), the_file)
                if os.path.isfile(file_path):
                    logger.debug("... unlinking: " + file_path)
                    os.unlink(file_path)
        except OSError as e:
            raise DispatcherException("got OSError while deleting all in {repo_path}: {e}") from e
