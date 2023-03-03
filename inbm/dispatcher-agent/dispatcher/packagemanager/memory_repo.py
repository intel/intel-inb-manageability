"""In-memory implementation of IRepo with simple add, get, list, exists
    functions

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from typing import Dict, List

from requests import Response

from .irepo import IRepo


class MemoryRepo(IRepo):
    """In-memory implementation of IRepo.  Used for testing purposes only.

    @path name:  Directory to use when creating repo
    """

    def __init__(self, name: str) -> None:
        self._contents: Dict = {}
        self.__name = name

    def get_repo_path(self) -> str:
        """Gets the repository path

        @return: directory path
        """
        return self.__name

    def add(self, filename: str, contents: bytes, umask: int = 0) -> None:
        """Add file contents

        @param filename: filename of target to add contents
        @param contents: contents to add to the file
        """
        self._contents[filename] = contents

    def get(self, filename: str) -> bytes:
        """Get file contents

        @param filename: filename of the source
        @return: contents of the file
        """
        return self._contents[filename]

    def list(self) -> List:
        """List repo entries

        @return: list of files in the repository
        """
        return list(self._contents.keys())  # pylint: disable=dict-keys-not-iterating

    def exists(self) -> bool:
        """True if directory exists; false otherwise"""
        return True

    def name(self) -> str:
        """Get repo ID

        @return: repository ID
        """
        return self.__name

    def delete(self, filename: str) -> None:
        """Deletes repo file

        @param filename: filename to delete
        """
        if filename in self._contents:
            del self._contents[filename]

    def is_present(self, filename: str) -> bool:
        """Returns True if file exists else False"""
        return filename in self._contents

    def add_from_requests_response(self, filename: str, response: Response, umask: int) -> None:
        """Add a file to the repo directly from a requests response object.

        @param filename: object name to place data in
        @param response: requests response object from which to get data
        @param umask: does nothing; present for compatibility with IRepo
        """
        self.add(filename, response.content)

    def get_free_space(self) -> int:
        """Since this is usually just for testing, return a large number.

        @return: free space available in this Repo
        """
        return 100000000000

    def delete_all(self) -> None:
        """Remove every object from the repo."""
        self._contents = {}
