"""
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from abc import ABC
from abc import abstractmethod
from typing import List

from requests import Response


class IRepo(ABC):  # pragma: no cover
    """Abstract base class for repos."""

    @abstractmethod
    def get_repo_path(self) -> str:
        """Get a path or equivalent name for the Repo.

        @return: Path or equivalent name for the Repo.
        """
        pass

    @abstractmethod
    def add(self, filename: str, contents: bytes, umask: int = 0) -> None:
        """Add file contents to Repo"""
        pass

    @abstractmethod
    def get(self, filename: str) -> bytes:
        """Get file contents from Repo"""
        pass

    @abstractmethod
    def list(self) -> List[str]:
        """List Repo entries"""
        pass

    @abstractmethod
    def exists(self) -> bool:
        """True if the Repo exists (e.g., if it's a directory on a filesystem); False otherwise."""
        pass

    @abstractmethod
    def name(self) -> str:
        """Return repo ID"""
        pass

    @abstractmethod
    def delete(self, filename: str) -> None:
        """Deletes repo file"""
        pass

    @abstractmethod
    def is_present(self, filename: str) -> bool:
        """Returns True if entry exists else False"""
        pass

    @abstractmethod
    def add_from_requests_response(self, filename: str, response: Response, umask: int) -> None:
        """Add an object to the repo directly from a requests response object.

        @param filename: object name to place data in
        @param response: requests response object from which to get data
        """
        pass

    @abstractmethod
    def get_free_space(self) -> int:
        """Get free space in the Repo in bytes

        @return: free space available in this Repo in bytes
        """
        pass

    @abstractmethod
    def delete_all(self) -> None:
        """Remove every object from the repo.

        @return: nothing
        """
        pass
