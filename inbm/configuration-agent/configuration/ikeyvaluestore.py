"""
    Base class of commands supported by Configuration Agent

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import abc
from typing import Optional, Dict


class IKeyValueStore(abc.ABC):
    """Interface for managing key/value pairs"""

    @abc.abstractmethod
    def get_element(self, path: str, element_string: Optional[str] = None, is_attribute: bool = False) -> str:
        """Gets element value from the specified path

        @param path: path to the key in the structure
        @param element_string: String of ; separated elements whose values need to be returned
        @param is_attribute: determines if the element attribute value needs to be returned
        """
        pass

    @abc.abstractmethod
    def set_element(self, path: str, value: str = "", value_string: Optional[str] = None,
                    is_attribute: bool = False) -> str:
        """Sets the element value at the specified path

        @param path: path to the key
        @param value: value to set at the key
        @param value_string: multiple variable value sting separated by ;
        @param is_attribute: determines if the element attribute value needs to be set
        """
        pass

    @abc.abstractmethod
    def load(self, path: str) -> None:
        """Loads a new key/value pair file

        @param path: path to file
        """
        pass

    @abc.abstractmethod
    def append(self, path: str, value_string: str) -> str:
        """Appends the element value at the specified path

        @param path: path to the key or multiple paths separated by ;
        @param value_string: value to append at the key or multiple values separated by ;
        """
        pass

    @abc.abstractmethod
    def remove(self, path: str, value: Optional[str] = None, value_string: Optional[str] = None) -> str:
        """Removes the element value at the specified path

        @param path: path to the key
        @param value: value to remove from the key
        @param value_string: multiple variable value sting separated by ;
        """
        pass

    @abc.abstractmethod
    def get_children(self, path: str) -> Dict[str, str]:
        """Gets all children under the specified path

        @param path: path to use
        """
        pass

    @abc.abstractmethod
    def get_parent(self, child_element: str) -> Optional[str]:
        """Find the parent of the child element from XML file

        @param child_element: child element tag
        """
        pass
