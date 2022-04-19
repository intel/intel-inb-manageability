"""
    Module that handles parsing of XML files.

    Copyright (C) 2019-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import os
import pathlib
import shutil
import xmlschema
from typing import Any, Optional, List, Union, Tuple, Dict
from pathlib import Path


from defusedxml import DefusedXmlException, DTDForbidden, EntitiesForbidden, ExternalReferenceForbidden, \
    NotSupportedError
from inbm_vision_lib.constants import FLASHLESS_FILE_PATH
from threading import Lock
from inbm_common_lib.utility import remove_file, copy_file
import defusedxml.ElementTree as element_tree
from defusedxml.ElementTree import parse, XMLParser, ParseError

logger = logging.getLogger(__name__)


class ConfigurationException(Exception):
    """Class exception Module."""
    pass


class ConfigurationManager:
    """Class for handling configuration."""

    def __init__(self, xml: Union[str, pathlib.Path], is_file: bool = True,
                 schema_location: Union[str, pathlib.Path] = None) -> None:
        """Init for ConfigurationManager.

        @param xml: XML to be parsed
        @param is_file: False by default, True if XML to be parsed is a file
        @param schema_location : location of schema file
        """
        self._xml = xml
        self._is_file = is_file
        self._schema_location = schema_location
        self._root = self.get_root()
        self._lock = Lock()

    def _validate_schema(self, xml_file=None):
        if self._schema_location is not None:
            if not os.path.exists(self._schema_location):
                raise ConfigurationException("Schema file not found.")
            if os.path.islink(self._schema_location):
                raise ConfigurationException(
                    "Schema file is a symlink which is not allowed for security reasons.")

            with open(self._schema_location) as schema_file:
                try:
                    schema = xmlschema.XMLSchema11(schema_file)
                    if xml_file:
                        # Check the xml file is valid. Will raise ParseError if the file is corrupted.
                        test_xml_file = parse(xml_file).getroot()
                        schema.validate(xml_file)
                    else:
                        schema.validate(self._xml)
                except (ConfigurationException, xmlschema.XMLSchemaValidationError, DefusedXmlException, DTDForbidden,
                        EntitiesForbidden, ExternalReferenceForbidden, NotSupportedError, ParseError) as e:
                    raise ConfigurationException(
                        f'Unable to parse configuration file. Error: {e}')

    def get_root(self):
        """Called when a manifest is received from xlink.
        @return: root path
        :raises:
        ConfigurationException: raise ConfigurationException when error happen
        """
        try:
            parser = XMLParser(forbid_dtd=True)

            if self._is_file:
                logger.debug(f"XML path: {self._xml}")
                if not os.path.exists(self._xml):
                    raise ConfigurationException("XML file not found")
                root = parse(self._xml, parser)
            else:
                logger.debug(f"XML : {self._xml}")
                root = element_tree.fromstring(self._xml.encode('utf-8'))  # type: ignore
            self._validate_schema()
            return root

        except (xmlschema.XMLSchemaValidationError, DefusedXmlException, DTDForbidden, EntitiesForbidden,
                ExternalReferenceForbidden, NotSupportedError) as error:
            raise ConfigurationException(f'Error with xml {error}')

    def _acquire_lock(self) -> None:
        if not self._lock.acquire(False):
            raise ConfigurationException('Configuration file locked.  Please try again later.')

    def _verify_root(self) -> None:
        if self._root is None:
            raise ConfigurationException('Root element is None.')

    def _clean_up(self, file_path: Union[str, pathlib.Path]) -> None:
        self._lock.release()
        remove_file(str(file_path))

    def reload_xml(self) -> None:
        """Parse the xml file and get the latest value"""
        if self._is_file:
            self._root = self.get_root()
        else:
            raise ConfigurationException('Reload fail. Not a file.')

    def get_children(self, path: str) -> Optional[dict]:
        """Find all elements matching path from parsed XML

        @param path: path to location
        @return: Values of the matched elements as a List
        """
        children: Dict[str, Any] = {}

        self._verify_root()

        elements = self._root.find(path)
        if elements is None:
            raise ConfigurationException(f'Cannot find children at specified path: {path}')

        for child in elements.getchildren():
            if child.text:
                children[child.tag] = child.text
            else:
                raise ConfigurationException('Cannot find value at specified element')
        return children

    def get_element(self, keys: List[str], target_type: Optional[str]) -> List[str]:
        """Find element matching the given path from parsed XML.

        @param keys: List of keys
        @param target_type: configuration target: node or vision
        @return: value of the keys in the parsed XML object
        """
        result = []
        self._acquire_lock()
        try:
            for num in keys:
                val = f'{target_type}/{num}'
                val = self._get_value(val)
                result.append(val)
        finally:
            self._lock.release()
        return result

    def _get_value(self, path) -> Any:
        self._verify_root()

        element = self._root.find(path).text
        if element is None:
            raise ConfigurationException(f'Cannot find element at specified path: {path}')
        return element

    def set_element(self, key_value_pairs: List[str], target_type: Optional[str]) -> List[str]:
        """Find element from parsed XML

        @param key_value_pairs : list of key/value pairs
        @param target_type: Configuration manager target: node or vision
        @return result : status SUCCESS or FAILED
        """
        def _check_value(e: str, v: str) -> Tuple[bool, str]:
            if e == FLASHLESS_FILE_PATH:
                return True, v
            elif v.isdigit():
                return True, v
            return False, v

        self._acquire_lock()
        result = []

        try:
            backup_file = self._create_backup_file()
        except IOError:
            raise ConfigurationException("Unable to create backup for SET command.  SET aborted.")

        try:
            for i in range(len(key_value_pairs)):
                ele = key_value_pairs[i].strip(',').split(':', 1)[0]
                val = key_value_pairs[i].strip(',').split(':', 1)[1]
                check_flag, value = _check_value(ele, val)
                if check_flag:
                    key = f'{target_type}/{ele}'
                    status = self._set_value(key, value)
                    logger.debug(status)
                    result.append(status)
                else:
                    result.append('Failed')
            self._validate_schema(self._xml)
            return result
        except ConfigurationException:
            try:
                logger.debug("Reverting configuration file changes.")
                copy_file(backup_file, str(self._xml))
            except IOError:
                raise ConfigurationException("Unable to revert to backup configuration file after SET command.")
            self.reload_xml()
            raise
        except IndexError as err:
            raise ConfigurationException(f'Cannot find the input value: {err}')
        finally:
            remove_file(backup_file)
            self._lock.release()

    def _set_value(self, path: str, value: Any) -> str:
        self._verify_root()

        logger.debug(f"path: {path}, value: {value}")
        elem = self._root.find(path)
        if elem is not None:
            elem.text = value
            logger.debug(f"VAL {elem.text}")
            try:
                self._write_to_file()
                return 'SUCCESS'
            except ConfigurationException as err:
                logger.error(f"Exception caught while writing to file. {err}")
                return 'Failed'
        else:
            raise ConfigurationException(f'Cannot find element at specified path: {path}')

    def _write_to_file(self) -> None:
        try:
            if self._is_file and self._root is not None:
                self._root.write(self._xml)
        except OSError as e:
            raise ConfigurationException(f'Unable to write XML file: {e}')

    def _create_backup_file(self) -> str:
        backup_file = "{}{}".format(self._xml, '_bak')
        logger.debug(f"Create backup file of: {self._xml}")
        try:
            copy_file(str(self._xml), backup_file)
            return backup_file
        except IOError as error:
            raise ConfigurationException(
                f'Unable to create backup configuration file: {error}')

    def load(self, path: Union[str, pathlib.Path]) -> None:
        """Loads new XML file

        @param path: location to place the new file
        @raises ConfigurationException
        """
        if not self._is_file:
            raise ConfigurationException('Configuration load failed. Not a file.')

        if not os.path.exists(path):
            raise ConfigurationException(
                f"New XML file to be loaded not found at '{path}'")

        self._acquire_lock()
        try:
            self._validate_schema(path)
        except ConfigurationException:
            self._clean_up(path)
            raise

        logger.debug('Loaded file was successfully validated.')

        self._create_backup_file()

        try:
            copy_file(str(path), str(self._xml))
            remove_file(path)
        except (OSError, IOError, IsADirectoryError, PermissionError) as error:
            self._clean_up(path)
            raise ConfigurationException(
                f'Unable to create/replace existing configuration file: {error}')

        self.reload_xml()
        self._lock.release()
