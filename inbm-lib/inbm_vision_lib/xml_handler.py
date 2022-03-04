"""
    Handles parsing of XML files

    Copyright (C) 2019-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import os.path
import xmlschema
import pathlib
import logging
import defusedxml.ElementTree as element_tree
from typing import Optional, Tuple, Union, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from defusedxml import DefusedXmlException, DTDForbidden, EntitiesForbidden, ExternalReferenceForbidden, \
    NotSupportedError

from inbm_vision_lib.constants import PARSE_TIME_SECS, XmlException


logger = logging.getLogger(__name__)


class XmlHandler:

    """Class for handling XML parsing

    @param xml: XML to be parsed (either as a string or file path)
    @param schema_location: location of schema file
    """

    def __init__(self, xml: Union[str, pathlib.Path], schema_location: str = None) -> None:
        self._xml = xml
        self._schema_location = schema_location
        with ThreadPoolExecutor(max_workers=1) as executor:
            tasks = {executor.submit(self._get_root, x): x for x in [xml]}
            for task in as_completed(tasks, timeout=PARSE_TIME_SECS):
                try:
                    self._root = task.result()
                except TimeoutError as err:
                    raise XmlException("XML Parser timed out.") from err

    def _validate_schema(self, xml_file: str = None) -> None:
        if self._schema_location is not None:
            if not os.path.exists(self._schema_location):
                raise XmlException("Schema file not found.")
            if os.path.islink(self._schema_location):
                raise XmlException("Schema file location is a symlink.")
            with open(self._schema_location) as schema_file:
                schema = xmlschema.XMLSchema11(schema_file)
                if xml_file:
                    schema.validate(xml_file)
                else:
                    schema.validate(self._xml)

    def _get_root(self, xml):
        """Called when a manifest is received from xlink.
        @return: root path
        @raises: XmlException: raise XmlException when error happen
        """
        try:
            logger.debug(f"XML : {xml}")
            root = element_tree.fromstring(xml.encode('utf-8'))  # type: ignore
            self._validate_schema()
            return root
        except (xmlschema.XMLSchemaValidationError, element_tree.ParseError, DefusedXmlException, DTDForbidden,
                EntitiesForbidden, ExternalReferenceForbidden, NotSupportedError) as error:
            raise XmlException(f'Error with xml {error}')

    def __repr__(self) -> str:
        return "<XmlHandler xml=" + self._xml.__repr__() + \
            ", schema_location=" + self._schema_location.__repr__() + ">"

    def get_element(self, xpath):
        """Find element matching XPath from parsed XML

        @param xpath: Valid XPath expression
        @return: Value of the element in the parsed XML object
        """
        element = self._root.findtext(xpath)
        if element is None:
            raise XmlException('Cannot find element at specified '
                               'path: {}'.format(xpath))

        return element

    def get_children(self, path: str) -> Optional[dict]:
        """Find all elements matching path from parsed XML

        @param path: path to location
        @return: Values of the matched elements as a List
        """
        children: Dict[str, Any] = {}

        if self._root is None:
            raise XmlException('Root element is None.')

        elements = self._root.find(path)
        if elements is None:
            return None

        for child in elements.getchildren():
            if child.text:
                children[child.tag] = child.text
            elif len(child):
                logger.debug("The element {} has {} children.".format(child.tag, len(child)))
            else:
                raise XmlException(
                    f'Cannot find value at specified element - {child.tag}')
        return children

    def get_multiple_children(self, xpath: str) -> Tuple[dict, int]:
        """Find all elements matching XPath from parsed XML

        @param xpath: Valid XPath expression
        @return: Values of the matched elements as a List and number of the matched elements and
        the number of matched element
        """
        children: Dict[str, Any] = {}
        elements = self._root.find(xpath)
        i = 0

        if elements is None:
            logger.debug(f'Cannot find children at path: {xpath}')
            return children, i

        for e in elements:
            if e.text:
                children[e.tag + str(i)] = e.text
                i = i + 1
            else:
                logger.debug("No targets tag found.")
        return children, i

    def get_attribute(self, xpath, attribute_name):
        """Get attribute value for the given path and key

        @xpath: path to key
        @attribute_name: name of attribute
        """
        element = self._root.find(xpath)
        return element.attrib[attribute_name]
