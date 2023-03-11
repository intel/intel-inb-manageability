"""
    Module that handles parsing of XML files

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import io
import os.path
import pathlib
import logging

# following line is only used for type checking; we used defusedxml for
# actual processing
from xml.etree.ElementTree import Element  # noqa: S405
import defusedxml.ElementTree as element_tree
from defusedxml.ElementTree import XMLParser, parse, ParseError, tostring
from inbm_common_lib.utility import get_canonical_representation_of_path
from .security_masker import mask_security_info

import xmlschema
from defusedxml import DefusedXmlException, DTDForbidden, EntitiesForbidden, ExternalReferenceForbidden, \
    NotSupportedError
from .constants import PARSE_TIME_SECS
from concurrent.futures import ThreadPoolExecutor, as_completed

from typing import Dict, Union, Any

logger = logging.getLogger(__name__)


class XmlException(Exception):
    """Class exception Module"""
    pass


class XmlHandler:
    """Class for handling XML parsing

    @param xml: XML to be parsed (either as a string or file path)
    @param is_file: False by default, True if XML to be parsed is a file
    @param schema_location: location of schema file
    """

    def __init__(self, xml: str, is_file: bool, schema_location: Union[str, pathlib.Path]) -> None:
        self._is_file = is_file
        self._schema_location = schema_location
        logger.debug(f"SCHEMA LOC : {self._schema_location}")

        self._xml: str = xml
        with ThreadPoolExecutor(max_workers=1) as executor:
            tasks = {executor.submit(self._getroot, x): x for x in [xml]}

            for task in as_completed(tasks, timeout=PARSE_TIME_SECS):
                try:
                    self._root = task.result()
                except TimeoutError:
                    raise XmlException("XML Parser timed out.")

    def _validate(self, xml: str) -> Any:
        """Validates the XML file against the schema for security

        @param xml: XML contents
        @return parsed document
        @raises XmlException
        """
        logger.debug('validating XML file: {}'.format(mask_security_info(xml)))
        try:
            if not os.path.exists(self._schema_location):
                raise XmlException("Schema file not found at location: " +
                                   str(self._schema_location))

            parser = XMLParser(forbid_dtd=True, forbid_entities=True, forbid_external=True)

            if self._is_file:
                if not os.path.exists(xml):
                    raise XmlException("XML file not found")
                parsed_doc = parse(xml, parser)
            else:
                parsed_doc = parse(io.StringIO(xml), parser)

            if not os.path.exists(self._schema_location):
                raise XmlException("Schema file not found.")
            if os.path.islink(self._schema_location):
                raise XmlException("Schema file location is a symlink.")
            with open(get_canonical_representation_of_path(str(self._schema_location))) as schema_file:
                schema = xmlschema.XMLSchema11(schema_file)
                schema.validate(xml)

            return parsed_doc
        except (xmlschema.XMLSchemaValidationError, ParseError, DefusedXmlException, DTDForbidden,
                EntitiesForbidden, ExternalReferenceForbidden, NotSupportedError, xmlschema.XMLSchemaParseError) as error:
            raise XmlException(f'XML validation error: {error}')

    def __repr__(self) -> str:
        return "<XmlHandler xml=" + self._xml.__repr__() +\
               ", is_file=" + self._is_file.__repr__() +\
               ", schema_location=" + self._schema_location.__repr__() + ">"

    def get_element(self, xpath: str) -> str:
        """Find element matching XPath from parsed XML.

        @param xpath: Valid XPath expression
        @return: Value of the element in the parsed XML object
        """
        logger.debug("")
        element = self._root.findtext(xpath)
        if element is None:
            raise XmlException('Cannot find element at specified '
                               'path: {}'.format(xpath))
        return element

    def get_children(self, xpath) -> Dict[str, Any]:
        """Find all elements matching XPath from parsed XML

        @param xpath: Valid XPath expression
        @return: Values of the matched elements as a List
        @raises XmlException
        """
        children = {}
        elements = self._root.find(xpath)

        if elements is None:
            raise XmlException(f'Cannot find children at specified path: {xpath}')
        for each in elements:
            if each.text:
                children[each.tag] = each.text
            elif len(each):
                children[each.tag] = str(each.tag)
                logger.debug(f'The element {each.tag} has {len(each)} children.')
            else:
                raise XmlException('Empty tag encountered. XML rejected')

        return children

    def find_element(self, xpath: str) -> Any:
        """Finds an attribute for the given key.

        @param xpath: xpath expression to find element
        @return: value of element if path exists, else None
        """
        return self._root.findtext(xpath)

    def get_attribute(self, xpath: str, attribute_name: str) -> str:
        """Get attribute value for the given path and key.

        @param xpath: path to key
        @param attribute_name: name of attribute
        @return: attribute str if found else None
        """
        logger.debug("XML get attr")
        element = self._root.find(xpath)
        if element is not None:
            return element.attrib[attribute_name]
        else:
            raise XmlException("Could not find element in get_attribute")

    def add_attribute(self, xpath, attribute_name, attribute_value) -> bytes:
        """Add a new key value to the given path.

        @param xpath: path to key
        @param attribute_name: name of attribute
        @param attribute_value: value of attribute
        @return: Xml in bytes
        @raises: XmlException when failed to update XML
        """
        try:
            logger.debug("XML add attr")
            element = self._root.find(xpath)
            if element is None:
                raise XmlException("cannot add find element in add_attribute")
            subtag = Element(attribute_name)
            subtag.text = attribute_value
            try:
                element.append(subtag)
            except TypeError as e:
                # workaround for https://github.com/tiran/defusedxml/issues/54
                if 'expected an Element' in str(e):
                    element._children.append(subtag)  # type: ignore
                else:
                    raise e
            return tostring(self._root, encoding='utf-8')
        except (XmlException, ValueError, TypeError, KeyError) as e:
            raise XmlException(f"ERROR while add : {e}")

    def set_attribute(self, xpath, attribute_value) -> bytes:
        """Set a new value to the given path.

        @param xpath: path to key
        @param attribute_value: value of attribute to set
        @return: Xml in bytes
        @raises: XmlException when failed to update
        """
        try:
            logger.debug("XML set attr")
            element = self._root.find(xpath)
            if element is not None:
                element.text = attribute_value
            else:
                raise XmlException("The path doesn't contain the element specified")
            return tostring(self._root, encoding='utf-8')
        except (XmlException, ValueError, TypeError, KeyError) as e:
            raise XmlException(f"ERROR while set : {e}")

    def remove_attribute(self, xpath) -> bytes:
        """Remove the attribute from xml if found.

        @param xpath: path to key
        @return: Xml in bytes
        @raises: XmlException when failed to update
        """
        try:
            logger.debug("XML remove attr")
            element = self._root.find(xpath)
            if element is not None:
                # maps child -> parent
                parent_map = {c: p for p in self._root.iter() for c in p}

                parent = parent_map[element]
                parent.remove(element)
            return tostring(self._root, encoding='utf-8')
        except (XmlException, ValueError, TypeError, KeyError) as e:
            raise XmlException(f"ERROR while remove : {e}")

    def get_root_elements(self, key: str, attr: str) -> list:
        """This function retrieves all the elements matching
        the specified element and it's attribute
        @param key: element name
        @param attr: element's attribute name
        @return: list
        @raises: XmlException when failed to update
        """
        elements = []
        try:
            for ele in self._root.findall(key):
                val = ele.get(attr)
                elements.append(val)
            return elements
        except (XmlException, ValueError, TypeError, KeyError) as e:
            raise XmlException(f"ERROR while fetching elements from root : {e}")

    def _getroot(self, xml: str) -> Any:
        """This function validates and returns the root of the xml
        @param xml: xml contents
        @return: root path
        """
        logger.debug(f"XML : {mask_security_info(xml)}")
        return self._validate(xml).getroot()
