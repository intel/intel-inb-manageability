"""
    Module that handles parsing of XML files

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import io
import logging
import os.path

# This import is necessary for type checking to work but we do not use it
# independently of defusedxml
from xml.etree.ElementTree import Element  # noqa: S405
import defusedxml
import xmlschema
from defusedxml import DefusedXmlException, DTDForbidden, EntitiesForbidden, ExternalReferenceForbidden, \
    NotSupportedError
from defusedxml.ElementTree import ParseError

from .ikeyvaluestore import IKeyValueStore
from .constants import ATTRIB_NAME
from .configuration_exception import ConfigurationException

from inbm_lib.constants import PARSE_TIME_SECS
from inbm_lib.security_masker import mask_security_info
from inbm_common_lib.utility import get_canonical_representation_of_path
from concurrent.futures import ThreadPoolExecutor, as_completed

from typing import Optional, Any

logger = logging.getLogger(__name__)


class XmlException(Exception):
    """Class exception Module"""
    pass


class XmlKeyValueStore(IKeyValueStore):
    """Class for handling XML parsing

    @param xml: XML to be parsed (either as a string or file path)
    @param is_file: True by default, True if XML to be parsed is a file
    @param schema_location: Location of the schema file.
    """

    def __init__(self,
                 xml: str,
                 is_file: bool,
                 schema_location: str) -> None:
        self._is_file = is_file
        self._schema_location = get_canonical_representation_of_path(schema_location)
        self._xml: str = get_canonical_representation_of_path(xml) if is_file else xml
        self._parse_xml_in_time_limit(self._xml)

    def _validate(self, xml: str) -> Any:
        """Validates the XML file against the schema for security

        @param xml: XML contents
        @return parsed document
        @raises XmlException
        """
        logger.debug(f'validating XML file: {mask_security_info(xml)}')
        try:
            if not os.path.exists(self._schema_location):
                raise XmlException("Schema file not found.")

            parser = defusedxml.ElementTree.XMLParser(
                forbid_dtd=True, forbid_entities=True, forbid_external=True)

            if self._is_file:
                if not os.path.exists(xml):
                    raise XmlException("XML file not found")
                parsed_doc = defusedxml.ElementTree.parse(xml, parser)
            else:
                parsed_doc = defusedxml.ElementTree.parse(io.StringIO(xml), parser)

            if not os.path.exists(self._schema_location):
                raise XmlException("Schema file not found.")
            if os.path.islink(self._schema_location):
                raise XmlException("Schema file location is a symlink.")
            with open(self._schema_location) as schema_file:
                schema = xmlschema.XMLSchema11(schema_file)
                schema.validate(xml)

            return parsed_doc
        except (xmlschema.XMLSchemaValidationError, ParseError, DefusedXmlException, DTDForbidden,
                EntitiesForbidden, ExternalReferenceForbidden, NotSupportedError) as error:
            raise XmlException(f'Error with xml {error}')

    @staticmethod
    def _write_file(file_to_open: str, file_to_write: str) -> None:
        try:
            with open(file_to_open) as f:
                opened_xml_file = f.read()
            with open(file_to_write, "w") as f:
                f.write(opened_xml_file)
        except OSError as err:
            raise XmlException(
                f"Unable to write configuration file: {err}")

    def load(self, xml_file_path: str) -> None:
        """Loads new XML file

        @param xml_file_path: location to place the new file
        @raises XmlException
        """
        file_path = get_canonical_representation_of_path(xml_file_path)
        if self._is_file:
            if not os.path.exists(file_path):
                logger.debug(f"New XML file to be loaded not found at '{file_path}")
                raise XmlException(
                    f"New XML file to be loaded not found.")

        self._parse_xml_in_time_limit(file_path)
        logger.debug('Loaded file was successfully validated')

        backup_file = self._xml + '_bak'
        self._write_file(self._xml, backup_file)
        logger.debug(f"Backup file: {backup_file}")

        self._write_file(file_path, self._xml)

    def get_element(self, path: str, element_string: Optional[str] = None, is_attribute: bool = False) -> str:
        """Find element matching XPath from parsed XML

        @param path: Valid XPath expression or multiple headers ';' separated
        @param element_string: String of ; separated elements whose values need to be returned
        @return: Value of the element in the parsed XML object
        @param is_attribute: determines if attribute value needs to be returned
        """
        if element_string is None:
            val = self._get_attribute_value(path) if is_attribute else self._get_value(path)
            return path + ':' + val
        else:
            elements = element_string.split(',')
            results = ''
            for ele in elements:
                var_list = ele.split(':', 1)
                var = var_list[0].strip('\'')
                val = self._get_attribute_value(path + '/' + var) if is_attribute \
                    else self._get_value(path + '/' + var)
                results += '{' + path + '/' + var + ':' + str(val) + '},'
            return results

    def set_element(self, xpath: str, value: str = "", value_string: Optional[str] = None,
                    is_attribute: bool = False) -> str:
        """This method is used to set an element value/element attribute value

        @param xpath: Valid XPath expression or multiple headers ';' separated
        @param value: Value to set
        @param value_string: multiple variable value string separated by ;
        @param is_attribute: determines if attribute value needs to be set
        """
        if value_string is None:
            self._set_element_value(xpath, value)
            return value
        else:
            values = value_string.split(",")
            paths = ''
            for val in values:
                val_list = val.split(':', 1)
                ele = val_list[0]
                value = val_list[1]
                if is_attribute:
                    self._set_element_attribute_value(ele, value)
                else:
                    self._set_element_value(xpath + '/' + ele, value)
                paths += xpath + '/' + ele + ':' + value + ';'
            return paths

    def get_children(self, xpath):
        """Find all elements matching XPath from parsed XML

        @param xpath: Valid XPath expression
        @return: Values of the matched elements as a List
        @raises XmlException
        """
        children = {}
        elements = self._root.find(xpath)

        if elements is None:
            raise XmlException('Cannot find children at specified '
                               'path: {}'.format(xpath))
        for each in elements:
            children[each.tag] = each.text
        return children

    def append(self, path: str, value_string: str) -> str:
        """Append method gets the existing values of the element in xml and 
        appends the new value to the existing values.

        @param path: Valid XPath expression or multiple headers ';' separated
        @param value_string: single or multiple variable value string separated by ;
        """
        logger.debug("")
        path_values = self.get_element(path, value_string)
        element_header = path_values.strip('{').strip('}').split(":", 1)[0].split("/", 1)[0]
        element_value = path_values.strip('{').strip('},').split(
            "/", 1)[1] + '\n\t    ' + value_string.split(":", 1)[1] + "\n\t"
        paths = self.set_element(element_header, value_string=element_value)
        return paths

    def remove(self, path, value=None, value_string=None):
        """Remove method gets the existing values of the element in xml and 
        removes the value from the existing values.

        @param path: Valid XPath expression or multiple headers ';' separated
        @param value: Value to set
        @param value_string: multiple variable value string separated by ;
        """
        logger.debug("")
        path_values = self.get_element(path, value_string)
        element_header_path = path_values.strip('{').strip('}').split(":", 1)[0]
        element_name = element_header_path.split("/", 1)[1]
        element_header = element_header_path.split("/", 1)[0]
        element_path_values = path_values.strip('{').strip('},').split(":", 1)[1]
        value_to_remove = value_string.split(":", 1)[1]

        if element_path_values is None or element_path_values == '':
            error = "The element path has no values listed in the conf file: {}".format(
                element_header_path)
            logger.error(error)
            raise ConfigurationException(error)
        else:
            element_values = element_path_values.strip().splitlines()
            element_values = list(map(str.strip, element_values))
            if value_to_remove in element_values:
                logger.debug("string exists in the element's value list")
                element_values.remove(value_to_remove)
                updated_element_values = '\n\t    '.join(element_values)
                updated_element_values = '\n\t    ' + updated_element_values + '\n\t'
                new_value_string = element_name + ":" + updated_element_values
                paths = self.set_element(element_header, value_string=new_value_string)
                return paths
            else:
                error = "The following element path doesn't contain the value to remove: {}".format(
                    element_header_path)
                logger.error(error)
                raise ConfigurationException(error)

    def _get_attribute_value(self, path: str) -> str:
        xml_tag = path.split("/")[-1]
        elements = self._root.findall(xml_tag)
        return str(elements[0].attrib.get(ATTRIB_NAME))

    def _get_value(self, path: str) -> str:
        """Method used to return the required value from XML file

         @param path: xml element
         @return: value of the respective element
         """
        elem = self._root.findtext(path)
        if elem is None:
            raise XmlException('Cannot find element at specified '
                               'path: {}'.format(path))
        return elem

    def _write_to_file(self, file_path: str) -> None:
        """Method used to write XML elements to file

        @param file_path: path to XML file
        """
        try:
            xml_str: str = defusedxml.ElementTree.tostring(self._root, 'unicode')
            with open(file_path, "w") as file:
                file.write(xml_str)
        except OSError:
            logger.debug(f"Unable to write at specified path: {file_path}")
            raise XmlException('Unable to write configuration changes')

    def _validate_file(self):
        try:
            self._validate(self._xml)
        except XmlException as e:
            raise ConfigurationException(
                f"Configuration Set Element Failed: {e} Keeping old value")

    def _update_file(self, elements: Any, value: str, is_attribute: bool = False) -> None:
        """Method used to update the value of the element key in XML file

         @param elements: xml element
         @param value: new value to be set for the respective element
         @param is_attribute: determines if attribute value be updated
         """
        if not self._is_file:
            raise ConfigurationException("cannot write non-file XML key value store to file")

        if is_attribute:
            old_value = elements[0].attrib.get(ATTRIB_NAME)
            elements[0].attrib[ATTRIB_NAME] = str(value)
        else:
            old_value = elements[0].text
            elements[0].text = str(value)
        try:
            self._write_to_file(file_path=self._xml)
            self._validate_file()
        except XmlException:
            raise ConfigurationException("Exception caught while writing to file")
        except ConfigurationException as err:
            elements[0].text = old_value
            self._write_to_file(file_path=self._xml)
            raise ConfigurationException(err)

    def _set_element_value(self, xpath: str, value: str) -> None:
        elements = self._root.findall(xpath)
        if len(elements) > 0:
            if self._is_file:
                self._update_file(elements=elements, value=value)
            else:
                elements[0].text = str(value)
        else:
            raise XmlException(f'Cannot find element at specified path: {xpath}')

    def _set_element_attribute_value(self, element_tag: str, attribute_value: str) -> None:
        """Find the element_tag from XML file and update it's attribute value

         @param element_tag: xml element tag name
         @param attribute_value: new attribute value to be set
         """
        elements = self._root.findall(element_tag)
        if elements:
            if self._is_file:
                self._update_file(elements=elements, value=attribute_value, is_attribute=True)
            else:
                elements[0].attrib[ATTRIB_NAME] = attribute_value
        else:
            raise XmlException(f'Cannot find element at specified path: {element_tag}')

    def get_parent(self, child_element: str) -> Optional[str]:
        """Find the parent of the child element from XML file

         @param child_element: child element tag
         @return: parent element tag
          """
        tree = self._root
        parent = None

        # maps child -> parent
        parent_map = {c: p for p in tree.iter() for c in p}

        for element in tree.iter():
            if element.tag == str(child_element):
                parent = parent_map[element]

        if parent is None:
            raise XmlException(
                f'Cannot find parent with specified child tag: {child_element}')

        return parent.tag

    def _parse_xml_in_time_limit(self, xml: str) -> None:
        """This function parses the XML within a time limit
        @param xml: xml contents
        @raises: XmlException: raise XmlException when timeout
        """
        with ThreadPoolExecutor(max_workers=1) as executor:
            tasks = {executor.submit(self._getroot, x): x for x in [xml]}
            for task in as_completed(tasks, timeout=PARSE_TIME_SECS):
                try:
                    self._root = task.result()
                except TimeoutError:
                    raise XmlException("XML Parser timed out.")

    def _getroot(self, xml: str) -> Any:
        """This function validates and returns the root of the xml
        @param xml: xml contents
        @return: root path
        @raises: XmlException: raise XmlException when error happen
        """
        try:
            logger.debug(f"XML : {mask_security_info(xml)}")
            return self._validate(xml).getroot()
        except (xmlschema.XMLSchemaValidationError, ParseError, DefusedXmlException, DTDForbidden,
                EntitiesForbidden, ExternalReferenceForbidden, NotSupportedError) as error:
            raise XmlException(f'Error with xml {error}')
