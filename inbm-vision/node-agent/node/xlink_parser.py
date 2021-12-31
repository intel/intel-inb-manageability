"""
    XLinkParser processes the messages received from Xlink and stores them as a list of
    directories.

    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
from typing import Optional, Any, Tuple, Dict
from .command.command import NodeCommands
from .node_exception import NodeException
from .constant import RESTART_MANIFEST

from inbm_vision_lib.ota_parser import ParseException, get_children, parse_fota, parse_sota, parse_pota
from inbm_vision_lib.constants import FOTA, SOTA, POTA, PARSE_TIME_SECS, ERROR_UNINITIALIZED_OBJECT, XmlException
from inbm_vision_lib.xml_handler import XmlHandler

logger = logging.getLogger(__name__)


class XLinkParser(object):
    """Concrete class to process the Command manifest receiving from xLink"""

    def __init__(self):
        self._xml_handler = None
        self.header = None
        self.command_type = None

    def parse(self, manifest, revise_manifest=None):
        """Called when a manifest is received from xLink and parsed

        @param manifest: OTA manifest from vision-agent
        @param revise_manifest : Revised OTA manifest and ready send to TC  
        @return: (str, str, dict) the type of command, node id, command info
        """
        logger.debug("Start parsing the manifest.")
        try:
            self._xml_handler = XmlHandler(xml=manifest)
        except XmlException as error:
            raise XmlException(error)

        self.header, self.command_type = self.check_command_type()
        if self.command_type is None:
            raise ValueError(
                "Error parsing manifest.  Command unsupported. {}".format(self.command_type))
        nid = self._check_nid()

        dictionary = None
        target_type = None
        if self.command_type is NodeCommands.RESTART.value:
            revise_manifest = RESTART_MANIFEST
        if self.command_type is NodeCommands.REQUEST_TO_DOWNLOAD.value:
            dictionary = self._parse_file_size()
        if self.command_type is NodeCommands.REGISTER_RESPONSE.value:
            dictionary = self._parse_heartbeat_interval()
        if self.command_type is NodeCommands.IS_ALIVE.value:
            dictionary = self._check_nid()
        if self.command_type is NodeCommands.OTA_UPDATE.value:
            revise_manifest = self._parse_ota_manifest(manifest)
        if self.command_type is NodeCommands.get_configuration.value \
                or self.command_type is NodeCommands.set_configuration.value \
                or self.command_type is NodeCommands.append_configuration.value \
                or self.command_type is NodeCommands.remove_configuration.value:
            dictionary, target_type = self._parse_config_manifest()
        if self.command_type is NodeCommands.config_request.value:
            dictionary, target_type, config_type = self._parse_config_request_manifest()
            self.command_type = config_type
        logger.debug("Parser done.")
        return self.command_type, nid, dictionary, revise_manifest, target_type

    def check_command_type(self) -> Tuple[Any, Any]:
        """This method is called to check the type of command object

        @return : (dict, str) The header of manifest, type of command
        """
        for command_type in NodeCommands:
            if self._xml_handler is None:
                raise NodeException(ERROR_UNINITIALIZED_OBJECT)
            logger.debug("command_type: {}".format(command_type))
            header = self._xml_handler.get_children(command_type.value)
            if header is not None:
                logger.debug("Command type: %s", command_type.value)
                return header, command_type.value
        return None, None

    def _check_nid(self) -> str:
        """Checks the node device id from the vision-agent
        @return: Node device id
        """
        if self._xml_handler is None:
            raise NodeException(ERROR_UNINITIALIZED_OBJECT)
        nid = self._xml_handler.get_attribute(self.command_type, "id")

        if not nid:
            raise ValueError("Error parsing manifest. Node ID not found.")

        logger.info("Node id: %s", str(nid))
        return nid

    def _parse_file_size(self):
        """This method is called to check the file_size given by vision-agent
        @return: int file size info in KB
        """
        if self._xml_handler is None:
            raise NodeException(ERROR_UNINITIALIZED_OBJECT)
        if self.command_type is None:
            raise NodeException(ERROR_UNINITIALIZED_OBJECT)
        file_size = self._xml_handler.get_children(self.command_type + '/items')
        file_size_info = file_size["size_kb"]

        logger.info("Firmware file size information: " + str(file_size_info))
        return file_size_info

    def _parse_heartbeat_interval(self):
        """check the heartbeat interval value from vision-agent
        @return: heartbeat interval value
        """
        if self._xml_handler is None:
            raise NodeException(ERROR_UNINITIALIZED_OBJECT)
        heartbeat_interval = self._xml_handler.get_children(self.command_type)
        heartbeat_interval_info = heartbeat_interval["heartbeatIntervalSecs"]
        logger.info("heartbeat interval information: " + str(heartbeat_interval_info))
        return heartbeat_interval_info

    def _parse_config_manifest(self):
        """Get the key value when receiving getConfigValues request from vision-agent.

        @return: key to fetch the value
        """
        if self._xml_handler is None:
            raise NodeException(ERROR_UNINITIALIZED_OBJECT)
        key, config_key = self._xml_handler.get_multiple_children(
            '{}/items'.format(self.command_type))
        children = self._xml_handler.get_children(self.command_type)
        target_type = children["targetType"]
        try:
            dictionary = []
            for num in range(config_key):
                dictionary.append(key["key" + str(num)])
            logger.info("Configuration key message received is: %s", dictionary)
            return dictionary, target_type

        except KeyError as error:
            raise NodeException("Invalid XML element format error: " + str(error))

    def _parse_ota_manifest(self, manifest, schema_location=None) -> Optional[str]:
        """parses the manifest sent from the vision-agent and creates a revised manifest for the Node OTA client.
        @param manifest: manifest sent from vision-agent
        @schema_location: location of schema file
        @return: revised manifest for OTA client
        """
        parsed = XmlHandler(xml=manifest, schema_location=schema_location)
        try:
            header = parsed.get_children('otaUpdate/items/manifest/ota/header')
            if header is None:
                raise NodeException('Unable to parse OTA manifest: header')
            ota_type = header.get('type', None)

            if ota_type == FOTA:
                resource = get_children(parsed, 'otaUpdate/items/manifest/ota/type/fota')
                parsed_params = parse_fota(resource)
            elif ota_type == SOTA:
                resource = get_children(parsed, 'otaUpdate/items/manifest/ota/type/sota')
                parsed_params = parse_sota(resource)
            elif ota_type == POTA:
                parsed_params = parse_pota(parsed, 'otaUpdate/items/manifest/ota/type/pota')

            logger.debug("____________________________________________________________________")
            for key in parsed_params:
                logger.debug('{0}: {1}'.format(key, parsed_params[key]))
            logger.debug("____________________________________________________________________")
            logger.debug('Done process the manifest.')

            return self.revise_fota_manifest(parsed_params) if ota_type == FOTA \
                else self.revise_sota_manifest(parsed_params) if ota_type == SOTA \
                else self.revise_pota_manifest(parsed_params)

        except (XmlException, ValueError, NodeException) as error:
            logger.error('Error parsing/validating manifest: {}'.format(error))
            return None

    def revise_fota_manifest(self, parsed_params: Dict[str, str]) -> str:
        """Modify FOTA manifest to be sent to node client

        @param parsed_params: parsed manifest in dictionary format
        @return: string representing revised manifest
        """
        revised_manifest = ('<?xml version="1.0" encoding="utf-8"?>'
                            '            <manifest>'
                            '                <type>ota</type>'
                            '                <ota>'
                            '                    <header>'
                            '                        <type>fota</type>'
                            '                        <repo>local</repo>'
                            '                    </header>'
                            '                    <type>'
                            '                        <fota name="sample">'
                            '                            <path>{}</path>'
                            '                            <biosversion>{}</biosversion>'
                            '                            <vendor>{}</vendor>'
                            '                            <manufacturer>{}</manufacturer>'
                            '                            <product>{}</product>'
                            '                            <releasedate>{}</releasedate>'
                            '{}'
                            '                        </fota>'
                            '                    </type>'
                            '                </ota>'
                            '            </manifest>'
                            ).format(
            parsed_params['path'],
            parsed_params['biosversion'],
            parsed_params['vendor'],
            parsed_params['manufacturer'],
            parsed_params['product'],
            parsed_params['releasedate'],
            "                            <signature>{}</signature>".format(
                parsed_params['signature']) if parsed_params['signature'] else "")
        return revised_manifest

    def revise_sota_manifest(self, parsed_params: Dict[str, str]) -> str:
        """Modify SOTA manifest to be sent to node client

        @param parsed_params: parsed manifest in dictionary format
        @return: string representing revised manifest
        """
        revised_manifest = ('<?xml version="1.0" encoding="utf-8"?>'
                            '            <manifest>'
                            '                <type>ota</type>'
                            '                <ota>'
                            '                    <header>'
                            '                        <type>sota</type>'
                            '                        <repo>local</repo>'
                            '                    </header>'
                            '                    <type>'
                            '                        <sota>'
                            '                            <cmd logtofile="{}">{}</cmd>'
                            '{}'
                            '                            <release_date>{}</release_date>'
                            '                            <path>{}</path>'
                            '                        </sota>'
                            '                    </type>'
                            '                </ota>'
                            '            </manifest>'
                            ).format(
            parsed_params['logtofile'],
            parsed_params['cmd'],
            "                            <signature>{}</signature>".format(
                parsed_params['signature'])
            if parsed_params['signature'] != "None" else "",
            parsed_params['release_date'],
            parsed_params['path'])
        logger.debug(revised_manifest)
        return revised_manifest

    def revise_pota_manifest(self, parsed_params: Dict[str, str]) -> str:
        """Modify POTA manifest to be sent to node client

        @param parsed_params: parsed manifest in dictionary format
        @return: string representing revised manifest
        """
        revised_manifest = ('<?xml version="1.0" encoding="utf-8"?>'
                            '            <manifest>'
                            '                <type>ota</type>'
                            '                <ota>'
                            '                    <header>'
                            '                        <type>pota</type>'
                            '                        <repo>local</repo>'
                            '                    </header>'
                            '                    <type>'
                            '                        <pota>'
                            '                            <fota name="sample">'
                            '                                <path>{}</path>'
                            '                                <biosversion>{}</biosversion>'
                            '                                <manufacturer>{}</manufacturer>'
                            '                                <product>{}</product>'
                            '                                <vendor>{}</vendor>'
                            '                                <releasedate>{}</releasedate>'
                            '{}'
                            '                            </fota>'
                            '                            <sota>'
                            '                                <cmd logtofile="{}">{}</cmd>'
                            '{}'
                            '                                <release_date>{}</release_date>'
                            '                                <path>{}</path>'
                            '                            </sota>'
                            '                        </pota>'
                            '                    </type>'
                            '                </ota>'
                            '            </manifest>'
                            ).format(
            parsed_params['fota_path'],
            parsed_params['biosversion'],
            parsed_params['manufacturer'],
            parsed_params['product'],
            parsed_params['vendor'],
            parsed_params['releasedate'],
            "                                <signature>{}</signature>".format(parsed_params['fota_signature']) if parsed_params[
                'fota_signature'] else "",
            parsed_params['logtofile'],
            parsed_params['cmd'],
            "                                <signature>{}</signature>".format(parsed_params['sota_signature']) if
            parsed_params['sota_signature'] else "",
            parsed_params['release_date'],
            parsed_params['sota_path'])

        logger.debug(revised_manifest)
        return revised_manifest

    def _parse_config_request_manifest(self) -> Tuple[str, str, str]:
        """Get the config request info when receiving config request from vision-agent.

        @return: new config file directory, target type and config request type
        """
        if self._xml_handler is None:
            raise NodeException(ERROR_UNINITIALIZED_OBJECT)
        if self.command_type is None:
            raise NodeException(ERROR_UNINITIALIZED_OBJECT)
        config_info = self._xml_handler.get_children(self.command_type + '/items/manifest/config')
        config_type = config_info["cmd"]
        target_type = config_info["targetType"]
        path = self._xml_handler.get_children(
            self.command_type + '/items/manifest/config/configtype/{0}'.format(config_type))
        path = path["path"]
        return path, target_type, config_type
