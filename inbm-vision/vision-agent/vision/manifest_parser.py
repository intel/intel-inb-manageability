"""
     Methods used to parse the manifest from the Cloud or INBC tool
     Handles the manifest received from an OTA client and revises it for the nodes.

    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
from dataclasses import dataclass, asdict
from typing import Optional, List, Any, Dict

from inbm_vision_lib.constants import NODE, NODE_CLIENT, SOTA, POTA, FOTA, PATH, RESTART, QUERY, UNKNOWN
from inbm_vision_lib.ota_parser import ParseException, get_children, parse_fota, parse_sota, parse_pota
from inbm_vision_lib.xml_handler import XmlException, XmlHandler
from .constant import SCHEMA_LOCATION, VisionException

logger = logging.getLogger(__name__)


@dataclass
class ParsedManifest:
    manifest_type: str
    info: Dict[str, Any]
    targets: List[str]

    @classmethod
    def from_instance(cls, instance):
        return cls(**asdict(instance))


@dataclass
class TargetParsedManifest(ParsedManifest):
    target_type: str


def parse_manifest(manifest: str, schema_location: Optional[str] = None) -> ParsedManifest:
    """Parses the OTA manifest received from OTA client. Grab the information and store
    them in dictionary format.

    @param manifest: OTA manifest receiving from OTA client
    @param schema_location:  optional location for manifest schema
    @return: The type of update, node info stored in dictionary format,
    the list of targeted node to be updated, config target agent
    """
    try:
        if schema_location:
            parsed = XmlHandler(xml=manifest, schema_location=schema_location)
        else:
            parsed = XmlHandler(xml=manifest, schema_location=SCHEMA_LOCATION)
    except XmlException as error:
        raise XmlException(error)

    type_of_manifest = parsed.get_element('type')

    if type_of_manifest == 'cmd':
        cmd = parsed.get_element('cmd')
        if cmd == RESTART:
            return _parse_restart_targets(parsed)
        if cmd == QUERY:
            return _parse_query_targets(parsed)
        if cmd == 'provisionNode':
            return _parse_provision_request(parsed)

    if type_of_manifest == 'config':
        logger.debug('Running configuration command sent down ')
        return _parse_config_request(parsed)

    if type_of_manifest == 'ota':
        ota_type, parsed_params, parsed_dict = _parse_ota(parsed)

        target, num_targets = parsed.get_multiple_children(
            'ota/type/{}/targets'.format(ota_type))

        if parsed_dict:
            parsed_params.update(parsed_dict)

        logger.debug("____________________________________________________________________")
        for key in parsed_params:
            logger.debug('{0}: {1}'.format(key, parsed_params[key]))

        node_list = []
        for num in range(num_targets):
            update_key = 'node_id' + str(num)
            update_value = target["target" + str(num)]
            update_dict = {update_key: update_value}
            parsed_params.update(update_dict)
            logger.debug('node_id%i: %s', num, parsed_params['node_id' + str(num)])
            node_list.append(parsed_params['node_id' + str(num)])

        logger.debug("____________________________________________________________________")
        logger.debug('Done processing the manifest.')
        logger.debug(parsed_params)
        return ParsedManifest(ota_type, parsed_params, node_list)
    else:
        # It shouldn't get here because the xmlschema should catch an invalid type.
        raise VisionException("Invalid request sent...")


def _parse_restart_targets(parsed_head: XmlHandler) -> ParsedManifest:
    target_list = []
    targets, num_targets = parsed_head.get_multiple_children('restart/targets')
    for num in range(num_targets):
        target_list.append(targets['target' + str(num)])
    return ParsedManifest(RESTART, {}, target_list)


def _parse_query_targets(parsed_head: XmlHandler) -> ParsedManifest:
    target_list = []
    target_type = parsed_head.get_element('query/targetType')
    option = parsed_head.get_element('query/option')
    targets, num_of_targets = parsed_head.get_multiple_children('query/targets')
    for num in range(num_of_targets):
        target_list.append(targets['target' + str(num)])

    parsed_params = {'option': option}

    return TargetParsedManifest(QUERY, parsed_params, target_list, target_type)


def _parse_provision_request(parsed_head: XmlHandler) -> ParsedManifest:
    """Parses the provision node request manifest received from OTA client.

    @param parsed_head: instance of XmlHandler
    @return: command type and the path of blob and cert
    """
    header = get_children(parsed_head, 'provisionNode')
    blob_path = header.get('blobPath', None)
    cert_path = header.get('certPath', None)

    parsed_params = ({'blob_path': blob_path,
                      'cert_path': cert_path})

    return ParsedManifest('provisionNode', parsed_params, [])


def _parse_config_request(parsed_head: XmlHandler) -> TargetParsedManifest:
    """Parses the configuration request manifest received from OTA client.

    @param parsed_head: instance of XmlHandler
    @return: type of config request, node info stored in dictionary format,
    the list of targeted node to be configured, config target agent
    """
    config_cmd_type = parsed_head.get_element('config/cmd')
    value_object: Dict[str, Any] = {}

    agent = parsed_head.get_element('config/targetType')
    if config_cmd_type in ['load', 'append', 'remove']:
        p = 'config/configtype/{}'.format(config_cmd_type)
        header = parsed_head.get_children(p)
        if header:
            value_object.update({PATH: header[PATH]})
    elif config_cmd_type == 'get_element':
        header = parsed_head.get_children('config/configtype/get')
        if header:
            value_object = ({PATH: header[PATH]})
    elif config_cmd_type == 'set_element':
        header = parsed_head.get_children('config/configtype/set')
        if header:
            value_object = ({PATH: header[PATH].strip()})

    _check_agent_type(config_cmd_type, agent)

    target_list = _get_targets(agent, parsed_head)

    logger.debug('path=%s', value_object[PATH])
    return TargetParsedManifest(config_cmd_type, value_object, target_list, target_type=agent)


def _check_agent_type(cmd_type: str, agent: str) -> None:
    if cmd_type in ['append', 'remove']:
        if agent != NODE_CLIENT:
            raise VisionException(
                "{0} does not support {1} request.".format(agent, cmd_type))


def _get_targets(agent: str, parsed_head: XmlHandler) -> List[str]:
    target_list: List[str] = []
    if agent == NODE or agent == NODE_CLIENT:
        targets, num_of_targets = parsed_head.get_multiple_children(
            'config/configtype/targets')
        for num in range(num_of_targets):
            target_list.append(targets['target' + str(num)])
    return target_list


def _parse_ota(parsed: XmlHandler):
    try:
        header = get_children(parsed, 'ota/header')
        ota_type = header.get('type', None)
        repo = header.get('repo', None)

        parsed_params = ({'repo': repo,
                          'ota': ota_type})
        if ota_type == FOTA:
            resource = get_children(parsed, 'ota/type/fota')
            parsed_dict = parse_fota(resource)
        elif ota_type == SOTA:
            resource = get_children(parsed, 'ota/type/sota')
            parsed_dict = parse_sota(resource)
        elif ota_type == POTA:
            parsed_dict = parse_pota(parsed, 'ota/type/pota')
        else:
            VisionException("Unsupported OTA type.")
        return ota_type, parsed_params, parsed_dict
    except ParseException as error:
        raise VisionException("Error parsing OTA request: {}".format(error))
