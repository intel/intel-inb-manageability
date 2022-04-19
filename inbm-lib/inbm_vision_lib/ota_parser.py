"""
    Copyright (C) 2019-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from typing import Dict, Any
from .xml_handler import XmlHandler
from .constants import FOTA, SOTA, PATH


class ParseException(Exception):
    """Parse exception module"""
    pass


def get_children(parsed: XmlHandler, key: str) -> dict:
    value = parsed.get_children(key)
    if value is None:
        raise ParseException(f'Unable to parse OTA manifest: missing {key}')
    return value


def parse_fota(resource: dict) -> Dict[str, Any]:
    return ({PATH: resource.get(PATH, None),
             'biosversion': resource.get('biosversion', None),
             'vendor': resource.get('vendor', None),
             'manufacturer': resource.get('manufacturer', None),
             'product': resource.get('product', None),
             'releasedate': resource.get('releasedate', None),
             'signature': resource.get('signature', None)})


def parse_sota(resource: dict) -> Dict[str, Any]:
    return ({PATH: resource.get(PATH, None),
             'release_date': resource.get('release_date', None),
             'cmd': resource.get('cmd', None),
             'logtofile': 'y',
             'signature': resource.get('signature', None)})


def parse_pota(parsed_head: XmlHandler, key: str) -> Dict[str, Any]:
    """ Parses POTA resources from manifest and creates a dictionary

        @param parsed_head: manifest values
        @param key: key to use when searching for children.  Will be different depending on if message was sent via
        xlink or MQTT.
        @return: dictionary of key/values to create revised manifest
        """
    fota_children = get_children(parsed_head, f'{key}/{FOTA}')
    fota_resource = parse_fota(fota_children)
    fota_resource['fota_path'] = fota_resource.pop('path')
    fota_resource['fota_signature'] = fota_resource.pop('signature')

    sota_children = get_children(parsed_head, f'{key}/{SOTA}')
    sota_resource = parse_sota(sota_children)
    sota_resource['sota_path'] = sota_resource.pop('path')
    sota_resource['sota_signature'] = sota_resource.pop('signature')

    if fota_resource is None or sota_resource is None:
        raise ParseException('Unable to parse OTA manifest: fota/sota')

    return {**fota_resource, **sota_resource}
