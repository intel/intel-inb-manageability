"""
    Module that contains the method for processing OTA resource

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from inbm_lib.xmlhandler import *


def create_ota_resource_list(parsed_head: XmlHandler, resource: Dict) -> Dict[str, Any]:
    """Creates a list of OTA commands requested under POTA along with the resources and arguments
    associated with each OTA

    @param parsed_head: Parsed head of the manifest xml
    @param resource: resource to parse
    @return Dict: A dict containing all the OTAs to be performed
    """
    ota_resource_dict = {}
    for key in resource.keys():
        ota_resource = parsed_head.get_children(f'ota/type/pota/{key}')
        if key == 'fota':
            ota_resource['holdReboot'] = True
        ota_resource_dict[key] = ota_resource
    return ota_resource_dict
