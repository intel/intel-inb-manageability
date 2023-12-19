"""
    Copyright (C) 2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import json
from dispatcher.common.result_constants import Result
from dispatcher.source.constants import OsType, SourceParameters
from dispatcher.source.source_manager_factory import create_os_source_manager
from dispatcher.source.source_manager_factory import create_application_source_manager
from inbm_lib.xmlhandler import XmlException, XmlHandler

logger = logging.getLogger(__name__)

def do_source_command(parsed_head: XmlHandler, os_type: OsType) -> Result:
    """Run a source command.
    
    @param parsed_head: XmlHandler corresponding to the manifest tag
    @param os_type: os type
    @return Result"""

    logger.debug(f"do_source_command: {parsed_head}")

    try:
        parsed_head.get_element('osSource')
        os_source_manager = create_os_source_manager(os_type)

        if parsed_head.get_children('osSource') == {'list': ''}:
            return Result(status=200, message=json.dumps(os_source_manager.list()))
        if parsed_head.get_children('osSource') == {'remove': 'remove'}:
            source_pkgs: list[str] = []
            for key, value in parsed_head.get_children_tuples('osSource/remove/repos'):
                if key == 'source_pkg':
                    source_pkgs.append(value)
            remove_parameters = SourceParameters(sources=source_pkgs)
            return Result(status=200, message=json.dumps(os_source_manager.remove(remove_parameters)))
    except XmlException:
        try:
            parsed_head.get_element('applicationSource')
            application_source_manager = create_application_source_manager(os_type)

            if parsed_head.get_children('applicationSource') == {'list': ''}:
                return Result(status=200, message=json.dumps(application_source_manager.list()))
        except XmlException as e:
            return Result(status=400, message="unable to handle source command XML: {e}")
    
    return Result(status=400, message="unknown source command")