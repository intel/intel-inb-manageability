"""
    Copyright (C) 2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import json
from dispatcher.common.result_constants import Result
from dispatcher.source.constants import ApplicationRemoveSourceParameters, OsType, SourceParameters
from dispatcher.source.source_manager_factory import create_os_source_manager
from dispatcher.source.source_manager_factory import create_application_source_manager
from inbm_lib.xmlhandler import XmlException, XmlHandler

logger = logging.getLogger(__name__)


def do_source_command(parsed_head: XmlHandler, os_type: OsType) -> Result:
    """
    Run a source command.

    @param parsed_head: XmlHandler corresponding to the manifest tag
    @param os_type: os type
    @return Result
    """
    logger.debug(f"do_source_command: {parsed_head}")

    try:
        os_action = parsed_head.get_children('osSource')
        if os_action:
            return _handle_os_source_command(parsed_head, os_type, os_action)
    except XmlException:
        pass  # If we get an XmlException here we still want to try applicationSource

    try:
        app_action = parsed_head.get_children('applicationSource')
        if app_action:
            return _handle_app_source_command(parsed_head, os_type, app_action)
    except XmlException as e:
        return Result(status=400, message=f"unable to handle source command XML: {e}")

    return Result(status=400, message="unknown source command")


def _handle_os_source_command(parsed_head: XmlHandler, os_type: OsType, os_action: dict) -> Result:
    """
    Handle the os source commands.

    @param parsed_head: XmlHandler with command information
    @param os_type: os type
    @param os_action: The action to be performed
    @return Result
    """
    os_source_manager = create_os_source_manager(os_type)

    if os_action == {'list': ''}:
        return Result(status=200, message=json.dumps(os_source_manager.list()))

    if os_action == {'remove': 'remove'}:
        source_pkgs = _get_source_packages(parsed_head)
        remove_parameters = SourceParameters(sources=source_pkgs)
        os_source_manager.remove(remove_parameters)
        return Result(status=200, message="SUCCESS")

    return Result(status=400, message="unknown os source command")


def _handle_app_source_command(parsed_head: XmlHandler, os_type: OsType, app_action: dict) -> Result:
    """
    Handle the application source commands.

    @param parsed_head: XmlHandler with command information
    @param os_type: os type
    @param app_action: The action to be performed
    @return Result
    """
    application_source_manager = create_application_source_manager(os_type)

    if app_action == {'list': ''}:
        return Result(status=200, message=json.dumps(application_source_manager.list()))

    if app_action == {'remove': 'remove'}:
        keyid = parsed_head.get_children('applicationSource/remove/gpg')['keyid']
        filename = parsed_head.get_children('applicationSource/remove/repo')['filename']
        application_source_manager.remove(
            ApplicationRemoveSourceParameters(file_name=filename, gpg_key_id=keyid))
        return Result(status=200, message="SUCCESS")

    return Result(status=400, message="unknown application source command")


def _get_source_packages(parsed_head: XmlHandler) -> list[str]:
    """
    Extract source packages from XML command.

    @param parsed_head: XmlHandler containing the remove source commands
    @return List of packages to remove
    """
    source_pkgs: list[str] = []
    for key, value in parsed_head.get_children_tuples('osSource/remove/repos'):
        if key == 'source_pkg':
            source_pkgs.append(value)
    return source_pkgs
