"""
    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from dataclasses import asdict
import logging
import json
from dispatcher.common.result_constants import Result
from dispatcher.source.constants import (
    ApplicationAddSourceParameters,
    ApplicationRemoveSourceParameters,
    ApplicationUpdateSourceParameters,
    OsType,
    SourceParameters,
)

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
        os_action = parsed_head.get_children("osSource")
        if os_action:
            return _handle_os_source_command(parsed_head, os_type, os_action)
    except XmlException:
        pass  # If we get an XmlException here we still want to try applicationSource

    try:
        app_action = parsed_head.get_children("applicationSource")
        if app_action:
            return _handle_app_source_command(parsed_head, os_type, app_action)
    except XmlException as e:
        return Result(status=400, message=f"unable to handle source command XML: {e}")

    return Result(status=400, message="unknown source command")


def _handle_os_source_command(parsed_head: XmlHandler, os_type: OsType, os_action: dict) -> Result:
    """
    Handle the os source commands.

    @param parsed_head: XmlHandler with command information
    @param os_type: OS type
    @param os_action: The action to be performed
    @return Result
    """
    os_source_manager = create_os_source_manager(os_type)

    if "list" in os_action:
        return Result(status=200, message=json.dumps(os_source_manager.list()))

    if "remove" in os_action:
        remove_source_pkgs: list[str] = []
        for key, value in parsed_head.get_children_tuples("osSource/remove/repos"):
            if key == "source_pkg":
                remove_source_pkgs.append(value)
        remove_parameters = SourceParameters(sources=remove_source_pkgs)
        os_source_manager.remove(remove_parameters)
        return Result(status=200, message="SUCCESS")

    if "add" in os_action:
        add_source_pkgs: list[str] = []
        for key, value in parsed_head.get_children_tuples("osSource/add/repos"):
            if key == "source_pkg":
                add_source_pkgs.append(value)
        add_parameters = SourceParameters(sources=add_source_pkgs)
        os_source_manager.add(add_parameters)
        return Result(status=200, message="SUCCESS")

    if "update" in os_action:
        update_source_pkgs: list[str] = []
        for key, value in parsed_head.get_children_tuples("osSource/update/repos"):
            if key == "source_pkg":
                update_source_pkgs.append(value)
        update_parameters = SourceParameters(sources=update_source_pkgs)
        os_source_manager.update(update_parameters)
        return Result(status=200, message="SUCCESS")

    return Result(status=400, message="unknown os source command")


def _handle_app_source_command(
        parsed_head: XmlHandler, os_type: OsType, app_action: dict) -> Result:
    """
    Handle the application source commands.

    @param parsed_head: XmlHandler with command information
    @param os_type: os type
    @param app_action: The action to be performed
    @return Result
    """
    application_source_manager = create_application_source_manager(os_type)

    if "list" in app_action:
        serialized_list = json.dumps(
            [asdict(app_source) for app_source in application_source_manager.list()]
        )
        return Result(status=200, message=serialized_list)

    if "remove" in app_action:
        keyname = parsed_head.get_children("applicationSource/remove/gpg")["keyname"]
        filename = parsed_head.get_children("applicationSource/remove/repo")["filename"]
        application_source_manager.remove(
            ApplicationRemoveSourceParameters(file_name=filename, gpg_key_name=keyname)
        )
        return Result(status=200, message="SUCCESS")

    if "add" in app_action:
        gpg_key_uri = None
        gpg_key_name = None

        try:
            gpg_key_uri = parsed_head.get_children("applicationSource/add/gpg")["uri"]
            gpg_key_name = parsed_head.get_children("applicationSource/add/gpg")["keyname"]
        except XmlException:
            # These children may not be present
            logger.info(f"Optional GPG key parameters not present in manifest")

        repo_filename = parsed_head.get_children("applicationSource/add/repo")["filename"]

        add_source_pkgs: list[str] = []
        for key, value in parsed_head.get_children_tuples("applicationSource/add/repo/repos"):
            if key == "source_pkg":
                add_source_pkgs.append(value)

        application_source_manager.add(
            ApplicationAddSourceParameters(
                file_name=repo_filename,
                gpg_key_name=gpg_key_name,
                gpg_key_uri=gpg_key_uri,
                sources=add_source_pkgs,
            )
        )
        return Result(status=200, message="SUCCESS")

    if "update" in app_action:
        repo_filename = parsed_head.get_children("applicationSource/update/repo")["filename"]
        update_source_pkgs: list[str] = []
        for key, value in parsed_head.get_children_tuples("applicationSource/update/repo/repos"):
            if key == "source_pkg":
                update_source_pkgs.append(value)

        application_source_manager.update(
            ApplicationUpdateSourceParameters(
                file_name=repo_filename,
                sources=update_source_pkgs,
            )
        )
        return Result(status=200, message="SUCCESS")

    return Result(status=400, message="unknown application source command")
