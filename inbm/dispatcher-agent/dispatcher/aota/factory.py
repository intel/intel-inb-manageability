"""
    AOTA Application Factory

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from ast import parse
from typing import Optional, Any, Mapping

from dispatcher.dispatcher_callbacks import DispatcherCallbacks
from dispatcher.config_dbs import ConfigDbs

from inbm_lib.detect_os import detect_os, LinuxDistType, is_inside_container

from .constants import DOCKER, COMPOSE, APPLICATION
from .application_command import Application, CentOsApplication, UbuntuApplication
from .aota_command import AotaCommand, AotaError, DockerCompose, Docker


def get_app_instance(app_type: str, dispatcher_callbacks: DispatcherCallbacks,
                     parsed_manifest: Mapping[str, Optional[Any]],
                     dbs: ConfigDbs) -> AotaCommand:
    # security assumption: parsed_manifest is already validated
    if app_type == COMPOSE:
        return DockerCompose(dispatcher_callbacks, parsed_manifest, dbs)
    if app_type == APPLICATION:
        return get_app_os(dispatcher_callbacks, parsed_manifest, dbs)
    if app_type == DOCKER:
        return Docker(dispatcher_callbacks, parsed_manifest, dbs)
    raise AotaError(f"Invalid application type: {app_type}")


def get_app_os(dispatcher_callbacks: DispatcherCallbacks, parsed_manifest: Mapping[str, Optional[Any]],
               dbs: ConfigDbs) -> Application:
    """Factory method to get the concrete Application based on OS"""
    our_os = detect_os()
    if our_os == LinuxDistType.Ubuntu.name:
        return UbuntuApplication(dispatcher_callbacks, parsed_manifest, dbs)
    elif our_os == LinuxDistType.CentOS.name and is_inside_container:
        return CentOsApplication(dispatcher_callbacks, parsed_manifest, dbs)
    else:
        raise AotaError(f'Application commands are unsupported on the OS: {detect_os()}')
