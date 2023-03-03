"""
    Performs checks during the application over the air update (AOTA)

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
from pathlib import Path

from typing import Optional
from urllib.parse import urlparse

from dispatcher.dispatcher_exception import DispatcherException
from dispatcher.dispatcher_callbacks import DispatcherCallbacks
from dispatcher.packagemanager.package_manager import verify_source
from .constants import DockerCommands, ComposeCommands, ApplicationCommands
from .aota_error import AotaError
from ..common import uri_utilities

logger = logging.getLogger(__name__)


def check_url(url: Optional[str]) -> None:
    """Checks that container tag provided.

    @param url: URL used to retrieve package
    @raise AotaError if url is None
    """
    if url is None:
        raise AotaError("missing URL.")


def check_resource(resource: Optional[str], uri: Optional[str], dispatcher_callbacks: DispatcherCallbacks) -> None:
    if resource is None or resource == '':
        raise AotaError('Invalid resource URL.')

    if not uri:
        raise AotaError('No URI provided when required')

    try:
        if is_local_file(uri):
            verify_source(source=uri, dispatcher_callbacks=dispatcher_callbacks, source_file=True)
        else:
            source = uri_utilities.get_uri_prefix(uri)
            verify_source(source=source, dispatcher_callbacks=dispatcher_callbacks)
    except DispatcherException as err:
        dispatcher_callbacks.broker_core.telemetry(str(err))
        raise AotaError('Source verification check failed')


def check_no_username_password_on_http(username: Optional[str], password: Optional[str], uri: str) -> None:
    """Raise AotaError if trying to access http with username or password"""
    if (username or password) and uri.startswith("http://"):
        raise AotaError('Bad request: username/password will not be processed on HTTP server')


def check_compose_command_supported(cmd: str) -> None:
    """Checks that Docker Compose command is supported

    @param cmd: Docker compose command
    @raise AotaError
    """
    if cmd not in ComposeCommands.__members__:
        raise AotaError(f"Unsupported Docker Compose command: {cmd}")


def check_docker_command_supported(cmd: str) -> None:
    """Checks that Docker command is supported

    @param cmd: Docker command
    @raise AotaError
    """
    if cmd not in DockerCommands.__members__:
        raise AotaError(f"Unsupported Docker command: {cmd}")


def check_application_command_supported(cmd: str) -> None:
    """Checks that Application command is supported

    @param cmd: Application command
    @raise AotaError
    """
    if cmd not in ApplicationCommands.__members__:
        raise AotaError(f"Unsupported Application command: {cmd}")


def is_local_file(uri: str) -> bool:
    """Checks if the URI or filename points out to url or filesystem path

    @return: returns True if filesystem path else False
    """
    if Path(uri).exists():
        return True
    elif urlparse(uri).scheme == "file":
        return True
    else:
        return False


def check_docker_parameters(docker_registry: Optional[str], docker_username: Optional[str],
                            docker_password: Optional[str]) -> None:
    """Perform some checks on docker parameters

    * docker username and password => must have docker_registry
    * docker_registry => must have docker username and password
    * docker_registry, docker_username => must not have spaces in docker_username or docker_registry

    @raise: AotaError if username or password is missing.
    """
    if docker_username and docker_password and (docker_registry is None):
        raise AotaError("Missing Docker private registry URL in Manifest")

    if docker_registry:
        if docker_username and (docker_password is None):
            raise AotaError("Missing docker password in Manifest")

        if (docker_username is None) and docker_password:
            raise AotaError('Missing docker username in Manifest')

        if docker_username:
            if docker_username.find(' ') != -1 or docker_registry.find(' ') != -1:
                raise AotaError("No spaces allowed in Docker Username/Registry")
