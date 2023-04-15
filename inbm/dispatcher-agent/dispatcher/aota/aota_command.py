"""
    Docker and Docker compose related functions used throughout the AOTA module

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import os
import time
from abc import ABC, abstractmethod
from typing import Any, Optional, Mapping

from inbm_common_lib.utility import canonicalize_uri
from inbm_common_lib.shell_runner import PseudoShellRunner
from inbm_lib.trtl import Trtl
from inbm_lib.constants import DOCKER_STATS

from dispatcher.common.result_constants import INSTALL_FAILURE, CODE_OK
from dispatcher.config_dbs import ConfigDbs
from dispatcher.constants import TELEMETRY_UPDATE_CHANNEL, UMASK_OTA
from dispatcher.dispatcher_callbacks import DispatcherCallbacks
from dispatcher.packageinstaller.package_installer import TrtlContainer
from dispatcher.packagemanager.local_repo import DirectoryRepo
from dispatcher.packagemanager.package_manager import get
from .aota_error import AotaError

from .checker import check_url, check_docker_parameters, check_no_username_password_on_http, \
    check_compose_command_supported, check_docker_command_supported, check_resource
from .cleaner import cleanup_repo, remove_directory, remove_old_images, cleanup_docker_compose_instance
from .constants import DOCKER_COMPOSE_CACHE, REPOSITORY_TOOL_CACHE, DOCKER
from ..common import uri_utilities

logger = logging.getLogger(__name__)


def _get_parsed_values(value: str) -> Optional[str]:
    return None if value == "None" else value


class AotaCommand(ABC):
    """Base class to all the AOTA apps(docker,compose,application)

    @param dispatcher_callbacks callback to the main Dispatcher object
    @param parsed_manifest: parameters from OTA manifest
    @param dbs: Config.dbs value
    """

    def __init__(self,
                 dispatcher_callbacks: DispatcherCallbacks,
                 parsed_manifest: Mapping[str, Optional[Any]],
                 dbs: ConfigDbs) -> None:
        # security assumption: parsed_manifest is already validated

        self._dispatcher_callbacks = dispatcher_callbacks
        if 'container_tag' in parsed_manifest and parsed_manifest['container_tag'] is not None:
            self._container_tag = _get_parsed_values(parsed_manifest['container_tag'])
        else:
            self._container_tag = None
        self._uri: Optional[str] = parsed_manifest['uri']
        self._dockerComposeFile: Optional[str] = parsed_manifest['file']
        self._cmd = parsed_manifest['cmd']
        self._version = parsed_manifest['version']
        self._app_type = parsed_manifest['app_type']
        self._username = parsed_manifest['username']
        self._password = parsed_manifest['password']
        if 'docker_registry' in parsed_manifest and parsed_manifest['docker_registry'] is not None:
            self._docker_registry = _get_parsed_values(parsed_manifest['docker_registry'])
        else:
            self._docker_registry = None
        self._docker_username = parsed_manifest['docker_username']
        self._docker_password = parsed_manifest['docker_password']
        self._device_reboot = parsed_manifest['device_reboot']
        self.repo_to_clean_up: Optional[DirectoryRepo] = None

        self._dbs = dbs
        logger.debug(f"Config.dbs: {self._dbs}")
        self._parsed_manifest = parsed_manifest

        # Resource to be installed
        self.resource: Optional[str] = None
        if self._uri:
            self.resource = self._uri.split('/')[-1]

        if self._dockerComposeFile and not self._dockerComposeFile.endswith(".yml"):
            logger.error("Invalid compose YAML file extension")

        self._trtl = Trtl(PseudoShellRunner(), self._app_type, parsed_manifest['config_params'])

    @abstractmethod
    def verify_command(self, cmd: str) -> None:  # pragma: no cover
        pass

    @abstractmethod
    def cleanup(self) -> None:  # pragma: no cover
        pass

    @staticmethod
    def create_repository_cache_repo() -> DirectoryRepo:
        """Creates a directory to download packages

        @return: path to download package
        @raise: AotaError on failure to create a repo
        """
        shell = PseudoShellRunner()
        dir_name = time.time()
        out, err, code = shell.run(
            "mkdir " + os.path.join(REPOSITORY_TOOL_CACHE, "aota" + str(dir_name)))
        if err:
            raise AotaError(f'{err}. {INSTALL_FAILURE.message}')
        return DirectoryRepo(os.path.join(REPOSITORY_TOOL_CACHE, "aota" + str(dir_name)))

    def remove(self) -> None:
        """This method removes all images either containers or docker-compose specific  images
        Sets the result variable to failure or success based on the TRTL command result

        @raise: AotaError when container_tag is missing
        """
        if self._container_tag is None:
            raise AotaError("missing container tag.")

        self.down()

        logger.debug(
            "Remove all images with the container_tag {}".format(
                self._container_tag))
        (result, message, code) = self._trtl.image_remove_all(
            self._container_tag, True)

        if code != 0:
            raise AotaError(message)

        if self._container_tag != '':
            cleanup_docker_compose_instance(self._container_tag)

    def down(self) -> None:
        """This method stops all containers
        Sets the result variable to failure or success based on the TRTL command result

        @raise: AotaError when container_tag is missing
        """
        logger.debug("Docker-Compose/Docker container down")

        if self._container_tag is None:
            raise AotaError("missing container tag.")

        if self._app_type == DOCKER:
            (result, message, code) = self._trtl.stop_all(self._container_tag)
        else:
            (result, message, code) = self._trtl.down(self._container_tag, self._dockerComposeFile)
        if code != 0:
            raise AotaError(message)

    def docker_login(self) -> None:
        """Performs docker login to a private docker registry images with credentials
        Sets the result variable to failure or success based on the TRTL command result

        @raise: AotaError when docker login fails
        """
        logger.debug("docker-private registry login")
        if self._docker_registry is None:
            raise AotaError("Docker Registry is required for Docker Login.")
        if self._docker_username is None:
            raise AotaError("Docker Username is required for Docker Login.")
        if self._docker_password is None:
            raise AotaError("Docker Password is required for Docker Login.")
        (out, err, code) = self._trtl.login(
            self._docker_registry, self._docker_username, self._docker_password)
        logger.debug(f'Docker Login Result: {code} {err}')  # type: ignore

        if code != 0:
            raise AotaError(f'Docker Login Failed {err}')  # type: ignore


class Docker(AotaCommand):
    """Performs Docker operations based on the cmd triggered via AOTA

    @param dispatcher_callbacks callback to the main Dispatcher object
    @param parsed_manifest: parameters from OTA manifest
    @param dbs: Config.dbs value
    """

    def __init__(self, dispatcher_callbacks: DispatcherCallbacks, parsed_manifest: Mapping[str, Optional[Any]], dbs: ConfigDbs) -> None:
        # security assumption: parsed_manifest is already validated
        super().__init__(dispatcher_callbacks, parsed_manifest, dbs)

    def verify_command(self, cmd: str) -> None:
        check_docker_command_supported(cmd)

    def cleanup(self) -> None:
        if self._cmd != 'list':
            if self.repo_to_clean_up is not None and self.resource is not None:
                cleanup_repo(self.repo_to_clean_up, self.resource)
                remove_directory(self.repo_to_clean_up)
            if self._container_tag is not None and self._cmd != 'pull' and self._cmd != 'remove':
                remove_old_images(self._trtl, self._container_tag)

    def list(self) -> None:
        """List all non-exited containers for all images stored on the system."""
        logger.debug(f"Docker List command: container_tag->{self._container_tag}")
        err, output = self._trtl.list(self._container_tag)
        if err is None:
            self._dispatcher_callbacks.broker_core.telemetry(str(output))
        else:
            raise AotaError(f'Docker List Failed {err}')

    def stats(self) -> None:
        """Displays info of running containers
        @raise: AotaError on failure
        """
        logger.debug("Docker Stats command")
        running_container_stats = self._trtl.stats()
        logger.debug(f'docker stats: {running_container_stats}')

        container_cpu_stats = DOCKER_STATS + ":" + str(running_container_stats)
        self._dispatcher_callbacks.broker_core.telemetry(container_cpu_stats)

    def remove(self) -> None:
        super().remove()

    def pull(self) -> None:
        """Pulls images from any public or private docker registries
        Successfully pulls an image on success
        @raise: AotaError on failure
        """
        if self._container_tag is None:
            raise AotaError("missing container tag.")

        check_docker_parameters(self._docker_registry,
                                self._docker_username, self._docker_password)

        if self._docker_username is not None:
            if self._docker_registry is None:
                raise AotaError("Docker Registry required when username is provided.")
            if self._docker_password is None:
                raise AotaError("Docker password required when username is provided.")
            out, err, code = self._trtl.image_pull_private(self._container_tag, self._docker_registry,
                                                           self._docker_username, self._docker_password)
        else:
            out, err, code = self._trtl.image_pull_public(
                self._container_tag, self._docker_registry)

        if code != 0:
            raise AotaError(f'{err}')

    def load(self) -> None:
        """This method loads an image from the tar ball specified
        Sets the result variable to failure or success based on the TRTL command result

        @raise: AotaError on failure
        """
        logger.debug("Installing package by Docker load.")

        if self._container_tag is None:
            raise AotaError("missing container tag.")
        if self._uri is None:
            raise AotaError("Fetch URI is required for Docker Load command.")

        check_resource(self.resource, self._uri, self._dispatcher_callbacks)

        if self.resource:
            ext = self.resource[-4:]
            if ext != '.tgz' and ext != '.tar':
                raise AotaError('Invalid package type; should be .tar or .tgz')

        self._dispatcher_callbacks.broker_core.telemetry(
            'OTA Trigger Install command invoked for package: {}'.format(
                self._uri))
        # Fetch resource
        repository_cache_repo = AotaCommand.create_repository_cache_repo()
        self.repo_to_clean_up = repository_cache_repo
        result = get(url=canonicalize_uri(self._uri), repo=repository_cache_repo, umask=UMASK_OTA)
        self._dispatcher_callbacks.broker_core.telemetry(
            f'Package: {self._uri} Fetch Result: {result}')

        if result.status != CODE_OK:
            raise AotaError(result.message)

        container = TrtlContainer(
            self._trtl,
            self._container_tag,
            self._dispatcher_callbacks,
            self._dbs)

        result = container.image_load(
            os.path.join(repository_cache_repo.get_repo_path(), uri_utilities.uri_to_filename(self._uri)))
        if result.status != CODE_OK:
            raise AotaError(result.message)

    def import_image(self) -> None:
        """This method Imports the contents from a tarball to create a filesystem image
        Sets the result variable to failure or success based on the TRTL command result

        @raise: AotaError on failure
        """
        logger.debug("Installing package by import.")
        if self._container_tag is None:
            raise AotaError("missing container tag.")
        if self._uri is None:
            raise AotaError("Fetch URI is required for Docker Import command.")

        check_resource(self.resource, self._uri, self._dispatcher_callbacks)

        container = TrtlContainer(
            self._trtl,
            self._container_tag,
            self._dispatcher_callbacks,
            self._dbs)

        result = container.image_import(self._uri)

        if result.status != CODE_OK:
            logger.debug(f"Result: {result}")
            if self.repo_to_clean_up is not None and self.resource is not None:
                cleanup_repo(self.repo_to_clean_up, self.resource)
            raise AotaError(result.message)


class DockerCompose(AotaCommand):
    """Performs Docker Compose operations based on the cmd triggered via AOTA

    @param dispatcher_callbacks callback to the main Dispatcher object
    @param parsed_manifest: parameters from OTA manifest
    @param dbs: Config.dbs value
    """

    def __init__(self, dispatcher_callbacks: DispatcherCallbacks, parsed_manifest: Mapping[str, Optional[Any]], dbs: ConfigDbs) -> None:
        # security assumption: parsed_manifest is already validated
        super().__init__(dispatcher_callbacks, parsed_manifest, dbs)

    def verify_command(self, cmd: str) -> None:
        check_compose_command_supported(cmd)

    def cleanup(self) -> None:
        if self._cmd != 'down':
            if self.repo_to_clean_up is not None and self.resource is not None:
                cleanup_repo(self.repo_to_clean_up, self.resource)
            if self._container_tag:
                remove_old_images(self._trtl, self._container_tag)

    def up(self) -> None:
        """This method is used to define and run multi-app Docker applications.
        Sets the result variable to failure or success based on the TRTL command result

        @raise: AotaError on failure
        """
        logger.debug("docker-compose up")
        if not self._container_tag:
            raise AotaError("missing container tag.")
        if self._uri is None:
            raise AotaError("fetch URI is required.")

        check_resource(self.resource, self._uri, self._dispatcher_callbacks)

        if self._docker_registry and self._docker_username and self._docker_password:
            self.docker_login()

        self._dispatcher_callbacks.broker_core.telemetry(
            f'OTA Trigger Install command invoked for package: {self._uri}')
        docker_compose_repo = DirectoryRepo(DOCKER_COMPOSE_CACHE)
        self.repo_to_clean_up = docker_compose_repo
        get_result = get(url=canonicalize_uri(self._uri),
                         repo=docker_compose_repo,
                         umask=UMASK_OTA,
                         username=self._username,
                         password=self._password)
        self._dispatcher_callbacks.broker_core.telemetry(
            f'Package: {self._uri} Fetch Result: {get_result}')
        if get_result.status != CODE_OK:
            raise AotaError("Unable to download docker-compose container.")
        (result, message, code) = self._trtl.up(self._container_tag, self._dockerComposeFile)
        if code != 0:
            raise AotaError(message)

    def remove(self) -> None:
        super().remove()

    def down(self) -> None:
        """This method stops all containers that were created by Docker-Compose Up
        Sets the result variable to failure or success based on the TRTL command result

        @raise: AotaError when container_tag is missing
        """
        super().down()

    def pull(self) -> None:
        """This method is used to pull the latest changes of the images mentioned in the
        docker-compose files.
        Sets the result variable to failure or success based on the TRTL command result

        @raise: AotaError on failure
        """
        logger.debug("docker-compose pull")
        if self._container_tag is None:
            raise AotaError("missing container tag.")
        if self._uri is None:
            raise AotaError("fetch URI is required.")

        check_docker_parameters(self._docker_registry,
                                self._docker_username, self._docker_password)
        check_url(self._uri)
        check_no_username_password_on_http(self._username, self._password, self._uri)

        if self._docker_registry and self._docker_username and self._docker_password:
            self.docker_login()

        self._download()

        out, err, code = self._trtl.image_pull_public(
            self._container_tag, self._docker_registry, self._dockerComposeFile)

        if self._container_tag != '':
            cleanup_docker_compose_instance(self._container_tag)
        if code != 0:
            raise AotaError(f'{err}')

    def _download(self) -> None:
        """This method is used to download a package
        Sets the result variable to failure or success based on the TRTL command result

        @raises: AotaError
        """
        logger.debug("AOTA to download a package")

        if self._uri is None:
            raise AotaError("Fetch URI is required.")

        self._dispatcher_callbacks.broker_core.telemetry(
            'OTA Trigger Install command invoked for package: {}'.format(
                self._uri))
        docker_compose_repo = DirectoryRepo(DOCKER_COMPOSE_CACHE)
        self.repo_to_clean_up = docker_compose_repo
        get_result = get(url=canonicalize_uri(self._uri),
                         repo=docker_compose_repo,
                         umask=UMASK_OTA,
                         username=self._username,
                         password=self._password)
        self._dispatcher_callbacks.broker_core.telemetry(
            f'Package: {self._uri} Fetch Result: {get_result}')

        if get_result.status != CODE_OK:
            raise AotaError('Unable to download docker-compose container.')

    def list(self):
        """This method list the containers
        Sets the result variable to failure or success based on the TRTL command result

        @raise: AotaError on failure
        """
        logger.debug("AOTA docker-compose list ")

        if self._container_tag is None:
            raise AotaError("missing container tag.")

        (code, message) = self._trtl.list(self._container_tag)

        if code is None:
            self._dispatcher_callbacks.broker_core.telemetry("Container List: " + message)
        else:
            raise AotaError(message)
