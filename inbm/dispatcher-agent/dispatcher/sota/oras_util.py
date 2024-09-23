"""
    ORAS tool will be called by dispatcher to perform the image downloading in TiberOS.

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
import os
import requests
import json
from urllib.parse import urlsplit, urlparse
from typing import Optional, Tuple
from dispatcher.dispatcher_exception import DispatcherException
from inbm_common_lib.shell_runner import PseudoShellRunner
from inbm_common_lib.utility import CanonicalUri
from dispatcher.packagemanager.package_manager import verify_source
from ..packagemanager.irepo import IRepo
from ..dispatcher_broker import DispatcherBroker
from .constants import ORAS_TOKEN_PATH
from .sota_error import SotaError

logger = logging.getLogger(__name__)


def oras_download(dispatcher_broker: DispatcherBroker, uri: CanonicalUri,
             repo: IRepo, username: Optional[str], password: str, umask: int) -> None:
    """Downloads files and places capsule file in path mentioned by manifest file.

    @param dispatcher_broker: DispatcherBroker object used to communicate with other INBM services
    @param uri: URI of the source location
    @param repo: repository for holding the download
    @param username: username to use for download
    @param password: password to use for download
    @param umask: file permission mask
    @raises DispatcherException: any exception
    """
    dispatcher_broker.telemetry(f'Package to be fetched from {uri.value}')
    dispatcher_broker.telemetry(
        'Checking authenticity of package by checking signature and source')

    if not isinstance(uri, CanonicalUri):
        raise DispatcherException("Internal error: uri improperly passed to download function")

    try:
        source, registry_server, image, image_tag, repository_name, image_full_path, registry_manifest = \
            parse_uri(uri)
    except IndexError as err:
        logger.error(f"IndexError occurs with uri {uri.value}: {err}")
        raise DispatcherException(err)

    logger.debug(f"source: {source}, "
                 f"registry_server: {registry_server}, "
                 f"image: {image}, "
                 f"image_tag: {image_tag}, "
                 f"repository_name: {repository_name}, "
                 f"image_full_path: {image_full_path}, "
                 f"registry_manifest: {registry_manifest}")

    verify_source(source=source, dispatcher_broker=dispatcher_broker)
    dispatcher_broker.telemetry('Source Verification check passed')

    enough_space = is_enough_space_to_download(
        registry_manifest, repo, password)

    if not enough_space:
        err_msg = " Insufficient free space available on " + repo.get_repo_path() + \
                  " for " + str(uri.value)
        raise DispatcherException(err_msg)

    if password:
        logger.debug("RS password provided.")
    else:
        err_msg = " No JWT token. Abort the update. "
        raise DispatcherException(err_msg)

    # Set password as environment variables for security reason.
    env = dict(os.environ)  # make a copy of the environment
    env["ORAS_PASSWORD"] = password

    msg = f'Fetching software package from {image_full_path}'
    dispatcher_broker.telemetry(msg)

    # Call oras to pull the image. The password is the JWT token.
    (out, err_run, code) = PseudoShellRunner().run(f"oras pull {image_full_path} -o {repo.get_repo_path()} "
                                                   f"--password $ORAS_PASSWORD", env=env)
    if code != 0:
        if err_run:
            raise DispatcherException("Error to download OTA files with ORAS: " + err_run + ". Code: " + str(code))
        else:
            raise DispatcherException("Error to download OTA files with ORAS. Code: " + str(code))
    else:
        dispatcher_broker.telemetry('OTA Download Successful.')


def is_enough_space_to_download(manifest_uri: str,
                                destination_repo: IRepo,
                                jwt_token: str) -> bool:
    """Checks if enough free space exists on platform to hold download.

    Calculates the file size from the OCI server and checks if required free space is available on
    the platform.
    @param manifest_uri: registry manifest uri
    @param destination_repo:  desired download destination
    @param jwt_token: jwt_token provided for access the release server
    """
    try:
        logger.debug(f"Checking OCI artifact size with manifest uri: {manifest_uri}")
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/vnd.oci.artifact.manifest.v1+json"
        }
        response = requests.get(manifest_uri, headers=headers)
        if response.status_code != 200:
            raise DispatcherException(f"Failed to get the response from {manifest_uri}.")
        data = json.loads(response.text)
        logger.debug(f"resp={data}")
        # Calculate the total size
        file_size = 0
        for layer in data['layers']:
            file_size += layer['size']
        logger.debug(f"Total file size: {file_size}")

    except (TypeError, KeyError, json.JSONDecodeError, DispatcherException) as err:
        err_msg = f"Error getting artifact size from {manifest_uri} using token={jwt_token} Error: {err}"
        logger.error(err_msg)
        raise DispatcherException(err_msg)

    if destination_repo.exists():
        get_free_space = destination_repo.get_free_space()
        free_space: int = int(get_free_space)
    else:
        raise DispatcherException("Repository does not exist : " +
                                  destination_repo.get_repo_path())

    logger.debug("get_free_space: " + repr(get_free_space))
    logger.debug("Free space available on destination_repo is " + repr(free_space))
    logger.debug("Free space needed on destination repo is " + repr(file_size))
    return True if free_space > file_size else False

def parse_uri(uri: CanonicalUri) -> Tuple[str, str, str, str, str, str, str]:
    """ Parse the uri.

    In case of uri.value = https://registry-rs.internal.ledgepark.intel.com/one-intel-edge/tiberos:latest
    source = https://registry-rs.internal.ledgepark.intel.com/one-intel-edge
    registry_server = registry-rs.internal.ledgepark.intel.com
    image = tiberos
    image_tag = latest
    image_full_path = registry-rs.internal.ledgepark.intel.com/one-intel-edge/tiberos:latest
    repository_name = one-intel-edge
    registry_manifest = https://registry-rs.internal.ledgepark.intel.com/v2/one-intel-edge/tiberos/manifest/latest

    @return: str representing source, registry_server, image, image_tag, image_full_path, repository_name and
             registry_manifest
    """
    source = uri.value[:-(len(uri.value.split('/')[-1]) + 1)]
    parsed_uri = urlparse(uri.value)
    registry_server = parsed_uri.netloc
    parsed_uri.geturl()
    path_parts = parsed_uri.path.strip('/').split('/')
    if len(path_parts) < 2:
        raise DispatcherException(f"Invalid URI format: {uri.value}")
    repository_name = '/'.join(path_parts[:-1])
    image = path_parts[-1].split(':')[0]
    image_tag = path_parts[-1].split(':')[1] if ':' in path_parts[-1] else 'latest'
    image_full_path = f"{registry_server}/{repository_name}/{image}:{image_tag}"
    registry_manifest = f"https://{registry_server}/v2/{repository_name}/{image}/manifests/{image_tag}"

    return source, registry_server, image, image_tag, repository_name, image_full_path, registry_manifest

def read_oras_token() -> str:
    """Read oras JWT token from a path configured by Tiber OS node-agent. The node agent will renew the token when
    the token is expired.

    @return: JWT token to access release server
    """
    token = None
    if os.path.exists(ORAS_TOKEN_PATH):
        with open(ORAS_TOKEN_PATH, 'r') as f:
            token = f.read().strip()
        return token
    else:
        msg = f"{ORAS_TOKEN_PATH} not exist."

    if token is None:
        msg = f"No JWT token found."

    logger.error(msg)
    raise SotaError(f"Error while performing TiberOS download: {msg}")