"""
    Tiber Util module will be called by dispatcher to perform the image downloading in TiberOS.

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
import os
import requests
from requests import HTTPError
from requests.exceptions import ProxyError, ChunkedEncodingError, ContentDecodingError, ConnectionError

import shlex
from urllib.parse import urlsplit
from typing import Optional, Any
from inbm_common_lib.utility import CanonicalUri
from dispatcher.packagemanager.package_manager import verify_source
from ..packagemanager.irepo import IRepo
from ..dispatcher_broker import DispatcherBroker
from .constants import RELEASE_SERVER_TOKEN_PATH
from .sota_error import SotaError

logger = logging.getLogger(__name__)


def tiber_download(dispatcher_broker: DispatcherBroker, uri: CanonicalUri,
                   repo: IRepo, username: Optional[str], token: str, umask: int) -> None:
    """Downloads files and places capsule file in path mentioned by manifest file.

    @param dispatcher_broker: DispatcherBroker object used to communicate with other INBM services
    @param uri: URI of the source location
    @param repo: repository for holding the download
    @param username: username to use for download
    @param token: token to use for download
    @param umask: file permission mask
    @raises SotaError: any exception
    """
    dispatcher_broker.telemetry(f'Package to be fetched from {uri.value}')
    dispatcher_broker.telemetry(
        'Checking authenticity of package by checking signature and source')

    if not isinstance(uri, CanonicalUri):
        raise SotaError("Internal error: uri improperly passed to download function")

    source = uri.value[:-(len(uri.value.split('/')[-1]) + 1)]
    file_name = os.path.basename(urlsplit(uri.value).path)
    logger.debug(f"source: {source}, filename: {file_name}")

    verify_source(source=source, dispatcher_broker=dispatcher_broker)
    dispatcher_broker.telemetry('Source Verification check passed')

    if token:
        logger.debug("RS token provided.")
    else:
        err_msg = " No JWT token. Abort the update. "
        raise SotaError(err_msg)

    # Specify the token in header.
    headers = {
        "Authorization": f"Bearer {token}"
    }

    enough_space = is_enough_space_to_download(uri.value, repo, headers)

    if not enough_space:
        err_msg = " Insufficient free space available on " + shlex.quote(repo.get_repo_path()) + \
                  " for " + str(uri.value)
        raise SotaError(err_msg)

    msg = f'Fetching software package from {uri.value}'
    dispatcher_broker.telemetry(msg)

    if uri.value.startswith("http://"):
        info_msg = "The file requested from repo is being downloaded over an insecure(non-TLS) session..."
        logger.info(info_msg)
        dispatcher_broker.telemetry(info_msg)

    try:
        with requests.get(url=uri.value, headers=headers) as response:
            repo.add(filename=file_name, contents=response.content)
    except (HTTPError, OSError) as err:
        raise SotaError(f'OTA Fetch Failed: {err}')

    dispatcher_broker.telemetry('OTA Download Successful')


def is_enough_space_to_download(manifest_uri: str,
                                destination_repo: IRepo,
                                headers: Any) -> bool:
    """Checks if enough free space exists on platform to hold download.

    Calculates the file size from the OCI server and checks if required free space is available on
    the platform.
    @param manifest_uri: registry manifest uri
    @param destination_repo:  desired download destination
    @param headers: headers that contains jwt_token to access the release server
    """
    try:
        logger.debug(f"Checking file size with manifest uri: {manifest_uri}")

        with requests.get(url=manifest_uri, headers=headers) as response:
            response.raise_for_status()
            # Read Content-Length header
            try:
                content_length = int(response.headers.get("Content-Length", "0"))
            except ValueError:
                content_length = 0

            if content_length == 0:
                # Stream file to measure the file size
                for chunk in response.iter_content(chunk_size=16384):
                    if chunk:
                        content_length += len(chunk)

    except HTTPError as e:
        if e.response:
            status_code = e.response.status_code
        else:
            status_code = 0
        raise SotaError('Failed to access URI:' 'Status code for ' + manifest_uri +
                        ' is ' + str(status_code) + ". Invalid URI or Token might be expired.")
    except (ProxyError, ChunkedEncodingError, ContentDecodingError, ConnectionError) as e:
        raise SotaError(str(e))

    logger.debug("File size: " + repr(content_length))
    file_size: int = int(content_length)
    if destination_repo.exists():
        get_free_space = destination_repo.get_free_space()
        free_space: int = int(get_free_space)
    else:
        raise SotaError("Repository does not exist : " +
                        shlex.quote(destination_repo.get_repo_path()))

    logger.debug("get_free_space: " + repr(get_free_space))
    logger.debug("Free space available on destination_repo is " + repr(free_space))
    logger.debug("Free space needed on destination repo is " + repr(file_size))
    return True if free_space > file_size else False


def read_release_server_token(token_path: str = RELEASE_SERVER_TOKEN_PATH) -> str:
    """Read release server JWT token from a path configured by Tiber OS node-agent. The node agent will renew
    the token when the token is expired.

    @return: JWT token to access release server
    """
    token = None
    try:
        if os.path.exists(token_path):
            with open(token_path, 'r') as f:
                token = f.read().strip()
            return token
        else:
            msg = f"{token_path} not exist."
    except OSError as err:
        raise SotaError(f"Error while performing TiberOS download: {err}")

    if token is None:
        msg = f"No JWT token found."

    logger.error(msg)
    raise SotaError(f"Error while performing TiberOS download: {msg}")
