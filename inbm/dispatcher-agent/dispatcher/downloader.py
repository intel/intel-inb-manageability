"""
    OTA update tool which is called from the dispatcher during installation

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
import os.path
from typing import Optional
from urllib.parse import urlsplit

from dispatcher.dispatcher_exception import DispatcherException
from dispatcher.packagemanager.package_manager import get, verify_source, is_enough_space_to_download
from dispatcher.packagemanager.local_repo import DirectoryRepo
from inbm_common_lib.utility import validate_file_type, remove_file
from inbm_common_lib.utility import CanonicalUri
from .constants import CACHE
from .dispatcher_callbacks import DispatcherCallbacks
from .packagemanager.irepo import IRepo

logger = logging.getLogger(__name__)


def _check_if_valid_file(file_name: str, repo: IRepo):
    try:
        file_path = os.path.join(repo.get_repo_path(), file_name)
        logger.debug('Validating the file type of the downloaded file...')
        validate_file_type([file_path])
    except TypeError as error:
        remove_file(file_path)
        raise DispatcherException(f'OTA File downloaded is of unsupported file type: {error}')


def download(dispatcher_callbacks: DispatcherCallbacks, uri: CanonicalUri, repo: IRepo, username: Optional[str],
             password: Optional[str], umask: int) -> None:
    """Downloads files and places capsule file in path mentioned by manifest file.

    @param dispatcher_callbacks: callback to dispatcher
    @param uri: URI of the source location
    @param repo: repository for holding the download
    @param username: username to use for download
    @param password: password to use for download
    @param umask: file permission mask
    @raises DispatcherException: any exception
    """

    dispatcher_callbacks.broker_core.telemetry(f'Package to be fetched from {uri.value}')
    dispatcher_callbacks.broker_core.telemetry(
        'Checking authenticity of package by checking signature and source')

    if not isinstance(uri, CanonicalUri):
        raise DispatcherException("Internal error: uri improperly passed to download function")

    source = uri.value[:-(len(uri.value.split('/')[-1]) + 1)]
    file_name = os.path.basename(urlsplit(uri.value).path)
    logger.debug(f"source: {source}, filename: {file_name}")

    verify_source(source=source, dispatcher_callbacks=dispatcher_callbacks)
    dispatcher_callbacks.broker_core.telemetry('Source Verification check passed')
    if username and password and uri.value.startswith("http://"):
        raise DispatcherException(
            'Bad request: username/password will not be processed on HTTP server')

    try:
        enough_space = is_enough_space_to_download(
            uri, DirectoryRepo(str(CACHE)), username, password)
    except DispatcherException as e:
        raise DispatcherException(e)

    if not enough_space:
        err_msg = " Insufficient free space available on " + repo.get_repo_path() + \
                  " for " + str(uri)
        raise DispatcherException(err_msg)

    msg = f'Fetching software package from {uri}'
    dispatcher_callbacks.broker_core.telemetry(msg)

    if uri.value.startswith("http://"):
        info_msg = "The file requested from repo is being downloaded over an insecure(non-TLS) session..."
        logger.info(info_msg)
        dispatcher_callbacks.broker_core.telemetry(info_msg)
    result = get(url=uri, repo=repo, umask=umask, username=username, password=password)
    if result.status == 200:
        dispatcher_callbacks.broker_core.telemetry('OTA Download Successful')
        _check_if_valid_file(file_name, repo)
    else:
        raise DispatcherException(f'OTA Fetch Failed: {result}')
