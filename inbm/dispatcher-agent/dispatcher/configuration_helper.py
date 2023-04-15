"""
    Central communication agent in the manageability framework responsible
    for issuing commands and signals to other tools/agents

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
import os

from typing import Tuple, Optional, Any

from inbm_common_lib.shell_runner import PseudoShellRunner
from inbm_common_lib.utility import get_canonical_representation_of_path
from inbm_common_lib.utility import canonicalize_uri
from inbm_common_lib.exceptions import UrlSecurityException
from inbm_common_lib.utility import validate_file_type
from inbm_lib.xmlhandler import XmlHandler, XmlException
from .constants import *
from .packagemanager.package_manager import get, verify_source, verify_signature, get_file_type
from .dispatcher_callbacks import DispatcherCallbacks
from .packagemanager.irepo import IRepo
from .dispatcher_exception import DispatcherException
from .packagemanager.local_repo import DirectoryRepo

logger = logging.getLogger(__name__)


class ConfigurationHelper:
    """Helps manage interaction with configuration-agent messages

    @param dispatcher_callbacks: DispatcherCallbacks object
    """

    def __init__(self, dispatcher_callbacks: DispatcherCallbacks) -> None:
        self._dispatcher_callbacks = dispatcher_callbacks
        self._repo: Optional[IRepo] = None

    def _is_tar_file(self, tar_file_name: str) -> bool:
        extension = tar_file_name.rsplit('.', 1)[-1]
        logger.debug(f"file extension: {extension}")
        return True if extension.lower() == 'tar' else False

    def _extract_files_from_tar(self, file_path: str) -> Optional[str]:
        file_path = get_canonical_representation_of_path(file_path)
        cmd = "tar -xvf " + file_path + " --no-same-owner -C " + \
            file_path[:-(len(file_path.split('/')[-1]) + 1)]
        logger.debug(f"untar command: {cmd}")
        conf_file = None
        try:
            (out, err, code) = PseudoShellRunner.run(cmd)
            if code == 0 and not err:
                for line in out.splitlines():
                    file_type = get_file_type(line)
                    if file_type == 'package':
                        conf_file = line
                    else:
                        raise DispatcherException(
                            f"Configuration File Load Error: Invalid File sent. error: {err}")
                return conf_file
            else:
                raise DispatcherException(
                    f"Configuration File Load Error: uncompress failed. error: {err}")
        except OSError as e:
            raise DispatcherException(
                f"Configuration File Load Aborted: File untar failed: error: {e}")

    def parse_url(self, parsed: XmlHandler) -> Optional[str]:
        """Parse url from configuration request

        @param parsed: parsed details from manifest
        @return: url if successful; otherwise None (local path used)
        """
        try:
            header = parsed.get_children('config/configtype/load')
            return header['fetch']
        except (XmlException, KeyError):
            return None

    def download_config(self, parsed: XmlHandler, repo: IRepo) -> Optional[str]:
        """Downloads configuration file to local repository

        @param parsed: parsed details from manifest
        @param repo: destination repo for download
        @return: configuration file
        """
        logger.debug("download_config(parsed=" + parsed.__repr__() + ")")
        self._repo = repo if repo else DirectoryRepo(CACHE)
        url = self.parse_url(parsed)
        if url is None:
            raise DispatcherException(
                "Configuration File Load Error: Unable to parse URL from manifest")
        try:
            canonical_url = canonicalize_uri(url)
            header = parsed.get_children('config/configtype/load')
            signature = header.get('signature')
            logger.debug(f"SIGN : {signature}")
            hash_algorithm = 384 if signature else None
        except (XmlException, UrlSecurityException) as err:
            raise DispatcherException(
                f"Configuration File Load Error: Manifest Data in Invalid format {err}")

        tar_file_name = canonical_url.value.split('/')[-1]
        is_tar_file = self._is_tar_file(tar_file_name)
        tar_file_path = os.path.join(self._repo.get_repo_path(), tar_file_name)
        source = url[:-(len(url.split('/')[-1]) + 1)]
        logger.debug(f"source: {source}")

        verify_source(source=source, dispatcher_callbacks=self._dispatcher_callbacks)
        self._dispatcher_callbacks.broker_core.telemetry('Source Verification check passed')
        self._dispatcher_callbacks.broker_core.telemetry(
            f'Fetching configuration file from {url}')
        result = get(canonical_url, repo, UMASK_CONFIGURATION_FILE)

        if result.status == 200:
            self._dispatcher_callbacks.broker_core.telemetry(
                'Configuration File Download Successful')
            try:
                logger.debug(
                    f'Validating the file type of the downloaded file... : {tar_file_path}')
                validate_file_type([tar_file_path])
            except TypeError:
                self._repo.delete(tar_file_name)
                raise DispatcherException('Configuration Load Aborted: Invalid file')
            if os.path.exists(OTA_PACKAGE_CERT_PATH):
                if signature:
                    try:
                        verify_signature(signature, tar_file_path,
                                         self._dispatcher_callbacks, hash_algorithm)
                    except DispatcherException as err:
                        self._repo.delete(tar_file_name)
                        raise DispatcherException(f'Configuration Load Aborted. {str(err)}')
                else:
                    self._repo.delete(tar_file_name)
                    raise DispatcherException('Configuration Load Aborted: Signature is required to '
                                              'proceed with the update.')
            else:
                self._dispatcher_callbacks.broker_core.telemetry(
                    'Proceeding without signature check on package.')
            if not is_tar_file:
                conf_file = tar_file_name
                return conf_file
            else:
                try:
                    return self._extract_files_from_tar(tar_file_path)
                except DispatcherException:
                    logger.error("No files found in the tar ball.")
                    raise
                finally:
                    self._repo.delete(tar_file_name)
        else:
            raise DispatcherException(f'Configuration File Fetch Failed: {result}')
