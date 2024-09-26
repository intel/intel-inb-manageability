"""
    SOTA to perform download during an update and is called from the dispatcher

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import os
import hashlib
from abc import abstractmethod
import logging
from datetime import datetime

from typing import Optional
from .mender_util import read_current_mender_version
from .sota_error import SotaError
from .oras_util import oras_download, read_oras_token
from ..constants import UMASK_OTA
from ..downloader import download
from ..packagemanager.irepo import IRepo
from ..dispatcher_broker import DispatcherBroker
from inbm_common_lib.utility import CanonicalUri


logger = logging.getLogger(__name__)


class Downloader:
    """Abstract class to download SOTA update/upgrade"""

    def __init__(self) -> None:
        pass

    def download(self,
                 dispatcher_broker: DispatcherBroker,
                 uri: Optional[CanonicalUri],
                 repo: IRepo,
                 username: Optional[str],
                 password: Optional[str],
                 release_date: Optional[str]) -> None:
        """Downloads update/upgrade and places capsule file in local cache.

        @param dispatcher_broker: DispatcherBroker object used to communicate with other INBM services
        @param uri: URI of the source location
        @param repo: repository for holding the download
        @param username: username to use for download
        @param password: password to use for download
        @param release_date: manifest release date
        """
        logger.debug("")

    def is_valid_release_date(self, release_date: Optional[str]) -> bool:
        """Check if manifest release date is higher than mender release date

        @param release_date: manifest release date
        @return True if condition satisfies; otherwise False
        """

        if release_date is None:
            raise SotaError('Missing manifest Release date field')

        manifest_release_date = datetime.strptime(release_date, "%Y-%m-%d")
        try:
            content = read_current_mender_version()
            platform_mender_date_str = content.strip('Release-').strip()
            platform_mender_date = datetime.strptime(platform_mender_date_str, "%Y%m%d%H%M%S")
        except (ValueError, FileNotFoundError) as err:
            raise SotaError(err)
        logger.debug(f"System mender release date: {platform_mender_date}")
        return True if manifest_release_date > platform_mender_date else False

    @abstractmethod
    def check_release_date(self, release_date: Optional[str]) -> bool:
        pass


class DebianBasedDownloader(Downloader):
    """DebianBasedDownloader class, child of Downloader"""

    def __init__(self) -> None:
        super().__init__()

    def download(self,
                 dispatcher_broker: DispatcherBroker,
                 uri: Optional[CanonicalUri],
                 repo: IRepo,
                 username: Optional[str],
                 password: Optional[str],
                 release_date: Optional[str]) -> None:
        """downloads Debian-based update"""

        logger.debug("Debian-based OS does not require a file download to "
                     "perform a software update")

    def check_release_date(self, release_date: Optional[str]) -> bool:
        """
        @return True always as ubuntu doesn't need to check release date
        """
        return True


class WindowsDownloader(Downloader):
    """WindowsDownloader class, child of Downloader"""

    def __init__(self) -> None:
        super().__init__()

    def download(self,
                 dispatcher_broker: DispatcherBroker,
                 uri: Optional[CanonicalUri],
                 repo: IRepo,
                 username: Optional[str],
                 password: Optional[str],
                 release_date: Optional[str]) -> None:
        """STUB: downloads Windows update

        @param uri: URI of the source location
        @param repo: repository for holding the download
        @param username: username to use for download
        @param password: password to use for download
        @param release_date: manifest release date
        @raises SotaError: release date is not valid
        """

        logger.debug("")

    def check_release_date(self, release_date: Optional[str]) -> bool:
        raise NotImplementedError()


class YoctoDownloader(Downloader):
    """YoctoDownloader class, child of Downloader"""

    def __init__(self) -> None:
        super().__init__()

    def download(self,
                 dispatcher_broker: DispatcherBroker,
                 uri: Optional[CanonicalUri],
                 repo: IRepo,
                 username: Optional[str],
                 password: Optional[str],
                 release_date: Optional[str]) -> None:
        """Downloads files and places image in local cache

        @param dispatcher_broker: DispatcherBroker object used to communicate with other INBM services
        @param uri: URI of the source location
        @param repo: repository for holding the download
        @param username: username to use for download
        @param password: password to use for download
        @param release_date: manifest release date
        @raises SotaError: release date is not valid
        """

        if not self.check_release_date(release_date):
            msg = " SOTA download Aborted as mender release date " \
                  "is not lower than manifest date"
            raise SotaError(msg)
        if uri is None:
            raise SotaError("URI is None while performing Yocto download")

        download(dispatcher_broker=dispatcher_broker,
                 uri=uri,
                 repo=repo,
                 umask=UMASK_OTA,
                 username=username,
                 password=password)

    def check_release_date(self, release_date: Optional[str]) -> bool:
        return self.is_valid_release_date(release_date)


class TiberOSDownloader(Downloader):
    """TiberOSDownloader class, child of Downloader

       @param signature: signature used to preform signature check on downloaded image.
    """

    def __init__(self, signature: Optional[str] = None) -> None:
        super().__init__()
        self._signature = signature

    def download(self,
                 dispatcher_broker: DispatcherBroker,
                 uri: Optional[CanonicalUri],
                 repo: IRepo,
                 username: Optional[str],
                 password: Optional[str],
                 release_date: Optional[str]) -> None:
        """Downloads files and places image in local cache

        @param dispatcher_broker: DispatcherBroker object used to communicate with other INBM services
        @param uri: URI of the source location
        @param repo: repository for holding the download
        @param username: username to use for download
        @param password: password to use for download
        @param release_date: manifest release date
        @raises SotaError: release date is not valid
        """

        if uri is None:
            raise SotaError("URI is None while performing TiberOS download")

        password = read_oras_token()

        oras_download(dispatcher_broker=dispatcher_broker,
                      uri=uri,
                      repo=repo,
                      umask=UMASK_OTA,
                      username=username,
                      password=password)

        # Perform signature check.
        # Multiple files may have been downloaded from OCI.
        # The method below will iterate over all files in the repo, calculate the SHA256sum for each file,
        # and compare it with the provided signature.
        # FIXME: https://jira.devtools.intel.com/browse/NEXMANAGE-734
        try:
            if self._signature:
                logger.debug("Perform signature check on the downloaded file.")
                dest_repo = repo.get_repo_path()
                for filename in os.listdir(dest_repo):
                    filepath = os.path.join(dest_repo, filename)
                    if os.path.isfile(filepath):
                        with open(filepath, 'rb') as file:
                            file_checksum = hashlib.sha256(file.read()).hexdigest()
                            if file_checksum == self._signature:
                                return

                raise SotaError("Signature checks failed. No matching file found.")
            else:
                logger.info("No signature provided. Skip signature check.")
        except OSError as err:
            raise SotaError(err)


    def check_release_date(self, release_date: Optional[str]) -> bool:
        raise NotImplementedError()