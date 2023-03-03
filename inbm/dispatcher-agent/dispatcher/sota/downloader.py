"""
    SOTA to perform download during an update and is called from the dispatcher

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
from datetime import datetime

from typing import Optional
from .mender_util import read_current_mender_version
from .sota_error import SotaError
from ..constants import UMASK_OTA
from ..downloader import download
from ..packagemanager.irepo import IRepo
from ..dispatcher_callbacks import DispatcherCallbacks
from inbm_common_lib.utility import CanonicalUri


logger = logging.getLogger(__name__)


class Downloader:
    """Abstract class to download SOTA update/upgrade"""

    def __init__(self) -> None:
        pass

    def download(self,
                 callback: DispatcherCallbacks,
                 uri: Optional[CanonicalUri],
                 repo: IRepo,
                 username: Optional[str],
                 password: Optional[str],
                 release_date: Optional[str]) -> None:
        """Downloads update/upgrade and places capsule file in local cache.

        @param callback: callback to dispatcher
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

    def check_release_date(self, release_date: Optional[str]) -> bool:
        pass


class DebianBasedDownloader(Downloader):
    """DebianBasedDownloader class, child of Downloader"""

    def __init__(self) -> None:
        super().__init__()

    def download(self,
                 callback: DispatcherCallbacks,
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
                 callback: DispatcherCallbacks,
                 uri: Optional[CanonicalUri],
                 repo: IRepo,
                 username: Optional[str],
                 password: Optional[str],
                 release_date: Optional[str]) -> None:
        """STUB: downloads Windows update

        @param callback: callback to dispatcher
        @param uri: URI of the source location
        @param repo: repository for holding the download
        @param username: username to use for download
        @param password: password to use for download
        @param release_date: manifest release date
        @raises SotaError: release date is not valid
        """

        logger.debug("")

    def check_release_date(self, release_date: Optional[str]) -> bool:
        pass


class YoctoDownloader(Downloader):
    """YoctoDownloader class, child of Downloader"""

    def __init__(self) -> None:
        super().__init__()

    def download(self,
                 callback: DispatcherCallbacks,
                 uri: Optional[CanonicalUri],
                 repo: IRepo,
                 username: Optional[str],
                 password: Optional[str],
                 release_date: Optional[str]) -> None:
        """Downloads files and places image in local cache

        @param callback: callback to dispatcher
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

        download(dispatcher_callbacks=callback,
                 uri=uri,
                 repo=repo,
                 umask=UMASK_OTA,
                 username=username,
                 password=password)

    def check_release_date(self, release_date: Optional[str]) -> bool:
        return self.is_valid_release_date(release_date)
