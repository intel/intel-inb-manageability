"""
    Utilities

    Copyright (C) 2019-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import os
import logging
import tarfile
import glob

from datetime import datetime
from typing import Dict, List
from pathlib import Path
from .constants import FIP_FILE, OS_IMAGE, ROOTFS

from inbm_common_lib.utility import remove_file, get_canonical_representation_of_path

logger = logging.getLogger(__name__)


def get_file_path_from_manifest(manifest: str) -> str:
    """ Get the file path from OTA manifest.
    This function is used when the manifest is failed to parse and want to remove temporary OTA file.
    It gets the file path information directly from the manifest.

    @param manifest: OTA manifest
    @return: string representing the location of file
    """
    path_start_idx = manifest.find('<path>')
    path_end_idx = manifest.find('</path>')
    return manifest[path_start_idx:path_end_idx].replace('<path>', '')


def build_file_path_list(parsed_params: Dict[str, str]) -> List[str]:

    # Single FOTA or SOTA
    path = parsed_params.get('path', None)
    if path:
        return [path]

    # POTA (FOTA and SOTA)
    file_paths = []
    fota_file_path = parsed_params.get('fota_path', None)
    sota_file_path = parsed_params.get('sota_path', None)

    if not fota_file_path or not sota_file_path:
        raise FileNotFoundError("Missing file location for POTA")

    file_paths.append(fota_file_path)
    file_paths.append(sota_file_path)
    return file_paths


def move_flashless_files(path: str, destination: str) -> None:
    """ Method to untar and move the flashless files.

    @param path: string representing the location of flashless tarball
    @param destination: string representing the flashless folder
    """
    # Only support TBH HDDL now
    # untar flashless tarball to /lib/firmware/
    # the tarball should contains fip, flashless image and rootfs
    tar_path = Path(path)
    if os.path.islink(tar_path):
        raise OSError("Flashless tarball location is a symlink.")
    if tar_path.is_file():
        with tarfile.open(tar_path) as tar:
            logger.debug(f"Extract {tar_path}.")
            tar.extractall(path=destination)
            tar_path.unlink()

        try:
            fip_path = os.path.join(destination, "fip.bin")
            fip_path_des = os.path.join(destination, FIP_FILE)
            flashless_img_path = os.path.join(destination, "Image--Flashless.bin")
            flashless_img_path_des = os.path.join(destination, OS_IMAGE)
            rootfs_path = ""
            rootfs_path_des = ""
            rootfs_file_name = glob.glob(destination + "*.cpio.gz.u-boot")
            if not rootfs_file_name:
                raise FileNotFoundError("No rootfs file (cpio.gz.u-boot) found in the package.")
            rootfs_path = os.path.join(destination, rootfs_file_name[0])
            rootfs_path_des = os.path.join(destination, ROOTFS)
            os.rename(fip_path, fip_path_des)
            os.rename(flashless_img_path, flashless_img_path_des)
            os.rename(rootfs_path, rootfs_path_des)
        except (FileNotFoundError, IndexError) as error:
            remove_file(fip_path)
            remove_file(fip_path_des)
            remove_file(flashless_img_path)
            remove_file(flashless_img_path_des)
            remove_file(rootfs_path)
            remove_file(rootfs_path_des)
            raise FileNotFoundError(f"FLASHLESS OTA FAILURE due to error: {error}")


def create_date(date_info: datetime) -> str:
    """Converts a datetime object to create a custom string

    @param date_info: Date object to convert
    @return: Custom date format
    """
    return date_info.strftime("%m-%d-%Y %H:%M:%S") if date_info else "No date provided"
