"""
    Utilities

    Copyright (C) 2017-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import html
import os
import url_normalize
import shutil
import tarfile
import logging

from dataclasses import dataclass
from pathlib import Path
from typing import List, Union

from inbm_common_lib.constants import VALID_MAGIC_FILE_TYPE, TEMP_EXT_FOLDER
from inbm_common_lib.shell_runner import PseudoShellRunner

from .constants import URL_NULL_CHAR
from .exceptions import UrlSecurityException

logger = logging.getLogger(__name__)


class CannotFindFileTypeException(Exception):
    pass


def get_file_type(path: str) -> str:
    """Get string corresponding to file type

    @param path: string representing the location of the file
    @return file type as a string (as the 'file' utility might return)"""

    try:
        canonical_path = get_canonical_representation_of_path(path)
        (out, err, code) = PseudoShellRunner.run("file -b " + canonical_path)
    except OSError as e:
        raise CannotFindFileTypeException("OSError encountered") from e
    if code != 0:
        if err is None:
            raise CannotFindFileTypeException(out)
        else:
            raise CannotFindFileTypeException(err)
    return out


def remove_file(path: Union[str, Path]) -> None:
    """ Remove file from the given path

    @param path: location of file to be removed
    """
    if not os.path.exists(path):
        return

    if os.path.isfile(path):
        logger.debug(f"Removing file at {path}.")
        os.remove(path)
    else:
        logger.warn("Failed to remove file. Path is a directory.")


def remove_file_list(path: List[str]) -> None:
    """ Remove file from the given path list

    @param path: list of string representing the location of file
    """
    for file in path:
        remove_file(file)


def get_canonical_representation_of_path(path: str) -> str:
    """Returns the canonical absolute expanded path of the path provided for both windows and linux
    @param path: path
    @return canonical representation of the path
    """
    return os.path.normcase(
        os.path.normpath(
            os.path.realpath(
                os.path.abspath(
                    os.path.expanduser(path)
                )
            )
        )
    )


def clean_input(val: str) -> str:
    """Clean input by escaping special characters and removing null characters"""
    val = html.escape(val)
    return str.replace(val, "\x00", "", -1)


@dataclass(frozen=True)
class CanonicalUri:
    """Use type system + mypy to keep track of whether URI has been canonicalized"""
    value: str


def canonicalize_uri(url: str) -> CanonicalUri:
    """Canonicalize a URI

    WARNING: a string with no forward slashes will have a scheme added. e.g., 'a' -> 'https://a'

    @param url: the url
    @return canonicalized version"""

    if url and URL_NULL_CHAR in url:
        raise UrlSecurityException("Unsafe characters detected in the url. Cannot process the request.")

    return CanonicalUri(value=url_normalize.url_normalize(url))


def validate_file_type(path: List[str]) -> None:
    """ Method to check target file's type. Example of supported file list:

    If the file is tarball, the content is extracted and all files will be identified.
    At the end, the extracted files are deleted.
    If error happened, all files are deleted.

    @param path: string representing the location of target file
    """
    logger.debug("Supported: {0}".format(VALID_MAGIC_FILE_TYPE))

    tarball_list: List[str] = [x for x in path if (not str(x).endswith('.mender') and tarfile.is_tarfile(x))]
    extracted_file_list: List[str] = []

    for tarball in tarball_list:
        with tarfile.open(tarball) as tar:
            logger.debug("Extract {0}.".format(tarball))
            tar.extractall(path=TEMP_EXT_FOLDER)
            extracted_file = tar.getmembers()
            for index in range(len(extracted_file)):
                extracted_file_list.append(os.path.join(TEMP_EXT_FOLDER, extracted_file[index].name))

    # Add the extracted file path into check list
    for file_path in path + extracted_file_list:
        logger.debug(f"looking for file type of file located at {file_path}")
        try:
            file_type = get_file_type(file_path)
        except CannotFindFileTypeException as e:
            # Remove all files on failure
            remove_file_list(path + extracted_file_list)
            if os.path.exists(TEMP_EXT_FOLDER):
                shutil.rmtree(TEMP_EXT_FOLDER, ignore_errors=True)
            raise TypeError(f"Cannot find file type of file {file_path}") from e
        logger.debug("{0}".format(file_type))
        if any(x in file_type for x in VALID_MAGIC_FILE_TYPE):
            pass
        else:
            # Remove all files on failure
            remove_file_list(path + extracted_file_list)
            if os.path.exists(TEMP_EXT_FOLDER):
                shutil.rmtree(TEMP_EXT_FOLDER, ignore_errors=True)
            raise TypeError("Unsupported file types: {0}".format(file_type))

    # Remove the extracted file
    if os.path.exists(TEMP_EXT_FOLDER):
        shutil.rmtree(TEMP_EXT_FOLDER, ignore_errors=True)
    remove_file_list(extracted_file_list)
