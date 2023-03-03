"""
    Utilities

    Copyright (C) 2017-2023 Intel Corporation
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

from inbm_common_lib.constants import VALID_MAGIC_FILE_TYPE_PREFIXES, TEMP_EXT_FOLDER
from inbm_common_lib.shell_runner import PseudoShellRunner

from .constants import URL_NULL_CHAR
from .exceptions import UrlSecurityException

logger = logging.getLogger(__name__)


class CannotFindFileTypeException(Exception):
    pass


def get_file_type(path: str) -> str:
    """Get string corresponding to file type

    @param path: location of the file
    @return file type (as the 'file' utility might return)
    """
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


def move_file(source_file_path: str, destination_path: str) -> None:
    """ Move a file from one location to another using the same name.  This does not allow symlinks for
    either src or destination for security reasons.

    @param source_file_path: path of source file
    @param destination_path: path to destination file
    @raises: Symlink for src or destination.  Any errors during move.
    """
    canonical_src_path = get_canonical_representation_of_path(source_file_path)
    canonical_target_path = get_canonical_representation_of_path(destination_path)

    try:
        _check_paths(canonical_src_path, canonical_target_path)
    except IOError as e:
        raise IOError(f"Error while moving file: {str(e)}")

    try:
        shutil.move(canonical_src_path, canonical_target_path)
    except (shutil.SameFileError, PermissionError, IsADirectoryError, FileNotFoundError, OSError) as e:
        raise IOError(f"Error while moving file: {str(e)}")


def copy_file(src: str, destination: str) -> None:
    """Copies file from source to destination.  This does not allow symlinks for
    either src or destination for security reasons.

    @param src: path to source file
    @param destination: path to destination
    @raises: Symlink for src or destination.  Any errors during copyfile.
    """
    canonical_src_path = get_canonical_representation_of_path(str(src))
    canonical_target_path = get_canonical_representation_of_path(str(destination))
    try:
        _check_paths(canonical_src_path, canonical_target_path)
    except IOError as e:
        raise IOError(f"Error while copying file: {str(e)}")

    try:
        logger.debug(f"copyfile: src={canonical_src_path}, destination={canonical_target_path}")
        shutil.copy(canonical_src_path, canonical_target_path)
    except (shutil.SameFileError, PermissionError, IsADirectoryError, FileNotFoundError, OSError) as e:
        raise IOError(f"Error while copying file: {str(e)}")


def _check_paths(src: str, destination: str) -> None:
    logger.debug(f"check paths: src:{src}, destination:{destination}")
    if not os.path.isfile(src):
        logger.debug(f"File does not exist or file path is not to a file: {src}")
        raise IOError("File does not exist or file path is not to a file.")

    if os.path.islink(src):
        logger.debug(f"Security error: Source file is a symlink: {src}")
        raise IOError("Security error: Source file is a symlink.")

    if os.path.islink(destination):
        logger.debug(f"Security error: Destination is a symlink: {src}")
        raise IOError("Security error: Destination  is a symlink")


def remove_file(path: Union[str, Path]) -> None:
    """ Remove file from the given path

    @param path: location of file to be removed
    """
    canonical_path = get_canonical_representation_of_path(str(path))
    if not os.path.exists(canonical_path):
        return

    if os.path.isfile(canonical_path):
        logger.debug(f"Removing file at {canonical_path}.")
        os.remove(canonical_path)
    else:
        logger.warning("Failed to remove file. Path is a directory.")


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

def is_within_directory(directory: str, target: str) -> bool:
    """Check if target is within directory
    
    @param directory: directory to check
    @param target: target to check
    @return whether target is within directory
    """

    abs_directory = os.path.abspath(directory)
    abs_target = os.path.abspath(target)

    prefix = os.path.commonprefix([abs_directory, abs_target])

    return prefix == abs_directory

def safe_extract(tarball: tarfile.TarFile, path=".", members=None, *, numeric_owner=False):
    """Avoid path traversal when extracting tarball

    @param tarball: tarball to extract
    @param path: path to extract to
    @param members: members to extract
    @param numeric_owner: whether to extract numeric owner
    """
    for member in tarball.getmembers():
        member_path = os.path.join(path, member.name)
        if not is_within_directory(path, member_path):
            raise IOError("Attempted Path Traversal in Tar File")
    tarball.extractall(path, members, numeric_owner=numeric_owner) 

def validate_file_type(path: List[str]) -> None:
    """ Method to check target file's type. Example of supported file list:

    If the file is tarball, the content is extracted and all files will be identified.
    At the end, the extracted files are deleted.
    If error happened, all files are deleted.

    @param path: string representing the location of target file
    """
    logger.debug("Supported file type prefixes: {0}".format(VALID_MAGIC_FILE_TYPE_PREFIXES))

    tarball_list: List[str] = [x for x in path if (not str(x).endswith('.mender') and tarfile.is_tarfile(x))]
    extracted_file_list: List[str] = []

    for tarball in tarball_list:
        with tarfile.open(tarball) as tar:
            logger.debug("Extract {0}.".format(tarball))
            safe_extract(tar, path=TEMP_EXT_FOLDER)
            extracted_files = tar.getmembers()
            for index in range(len(extracted_files)):
                extracted_file_list.append(os.path.join(TEMP_EXT_FOLDER, extracted_files[index].name))

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
        logger.debug(f"checking validity of file type: {file_type}")

        # TODO: use regular expressions instead of fixed strings for VALID_MAGIC_FILE_TYPE_PREFIXES
        if any(file_type.startswith(valid_type_prefix) for valid_type_prefix in VALID_MAGIC_FILE_TYPE_PREFIXES):
            logger.debug("file type matches at least one valid prefix")
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
