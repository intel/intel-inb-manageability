"""
    Module which fetches and stores external update packages. It fetches a
    package from the specified URL and stores into a configured local cache
    on the device

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import hashlib
import json
import logging
import os
import platform
import shutil
import tarfile
from binascii import unhexlify
from tarfile import TarFile
from typing import Any, Union, Optional, Tuple, List, IO

import requests
from cryptography import exceptions  # type: ignore
from cryptography.hazmat.backends import default_backend  # type: ignore
from cryptography.hazmat.primitives import hashes  # type: ignore
from cryptography.hazmat.primitives.asymmetric import padding  # type: ignore
from cryptography.x509 import load_pem_x509_certificate  # type: ignore
from future.moves.urllib.parse import urlparse
from inbm_common_lib.utility import CanonicalUri, canonicalize_uri
from inbm_common_lib.utility import get_canonical_representation_of_path
from inbm_lib.count_down_latch import CountDownLatch
from requests import HTTPError
from requests.exceptions import ProxyError, ChunkedEncodingError, ContentDecodingError, ConnectionError
from requests.utils import get_environ_proxies

from .constants import LINUX_CA_FILE
from .irepo import IRepo
from ..constants import OTA_PACKAGE_CERT_PATH
from ..common.result_constants import Result, CODE_OK, CODE_BAD_REQUEST
from ..config.config_command import ConfigCommand
from ..config.constants import *
from ..dispatcher_callbacks import DispatcherCallbacks
from ..dispatcher_exception import DispatcherException

logger = logging.getLogger(__name__)


def get_file_type(file_name: str) -> Optional[str]:
    """Get the type of file i.e. cert or package based on the file extension

    @param file_name: Name of the file
    @return: type of file if valid extension else returns None
    """
    ext = _get_ext(file_name)

    if ext.lower() in {'rpm', 'deb', 'fv', 'cap', 'bio', 'bin', 'conf', 'mender'}:
        return 'package'
    else:
        return None


def get_platform_ca_certs() -> Union[bool, str]:
    """Get correct platform value for 'verify' parameter specifying CA certificates for TLS

    @return: (bool or str)  True for Windows, LINUX_CA_FILE for Linux"""

    if platform.system() == 'Windows':
        return True
    else:
        return LINUX_CA_FILE


def is_enough_space_to_download(uri: CanonicalUri,
                                destination_repo: IRepo,
                                username: str = None,
                                password: str = None) -> bool:
    """Checks if enough free space exists on platform to hold download.

    Calculates the file size from the server and checks if required free space is available on
    the platform.
    @param destination_repo:  desired download destination
    @param uri: server address where the file is hosted
    @param username: username  provided for download
    @param password: password  provided for download
    """

    if not isinstance(uri, CanonicalUri):
        raise DispatcherException(
            "Internal error: URI improperly passed to is_enough_space_to_download function")

    if username and password and not uri.value.startswith("https://"):
        raise DispatcherException('Bad request: username/password will not be'
                                  ' processed on Http server')
    auth: Optional[Tuple[str, str]] = None
    if username and password and uri.value.startswith("https://"):
        auth = (username, password)

    try:
        logger.info("Checking content size...")
        env_proxies = get_environ_proxies(uri.value)
        logger.debug("Proxies: " + str(env_proxies))
        with requests.get(uri.value, auth=auth, verify=get_platform_ca_certs(), stream=True) as response:
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
        raise DispatcherException('Invalid URI:' 'Status code for ' + uri.value +
                                  ' is ' + str(e.response.status_code))
    except (ProxyError, ChunkedEncodingError, ContentDecodingError, ConnectionError) as e:
        raise DispatcherException(str(e))

    except Exception as e:
        raise DispatcherException(e)

    logger.debug("Content-length: " + repr(content_length))
    file_size: int=int(content_length)
    if destination_repo.exists():
        get_free_space=destination_repo.get_free_space()
        free_space: int=int(get_free_space)
    else:
        raise DispatcherException("Repository does not exist : " +
                                  destination_repo.get_repo_path())

    logger.debug("get_free_space: " + repr(get_free_space))
    logger.debug("Free space available on destination_repo is " + repr(free_space))
    logger.debug("Free space needed on destination repo is " + repr(file_size))
    return True if free_space > file_size else False


def verify_signature(signature: str,
                     path_to_file: str,
                     dispatcher_callbacks: DispatcherCallbacks,
                     hash_algorithm: Optional[int]) -> None:
    """Verifies that the signed checksum of the package matches the package received by fetching the
    package and cert from tar ball and fetching the public key from the cert which is used in
    verifying the signature.

    @param signature: Signed checksum of the package retrieved from manifest
    @param path_to_file: Path to the package to be installed
    @param dispatcher_callbacks: DispatcherCallbacks instance
    @param hash_algorithm: version of checksum i.e. 256 or 384 or 512
    """
    logger.debug(f"tar_file_path: {path_to_file}")
    extension = path_to_file.rsplit('.', 1)[-1]
    path_to_file = get_canonical_representation_of_path(path_to_file)
    if extension.lower() == 'tar':
        files, tar = extract_files_from_tar(path_to_file)
        if files and tar:
            try:
                _is_valid_file(files)
            except DispatcherException:
                tar.close()
                raise DispatcherException('Signature check failed. Invalid package in tarball.')
            finally:
                tar.close()
        else:
            raise DispatcherException('Signature check failed. '
                                      'Invalid tar ball. No package found in tarball while validating signature.')
    else:
        if get_file_type(path_to_file) != 'package':
            raise DispatcherException('Signature check failed. Unsupported file format.')

    try:
        with open(path_to_file, 'rb') as file_content:
            package_content = file_content
            checksum_str = _get_checksum(package_content.read(), hash_algorithm)
    except (OSError, ValueError) as e:
        raise DispatcherException(
            f"Signature check failed. Could not load package content to create checksum: {e}")

    checksum = checksum_str.encode('utf-8')

    try:
        with open(OTA_PACKAGE_CERT_PATH, 'rb') as package_cert:
            cert_content = package_cert.read()
            cert_obj = load_pem_x509_certificate(cert_content, default_backend())
            pub_key = cert_obj.public_key()
        _verify_checksum_with_key(pub_key, signature, checksum, dispatcher_callbacks)
        dispatcher_callbacks.broker_core.telemetry('Signature check passed.')
    except (OSError, ValueError) as e:
        raise DispatcherException(f"Signature check failed.  "
                                  f"Could not load certificate content to validate signature: {str(e)}")


def _get_ext(name: str) -> str:
    return name.rsplit('.', 1)[-1] if name else ""


def extract_files_from_tar(path_to_file: str) -> Tuple[Optional[List], Optional[TarFile]]:
    path_to_file = get_canonical_representation_of_path(path_to_file)
    if not os.path.exists(path_to_file):
        logger.debug(f"Tar file does not exist: {path_to_file}")
        raise DispatcherException("ERROR: Tar file does not exist.  Unable to extract.")
    if tarfile.is_tarfile(path_to_file):
        tar = tarfile.open(get_canonical_representation_of_path(path_to_file), mode='r')
        return tar.getmembers(), tar
    else:
        return None, None


def _get_checksum(content: Union[bytes, bytearray, memoryview],
                  hash_algorithm: Optional[int]) -> str:
    """Calculates checksum of package received

    @param content: content of the package received
    @param hash_algorithm: hash algorithm of the checksum i.e. 256 or 384 or 512
    @return: checksum of the package
    """
    if hash_algorithm == 384:
        return hashlib.sha384(content).hexdigest()
    elif hash_algorithm == 256:
        return hashlib.sha256(content).hexdigest()
    elif hash_algorithm == 512:
        return hashlib.sha512(content).hexdigest()
    raise DispatcherException('Signature check failed. Unable to get checksum for package.')


def _is_valid_file(files: List) -> bool:
    """Extracts the files from the tar ball

    @param files: all files inside tar ball
    @return: package and cert extracted from tar ball
    """
    for member in files:
        file_type = get_file_type(member.name)
        if not file_type == 'package':
            return False
    return True


def _verify_checksum_with_key(pub_key: Any,
                              signature: Optional[str],
                              checksum: Optional[bytes],
                              dispatcher_callbacks: DispatcherCallbacks) -> None:
    """Verifies that the signed checksum of the package matches the package received.

    @param pub_key: Public Key fetched from the package
    @param signature: signature received from the manifest of the package
    @param checksum: checksum calculated of the package to be installed
    @param dispatcher_callbacks: DispatcherCallbacks instance
    """
    if not checksum:
        raise DispatcherException('Signature check failed. Invalid checksum.')
    if not signature:
        raise DispatcherException('Signature check failed. Invalid signature.')
    if pub_key.key_size > 3000:
        try:
            pub_key.verify(unhexlify(signature), checksum,
                           padding.PSS(mgf=padding.MGF1(hashes.SHA384()),
                                       salt_length=padding.PSS.MAX_LENGTH),  # type: ignore
                           hashes.SHA384())

        except (exceptions.InvalidSignature, ValueError, TypeError):
            raise DispatcherException(
                'Signature check failed. Checksum of data does not match signature in manifest.')

        dispatcher_callbacks.broker_core.telemetry(
            "Signature check passed. Checksum of data matches signature in manifest")
    else:
        raise DispatcherException('Invalid key size send.  Update rejected.')


def _is_source_match_trusted_repo(trusted_source: str, source: CanonicalUri) -> bool:
    if not isinstance(source, CanonicalUri):
        raise DispatcherException(
            "Internal error: URI improperly passed")

    if trusted_source.startswith('dispatcher/trustedRepositories:'):
        trusted_source = trusted_source[31:]
    if not trusted_source:
        return False

    return True if source.value.startswith(trusted_source) else False


def _parse_config_result(response, source) -> None:
    """Checks if the source received in manifest is in the trusted repository list response from config agent
    @param response: String response received from configuration agent for the command requested
    @param source: the repository path where the package is supposed to be fetched from
    """
    logger.debug("")
    if response is None:
        raise DispatcherException(
            'Source verification failed.  Failure fetching trusted repository.')
    for line in response.strip().splitlines():
        trusted_source = line.strip()
        if _is_source_match_trusted_repo(trusted_source, canonicalize_uri(source)):
            return
    logger.debug(f"Source '{source}' is not in the trusted repositories")
    raise DispatcherException(
        'Source verification failed.  Source is not in the trusted repository.')


def verify_source(source: Optional[str], dispatcher_callbacks: DispatcherCallbacks,
                  source_file: bool = False) -> None:  # pragma: no cover
    """Checks if the source received is in the trusted repository list by fetching the trusted
    repository list from config agent and then comparing it with the source received

    @param source: Path of repository where package is to be fetched from
    @param dispatcher_callbacks: DispatcherCallbacks instance
    @param source_file: variable specifying if source is locally on the system or not
    """
    if source_file:
        fp = urlparse(source).path
        if not os.path.exists(fp):
            raise DispatcherException('Source verification failed.  Path does not exist.')

    if source is None:
        logger.error("Invalid source passed")
        raise DispatcherException('Source verification failed.  Download aborted.')

    latch = CountDownLatch(1)

    def on_command(topic, payload, qos):
        logger.info('Message received: %s on topic: %s', payload, topic)

        try:
            cmd.response = json.loads(payload)

        except ValueError as error:
            logger.error(f'Unable to parse payload: {error}')

        finally:
            # Release lock
            latch.count_down()

            # Create command object for pre install check

    cmd = ConfigCommand('get_element', TRUSTED_REPOSITORIES_LIST)
    # Subscribe to response channel using the same request ID
    dispatcher_callbacks.broker_core.mqtt_subscribe(cmd.create_response_topic(), on_command)

    # Publish command request
    dispatcher_callbacks.broker_core.mqtt_publish(
        cmd.create_request_topic(), cmd.create_payload())

    latch.await_()

    _parse_config_result(cmd.response, source)


def get(url: CanonicalUri,
        repo: IRepo,
        umask: int,
        username: Optional[str] = None,
        password: Optional[str] = None) -> Result:
    """Fetches a package:
    a.) from URL specified and stores in a configured
    local repo
    OR
    b.) checks if a file exits on the local file system
    and copies to local repo

    @param url: Well-formed URL or a local file path
    @param repo: An instance of L{DirectoryRepo} object
    @return: A Result object
    @param url: URL to fetch package
    @param repo: repository to fetch package
    @param umask: umask for created files
    @param username: username used to authenticate/authorize source file
    @param password: password used to authenticate/authorize source file
    """
    code = CODE_BAD_REQUEST
    message = "Generic Error"

    if not isinstance(url, CanonicalUri):
        raise DispatcherException("Internal error: uri improperly passed to download function")

    if url.value == '':
        raise ValueError('Empty Fetch URL')

    logger.debug("Requesting file from repo...")
    if username and password and not url.value.startswith("https://"):
        error = "Username and password only allowed with https."
        logger.error(error)
        return Result(status=400, message=error)

    auth: Optional[Tuple[str, str]] = None
    if username and password:
        auth = (username, password)
    try:
        with requests.get(url.value, auth=auth, verify=get_platform_ca_certs(), stream=True) as response:
            response.raise_for_status()
            repo.add_from_requests_response(
                urlparse(url.value).path.split('/')[-1], response, umask=umask)
    except HTTPError as e:
        logger.error('Status code for ' + url.value + ' is ' + str(e.response.status_code))
        return Result(status=e.response.status_code, message=e.response.reason)
    except (shutil.Error, OSError) as e:
        logger.error(f"error occurred while adding file to repository. {e}")
        return Result(status=code, message=message)
    except Exception as e:
        logger.error(e)
        return Result(status=code, message=message)

    return Result(status=CODE_OK, message="OK")
