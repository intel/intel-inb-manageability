"""
    Gets package from remote repo, verifies, and rebuilds manifest to publish to vision-agent.

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
import os
from typing import List, Tuple
from tarfile import TarInfo

from inbm_common_lib.utility import get_canonical_representation_of_path, canonicalize_uri, remove_file
from inbm_common_lib.constants import DEFAULT_HASH_ALGORITHM

from .constants import UMASK_PROVISION_FILE, REPO_CACHE, SCHEMA_LOCATION, TARGET_PROVISION, OTA_PACKAGE_CERT_PATH
from .dispatcher_callbacks import DispatcherCallbacks
from .dispatcher_exception import DispatcherException
from .downloader import download
from .packagemanager.package_manager import extract_files_from_tar
from .packagemanager.package_manager import verify_signature
from .packagemanager.local_repo import DirectoryRepo
from inbm_lib.xmlhandler import XmlException, XmlHandler

logger = logging.getLogger(__name__)

NUM_EXPECTED_FILES_IN_TAR = 2  # (*.bin and *.crt)
BIN_FILE_EXT = ".bin"
CERT_FILE_EXT = ".crt"


class ProvisionTarget:
    """Install provision files for SOCs to the host.  Modify the manifest and publish to the vision-agent.
    @param xml: incoming XML file
    @param dispatcher_callbacks: Dispatcher objects
    @param schema_location: location of schema file
    """

    def __init__(self, xml: str, dispatcher_callbacks: DispatcherCallbacks,
                 schema_location: str = SCHEMA_LOCATION) -> None:
        logger.debug("")
        self._xml = xml
        self._dispatcher_callbacks = dispatcher_callbacks
        self._schema_location = schema_location

    def install(self, parsed_head: XmlHandler) -> None:
        """Manages the installation sequence to support the Accelerator Manageability Framework

        @param parsed_head: Parsed XML file
        @raises DispatcherException: package doesn't contain enough files to proceed
        """
        logger.debug("")
        uri = parsed_head.find_element('provisionNode/fetch')
        signature = parsed_head.find_element('provisionNode/signature')
        hash_algo = parsed_head.find_element('provisionNode/hash_algorithm')
        if signature:
            try:
                logger.debug(f"hash algorithm = {hash_algo}")
                hash_algo = int(hash_algo) if hash_algo else DEFAULT_HASH_ALGORITHM
            except ValueError:
                logger.debug("Unable to parse signature version. Use default version.")
                hash_algo = DEFAULT_HASH_ALGORITHM
        canonicalized_url = canonicalize_uri(uri)
        repo = DirectoryRepo(REPO_CACHE)
        download(dispatcher_callbacks=self._dispatcher_callbacks,
                 uri=canonicalized_url,
                 repo=repo,
                 umask=UMASK_PROVISION_FILE,
                 username=parsed_head.find_element('username'),
                 password=parsed_head.find_element('password'))
        tar_file_name = canonicalized_url.value.split('/')[-1]
        tar_file_path = os.path.join(REPO_CACHE, tar_file_name)
        if os.path.exists(OTA_PACKAGE_CERT_PATH):
            if signature:
                verify_signature(signature, tar_file_path, self._dispatcher_callbacks, hash_algo)
            else:
                raise DispatcherException(
                    'Provision Target install aborted. Signature is required to validate the package and proceed with the update.')
        else:
            self._dispatcher_callbacks.broker_core.telemetry('Skipping signature check.')

        files, tar = extract_files_from_tar(tar_file_path)
        if not files or len(files) != NUM_EXPECTED_FILES_IN_TAR:
            raise DispatcherException("ERROR: Cert/Blob file were not found in package")
        blob_file, cert_file = _verify_files(files)
        if tar:
            tar.extractall(path=REPO_CACHE)
            xml_to_publish = self._modify_manifest(blob_file, cert_file)
            self._dispatcher_callbacks.broker_core.mqtt_publish(
                TARGET_PROVISION, xml_to_publish)
        remove_file(tar_file_path)

    def _modify_manifest(self, blob_file: str, cert_file: str) -> str:
        try:
            parsed = XmlHandler(xml=self._xml, is_file=False,
                                schema_location=get_canonical_representation_of_path(self._schema_location))
            new_xml = parsed.remove_attribute("provisionNode/fetch")
            new_xml = parsed.remove_attribute("provisionNode/hash_algorithm")
            new_xml = parsed.remove_attribute("provisionNode/signature")
            new_xml = parsed.remove_attribute("provisionNode/username")
            new_xml = parsed.remove_attribute("provisionNode/password")
            new_xml = parsed.add_attribute(
                "provisionNode", "blobPath", REPO_CACHE + '/' + blob_file)
            new_xml = parsed.add_attribute(
                "provisionNode", "certPath", REPO_CACHE + '/' + cert_file)
        except XmlException as e:
            raise DispatcherException(f"ERROR : {e}")
        return new_xml.decode('utf-8', errors='strict')


def _verify_files(files: List[TarInfo]) -> Tuple[str, str]:
    """Verify that a .bin and .crt file exist in the TAR package"""
    #  TODO:  If we are able to verify that the insides of the files are what they say they are,
    # add that verification using magic.
    blob_file = None
    cert_file = None

    for index in range(len(files)):
        root, extension = os.path.splitext(files[index].name)
        if extension == BIN_FILE_EXT:
            blob_file = files[index].name
        elif extension == CERT_FILE_EXT:
            cert_file = files[index].name

    if not blob_file:
        raise DispatcherException("ProvisionNode did not contain the required *_blob.bin file")
    if not cert_file:
        raise DispatcherException("ProvisionNode did not contain the required .crt file")
    logger.debug("provisionNode file verification successful")
    return blob_file, cert_file
