"""
    Publishes OTA manifests for targets.

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
import os
from typing import Any, Optional, Mapping, List, Dict
from urllib.parse import urlsplit

from inbm_common_lib.utility import get_canonical_representation_of_path, canonicalize_uri, CanonicalUri
from inbm_common_lib.constants import CONFIG_CHANNEL, CONFIG_LOAD
from inbm_common_lib.exceptions import UrlSecurityException
from .common.result_constants import PUBLISH_SUCCESS, Result, OTA_FAILURE
from .constants import TARGET_OTA_CMD_CHANNEL, SCHEMA_LOCATION, UMASK_OTA, OTA_PACKAGE_CERT_PATH, REPO_CACHE
from .dispatcher_broker import DispatcherBroker
from .dispatcher_callbacks import DispatcherCallbacks
from .dispatcher_exception import DispatcherException
from .downloader import download
from .ota_factory import OtaType
from .packagemanager.local_repo import DirectoryRepo
from .packagemanager.package_manager import verify_signature
from inbm_lib.xmlhandler import XmlException, XmlHandler

logger = logging.getLogger(__name__)


class OtaTarget:
    """Publish OTA for targets Tool.

    @param xml: XML to be modified
    @param parsed_manifest: parsed_manifest values for ota
    @param ota_type: type of ota
    @param dispatcher_callbacks: callbacks
    """

    def __init__(self, xml: str, parsed_manifest: Mapping[str, Optional[Any]], ota_type: str,
                 dispatcher_callbacks: DispatcherCallbacks) -> None:
        self._xml = xml
        self._dispatcher_callbacks = dispatcher_callbacks
        self._uri: Optional[str] = parsed_manifest.get('uri', None)
        self._ota_element = parsed_manifest.get('resource')
        self._ota_type = ota_type
        self._str_repo = parsed_manifest.get('repo', None)
        self._repo = DirectoryRepo(self._str_repo) if self._str_repo else DirectoryRepo(REPO_CACHE)
        self._username = parsed_manifest.get('username', None)
        self._password = parsed_manifest.get('password', None)
        self._signature = parsed_manifest.get('signature', None)
        self._hash_algorithm = parsed_manifest.get('hash_algorithm', None)
        if self._ota_type == OtaType.POTA.name:
            [parsed_manifest.pop('ota_type')]  # type: ignore
        self._parsed_manifest = parsed_manifest
        logger.debug("")

    def install(self) -> Result:
        """Manages the install sequence to support the Accelerator Manageability Framework

        @return: OTA result
        @raises DispatcherException: Invalid OTA type requested
        """
        logger.debug("")

        self._dispatcher_callbacks.broker_core.telemetry(
            "Publishing manifest on targets initialized..")
        if self._dispatcher_callbacks is None:
            raise DispatcherException(
                "dispatcher_callbacks not specified in Publish OTA for Targets constructor")
        valid_check = True
        repo_list: List[DirectoryRepo] = []
        if self._ota_type == OtaType.POTA.name:
            logger.debug(f"parsed man : {self._parsed_manifest}")
            # To track user defined repos for fota and sota. The list is used during cleanup in case of signature check failure.
            for ota_key in self._parsed_manifest.keys():
                logger.debug(f"OTA KEY : {ota_key}")
                ota_resource = self._parsed_manifest[ota_key]
                if ota_resource is None:
                    raise DispatcherException("no ota_resource in POTA")
                uri = ota_resource.get('uri', None)
                username = ota_resource.get('username', None)
                password = ota_resource.get('password', None)
                repo = ota_resource.get('repo', None)
                repo = DirectoryRepo(repo) if repo else DirectoryRepo(REPO_CACHE)
                repo_list.append(repo)
                signature = ota_resource.get('signature', None)
                hash_algorithm = ota_resource.get('hash_algorithm', None)
                try:
                    download_info = {'username': username, 'password': password,
                                     'signature': signature, 'hash_algorithm': hash_algorithm}
                    self._download_and_validate_package(
                        self._dispatcher_callbacks, uri, repo, ota_key.upper(), download_info)
                except (DispatcherException, UrlSecurityException) as err:
                    valid_check = False
                    ota_error = str(err)
                    self._dispatcher_callbacks.broker_core.telemetry(ota_error)
                    break

        elif self._ota_type == OtaType.FOTA.name or self._ota_type == OtaType.SOTA.name:
            repo_list.append(self._repo)
            try:
                download_info = {'username': self._username, 'password': self._password,
                                 'signature': self._signature, 'hash_algorithm': self._hash_algorithm}
                self._download_and_validate_package(
                    self._dispatcher_callbacks, self._uri, self._repo, self._ota_type, download_info)
            except (DispatcherException, UrlSecurityException) as err:
                valid_check = False
                ota_error = str(err)
                self._dispatcher_callbacks.broker_core.telemetry(ota_error)
        else:
            raise DispatcherException(
                f"The target OTA type is not supported: {self._ota_type}")

        if not valid_check:
            logger.error(ota_error)
            for repo in repo_list:
                repo.delete_all()
            self._dispatcher_callbacks.broker_core.telemetry(ota_error)
            return OTA_FAILURE

        xml_to_publish = self._modify_manifest()
        self._dispatcher_callbacks.broker_core.mqtt_publish(
            TARGET_OTA_CMD_CHANNEL, xml_to_publish)
        return PUBLISH_SUCCESS

    def _download_and_validate_package(self, disp_callbacks: DispatcherCallbacks, uri: Optional[str],
                                       repo: DirectoryRepo, ota_type: str, download_info: Dict[str, Any]):
        if uri is None or uri == "":
            raise DispatcherException(
                f"Fetch URI is empty for {ota_type}. Please provide the URI to download file")

        if repo is None:
            raise DispatcherException("attempted to download with uninitialized repo")
        download(dispatcher_callbacks=disp_callbacks,
                 uri=canonicalize_uri(uri),
                 repo=repo,
                 umask=UMASK_OTA,
                 username=download_info.get('username', None),
                 password=download_info.get('password', None))
        if ota_type != OtaType.SOTA.name:
            self._validate_signature(canonicalize_uri(uri), repo, download_info.get(
                'signature', None), download_info.get('hash_algorithm', None))
        disp_callbacks.broker_core.telemetry('Proceeding to publish OTA manifest...')

    def _validate_signature(self, uri: CanonicalUri, repo: DirectoryRepo,
                            signature: Optional[str], hash_algo: Optional[int]):
        logger.debug("")
        file_name = os.path.basename(urlsplit(uri.value).path)
        file_path = os.path.join(repo.get_repo_path(), file_name)
        if os.path.exists(OTA_PACKAGE_CERT_PATH):
            if signature:
                verify_signature(signature, file_path, self._dispatcher_callbacks, hash_algo)
            else:
                raise DispatcherException(
                    'OTA update aborted. Signature is required to validate the package and proceed with the update.')
        else:
            self._dispatcher_callbacks.broker_core.telemetry('Skipping signature check.')

    def _modify_manifest(self, schema_location: str = SCHEMA_LOCATION) -> str:
        logger.debug("")
        schema_location = get_canonical_representation_of_path(schema_location)
        try:
            parsed = XmlHandler(xml=self._xml, is_file=False, schema_location=schema_location)
            if self._ota_type == OtaType.POTA.name:
                logger.debug("")
                for ota_key in self._parsed_manifest.keys():
                    ota_resource = self._parsed_manifest[ota_key]
                    if ota_resource is None:
                        raise DispatcherException("ota_resource missing in POTA")
                    uri = ota_resource.get('uri', None)
                    pkg_filename = os.path.basename(uri)
                    new_xml = self._modify_manifest_helper(
                        parsed=parsed, ota_key=ota_key, package_name=pkg_filename).decode('utf-8', errors='strict')
                    parsed = XmlHandler(xml=str(new_xml), is_file=False,
                                        schema_location=schema_location)
            else:
                if self._ota_element is None:
                    raise DispatcherException(f"ota_resource missing in {self._ota_type}")
                pkg_filename = os.path.basename(self._ota_element['fetch'])
                new_xml = self._modify_manifest_helper(
                    parsed=parsed, package_name=pkg_filename).decode('utf-8', errors='strict')
            return new_xml
        except XmlException as e:
            raise DispatcherException(f"ERROR : {e}")

    def _modify_manifest_helper(self, parsed: Any, package_name: str, ota_key: str = None) -> bytes:
        logger.debug("")
        if ota_key is None:
            ota_key = ''
            ota_path = f"ota/type/{self._ota_type.lower()}"
        else:
            ota_path = f"ota/type/{self._ota_type.lower()}/{ota_key}"

        fetch_path = f"ota/type/{self._ota_type.lower()}/{ota_key}/fetch"
        username = f"ota/type/{self._ota_type.lower()}/{ota_key}/username"
        password = f"ota/type/{self._ota_type.lower()}/{ota_key}/password"
        new_xml = parsed.set_attribute("ota/header/repo", "local")
        new_xml = parsed.add_attribute(ota_path, "path", REPO_CACHE + '/' + package_name)
        new_xml = parsed.remove_attribute(fetch_path)
        new_xml = parsed.remove_attribute(username)
        new_xml = parsed.remove_attribute(password)
        return new_xml


def target_config_load_operation(xml: str, broker_core: DispatcherBroker, file_path: str) -> None:
    """This function handles the config operation on the targets by publishing
    the modified xml

    @param xml: xml to be modified
    @param broker_core: DispatcherBroker
    @param file_path: File location to load a conf file, used only for load operation
    @return Result: PUBLISH_SUCCESS
    @raises DispatcherException: if invalid cmd is sent. Expected is 'load'.
    """
    logger.debug("")
    xml_to_publish = _modify_xml_config_load(xml, file_path)
    broker_core.mqtt_publish(CONFIG_CHANNEL + CONFIG_LOAD, xml_to_publish)


def _modify_xml_config_load(xml: str, file_path: str) -> str:
    """Modifies the xml to be published to targets

    @param xml: xml to be modified
    @param file_path: new xml file location to be added to the manifest
    @return str: New xml to be published
    @raises DispatcherException: when xml operations couldn't be performed
    """
    try:
        parsed = XmlHandler(xml=xml, is_file=False,
                            schema_location=get_canonical_representation_of_path(SCHEMA_LOCATION))
        new_xml = parsed.remove_attribute("config/configtype/load/fetch")
        new_xml = parsed.add_attribute("config/configtype/load", "path", file_path)
    except XmlException as e:
        raise DispatcherException(f"ERROR : {e}")
    return new_xml.decode('utf-8', errors='strict')
