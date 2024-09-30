"""
    Parses OTA manifests.

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
from typing import Dict, Optional, Any

import abc

from .constants import OtaType
from .common.uri_utilities import is_valid_uri
from .validators import is_valid_config_params
from .dispatcher_exception import DispatcherException
from inbm_lib.xmlhandler import XmlException
from inbm_lib.xmlhandler import XmlHandler
from inbm_common_lib.constants import DEFAULT_HASH_ALGORITHM, LOCAL_SOURCE

logger = logging.getLogger(__name__)


class OtaParser(metaclass=abc.ABCMeta):
    """Base class for parsing OTA."""

    def __init__(self, repo_type: str) -> None:
        self._repo_type = repo_type
        self._uri: Optional[str] = None
        self._username = None
        self._password = None
        self._signature = None
        self._hash_algorithm: int = DEFAULT_HASH_ALGORITHM
        self._ota_resource_list: Optional[Dict] = None
        self._ota_type = None

    @abc.abstractmethod
    def parse(self, resource: Dict, kwargs: Dict, parsed: XmlHandler) -> Dict[str, Any]:
        """Parse manifest

        @param resource: resource to parse
        @param kwargs: arguments
        @param parsed: parsed section of manifest
        """
        self._ota_type = kwargs.get('ota_type')

        self._uri = resource.get('fetch', None)

        if self._uri is not None and self._repo_type != LOCAL_SOURCE and not is_valid_uri(self._uri):
            error = "Invalid URI: " + str(self._uri)
            raise DispatcherException(error)

        self._username = resource.get('username', None)
        self._password = resource.get('password', None)
        self._signature = resource.get('signature', None)
        if self._signature:
            self._hash_algorithm = int(resource.get('sigversion', DEFAULT_HASH_ALGORITHM))

        return {}


class FotaParser(OtaParser):
    """Parses the FOTA manifest.

    """

    def __init__(self, repo_type: str) -> None:
        super().__init__(repo_type)

    def parse(self, resource: Dict, kwargs: Dict, parsed: XmlHandler) -> Dict[str, Any]:
        """Parse XML tree of FOTA resource and populate into kwargs

        @param resource: resource xml tree parsed from manifest
        @param kwargs: the dict return variable to populated
        @param parsed: parameter current not used for FOTA
        @return: kwargs(dict)
        """
        super().parse(resource, kwargs, parsed)

        device_reboot = resource.get('deviceReboot', "yes")
        resource_dict = {'uri': self._uri, 'signature': self._signature,
                         'hash_algorithm': self._hash_algorithm,
                         'resource': resource,
                         'username': self._username,
                         'password': self._password,
                         'deviceReboot': device_reboot}

        if self._ota_type == OtaType.POTA.name.lower():
            return resource_dict

        kwargs.update(resource_dict)
        return kwargs


class SotaParser(OtaParser):
    """Parses the SOTA manifest.

    """

    def __init__(self, repo_type: str) -> None:
        super().__init__(repo_type)

    def parse(self, resource: Dict, kwargs: Dict, parsed: XmlHandler) -> Dict[str, Any]:
        """Parse XML tree of SOTA resource and populate into kwargs

        @param resource: resource xml tree parsed from manifest
        @param kwargs: the dict return variable to populated
        @param parsed: manifest object
        @return: kwargs(dict)
        """
        logger.debug(" ")
        super().parse(resource, kwargs, parsed)
        sota_cmd = resource.get('cmd', None)
        release_date = resource.get('release_date', None)
        header = parsed.get_children('ota/header')
        sota_mode = resource.get('mode', None)
        package_list = resource.get('package_list', '')
        main_ota = header['type']
        device_reboot = resource.get('deviceReboot', "yes")
        try:
            if self._ota_type == OtaType.POTA.name.lower() or main_ota == OtaType.POTA.name.lower():
                log_to_file = parsed.get_attribute('ota/type/pota/sota/cmd', 'logtofile')
            else:
                log_to_file = parsed.get_attribute('ota/type/sota/cmd', 'logtofile')
        except (KeyError, DispatcherException):
            log_to_file = 'N'

        resource_dict = {'sota_mode': sota_mode, 'package_list': package_list,
                         'sota_cmd': sota_cmd, 'log_to_file': log_to_file, 'uri': self._uri,
                         'signature': self._signature,
                         'hash_algorithm': self._hash_algorithm, 'resource': resource, 'username': self._username,
                         'password': self._password, 'release_date': release_date, 'deviceReboot': device_reboot}

        if self._ota_type == OtaType.POTA.name.lower():
            return resource_dict

        kwargs.update(resource_dict)
        return kwargs


class AotaParser(OtaParser):
    """Parses the AOTA manifest.

    """

    def __init__(self, repo_type: str) -> None:
        super().__init__(repo_type)

    def parse(self, resource: Dict, kwargs: Dict, parsed: XmlHandler) -> Dict[str, Any]:
        """Parse XML tree of ATA resource and populate into kwargs

        @param resource: resource xml tree parsed from manifest
        @param kwargs: the dict return variable to populated
        @param parsed: manifest string
        @return: kwargs(dict)
        """
        logger.debug(" ")
        super().parse(resource, kwargs, parsed)
        cmd = resource.get('cmd', None)
        app = resource.get('app', None)
        version = resource.get('version', None)
        file = resource.get('file', None)
        config_params = resource.get('configParams', None)
        container_tag = resource.get('containerTag', None)
        device_reboot = resource.get('deviceReboot', None)
        docker_registry = resource.get('dockerRegistry', None)
        docker_username = resource.get('dockerUsername', None)
        docker_password = resource.get('dockerPassword', None)

        # Check to see if config parameters have been passed
        if 'import' in cmd:
            config_params = '{"execcmd":"/bin/true"}'

        if config_params and not is_valid_config_params(config_params):
            logger.info("Config Params not passed correctly"
                        " in manifest, rejected update")
            raise XmlException
        kwargs.update({'config_params': config_params,
                       'hash_algorithm': self._hash_algorithm,
                       'signature': self._signature,
                       'app_type': app,
                       'cmd': cmd,
                       'container_tag': container_tag,
                       'device_reboot': device_reboot,
                       'version': version,
                       'uri': self._uri,
                       'file': file,
                       'username': self._username,
                       'password': self._password,
                       'docker_registry': docker_registry,
                       'docker_username': docker_username,
                       'docker_password': docker_password})
        return kwargs


class PotaParser(OtaParser):
    """Parses the POTA manifest."""

    def __init__(self, repo_type: str) -> None:
        super().__init__(repo_type)

    def parse(self, resource: Dict, kwargs: Dict, parsed: XmlHandler) -> Dict[str, Any]:
        """Parse XML tree of FOTA resource and populate into kwargs

        @param resource: resource xml tree parsed from manifest
        @param kwargs: the dict return variable to populated
        @param parsed: manifest string
        @return: kwargs(dict)
        """
        logger.debug(" ")

        for key in resource.keys():
            ota_resource = parsed.get_children(f'ota/type/pota/{key}')
            if key == 'fota':
                fota_args = FotaParser(self._repo_type)
                kwargs.update({key: fota_args.parse(ota_resource, kwargs, parsed)})
            elif key == 'sota':
                sota_args = SotaParser(self._repo_type)
                kwargs.update({key: sota_args.parse(ota_resource, kwargs, parsed)})
        self._ota_resource_list = kwargs
        return kwargs
