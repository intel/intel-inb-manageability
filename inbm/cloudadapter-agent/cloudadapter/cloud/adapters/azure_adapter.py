"""
Adapter for communication with the cloud agent on the device. It abstracts
creation of the cloud connection, termination, creating commands etc.

Connects to Azure IoT Central via the General Cloud MQTT client

Copyright (C) 2017-2023 Intel Corporation
SPDX-License-Identifier: Apache-2.0
"""


from ...exceptions import AdapterConfigureError, ClientBuildError
from ...constants import (AZURE_MQTT_PORT,
                          AZURE_DPS_ENDPOINT,
                          AZURE_TOKEN_EXPIRATION)
from ..cloud_builders import build_client_with_config
from ..client.cloud_client import CloudClient
from .adapter import Adapter
from base64 import b64encode, b64decode
from hashlib import sha256
from future.moves.urllib.request import quote
from hmac import HMAC
from time import time, sleep
from typing import Optional, Any, Dict, Callable, Tuple
import requests
import json
import logging
logger = logging.getLogger(__name__)


class AzureAdapter(Adapter):
    def __init__(self, configs: dict) -> None:
        super().__init__(configs)

    def configure(self, configs: dict) -> CloudClient:
        """Configure the Azure cloud adapter

        @param configs: schema conforming JSON config data
        @exception AdapterConfigureError: If configuration fails
        """
        scope_id = configs.get("scope_id")
        if not scope_id:
            raise AdapterConfigureError("Missing Azure Scope ID")

        device_id = configs.get("device_id")
        if not device_id:
            raise AdapterConfigureError("Missing Azure Device ID")

        device_sas_key = configs.get("device_sas_key", None)
        device_key = configs.get("device_key", None)
        device_cert = configs.get("device_cert", None)
        template_urn = configs.get("template_urn", None)
        certs: Optional[Tuple] = None

        if device_cert and device_key:
            certs = (device_cert, device_key)

        device_auth_set = {"certs": certs, "sas_key": device_sas_key}

        hostname = self._retrieve_hostname(scope_id, device_id, device_auth_set, template_urn)
        if device_sas_key:
            device_sas_key = self._generate_sas_token(hostname, device_sas_key)

        event_pub = f"devices/{device_id}/messages/events/"
        config = {
            "mqtt": {
                "username": f"{hostname}/{device_id}/?api-version=2018-06-30",
                "password": device_sas_key,
                "hostname": hostname,
                "client_id": device_id,
                "port": AZURE_MQTT_PORT
            },
            "proxy": {
                "auto": True
            },
            "tls": {
                "version": "TLSv1.2"
            },
            "event": {
                "pub": event_pub,
                "format": "{\"eventGeneric\": \"{value}\"}"
            },
            "telemetry": {
                "pub": event_pub,
                "format": "{\"{key}\": \"{value}\"}"
            },
            "attribute": {
                "pub": "$iothub/twin/PATCH/properties/reported/",
                "format": "{\"{key}\": \"{value}\"}"
            },
            "method": {
                "pub": "$iothub/methods/res/201/{request_id}",
                "format": "",
                "sub": "$iothub/methods/POST/#",
                "parse": {
                    "single": {
                        "request_id": {
                            "regex": r"\$iothub\/methods\/POST\/(\w+)\/([\w=?$]+)",
                            "group": 2
                        },
                        "method": {
                            "regex": r"\$iothub\/methods\/POST\/(\w+)\/([\w=?$]+)",
                            "group": 1
                        },
                        "args": {
                            "path": ""
                        }
                    }
                }
            }
        }

        if device_cert and device_key:
            logger.debug("Using X509 authentication mechanism.")
            config.update({"x509": {"device_cert": device_cert, "device_key": device_key}})

        try:
            return build_client_with_config(config)
        except ClientBuildError as e:
            raise AdapterConfigureError(str(e))

    def _retrieve_hostname(self, scope_id: str, device_id: str, device_auth_set: Dict[str, Any], template_urn: Optional[str]) -> str:
        """Retrieve the IoT Central hostname associated to the device

        @param scope_id:  The device's Scope ID
        @param device_id: The device's ID
        @param device_auth_set:The device's Shared Access Key
        @param template_urn:The Template URN to be associated to device
        @return:          The IoT Central hostname
        """
        # Set up the initial HTTP request
        endpoint = f"{AZURE_DPS_ENDPOINT}/{scope_id}/registrations/{device_id}/"
        registration = "register?api-version=2019-03-31"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json; charset=utf-8",
            "Connection": "keep-alive",
            "UserAgent": "prov_device_client/1.0",
        }
        sas_key = device_auth_set.get('sas_key', None)
        if sas_key:
            # Get the authentication token for the requests
            logger.debug("Using SAS key authentication.")
            resource = f"{scope_id}%2Fregistrations%2F{device_id}"
            auth_token = self._generate_sas_token(resource, sas_key, expiration=int(time() + 30))
            auth_token += "&skn=registration"
            headers.update({"Authorization": auth_token})
        logger.debug(f"TEMPLATE_URN : {template_urn}")
        data: Dict[str, Any] = {}
        if template_urn is None:
            data = {
                "registrationId": device_id,
            }
        else:
            data = {
                "payload": {
                    "iotcModelId": template_urn
                },
                "registrationId": device_id,
            }

        # Place a registration request for the device (it should already be registered)
        result = requests.put(endpoint + registration, data=json.dumps(data),
                              headers=headers, cert=device_auth_set.get('certs', None))
        result_data = json.loads(result.text)

        # Continue checking device's registration status until it resolves
        while result_data.get("status") == "assigning" and result.ok:
            operation_id = result_data.get("operationId")
            operation = f"operations/{operation_id}?api-version=2019-03-31"

            result = requests.get(endpoint + operation, headers=headers,
                                  cert=device_auth_set.get('certs', None))
            result_data = json.loads(result.text)
            logger.info("DATA: {}".format(result_data))
            sleep(1)  # Pause for a bit

        # Get the device's assigned hub
        if not result.ok:
            error = "Ran into an error retrieving hostname: {} {}".format(
                result.status_code, result.text)
            raise AdapterConfigureError(error)
        else:
            registration_state = result_data.get("registrationState")
            # Following line will only execute in testing
            assert registration_state  # noqa: S101
            hub = registration_state.get("assignedHub")
            logger.debug("Retrieved hostname: %s", hub)
            return hub

    def _generate_sas_token(self,
                            resource: str,
                            device_key: str,
                            expiration: int = None) -> str:
        """Create a SAS token for authentication. More information:
        https://docs.microsoft.com/en-us/azure/iot-hub/iot-hub-devguide-security

        @param resource:  The IoT Central resource for which the key is created
        @param device_key: The device's Shared Access Key
        @param expiration: The time at which the token expires
        @return:          The SAS token
        """
        if not expiration:
            expiration = int(time() + AZURE_TOKEN_EXPIRATION)

        sign_key = f"{resource}\n{expiration}".encode('utf-8')
        signature = b64encode(HMAC(b64decode(device_key), sign_key,  # type: ignore
                                   sha256).digest())
        signature = quote(signature)

        return "SharedAccessSignature sr={!s}&sig={!s}&se={}".format(
            resource,
            signature,
            expiration
        )

    def bind_callback(self, name: str, callback: Callable) -> None:
        """Bind a callback to be triggered by a method called on the cloud
        The callback has the signature: (**kwargs) -> (str)
            (**kwargs): Keys/types are documented per action function
            (str): The success status and an accompanying message

        @param name:     callback method name
        @param callback: callback to trigger
        """
        self._client.bind_callback(name, callback)
