"""
Adapter for communication with the cloud agent on the device. It abstracts
creation of the cloud connection, termination, creating commands etc.

Connects to INBS service via gRPC

Copyright (C) 2017-2024 Intel Corporation
SPDX-License-Identifier: Apache-2.0
"""

from ...exceptions import AdapterConfigureError
from ...cloud.client.inbs_cloud_client import InbsCloudClient
from ..client.cloud_client import CloudClient
from .adapter import Adapter
from typing import Callable, Optional
import logging
import os
import json

logger = logging.getLogger(__name__)


class InbsAdapter(Adapter):
    def __init__(self, configs: dict) -> None:
        super().__init__(configs)

    def configure(self, configs: dict) -> CloudClient:
        """Configure the INBS cloud adapter

        @param configs: schema conforming JSON config data
        @exception AdapterConfigureError: If configuration fails
        """
        onboarding_json_file = configs.get("onboarding_json_file")
        if onboarding_json_file:
            # New mode using onboarding_json_file
            if not os.path.exists(onboarding_json_file):
                raise AdapterConfigureError(f"Onboarding JSON file '{onboarding_json_file}' does not exist")

            with open(onboarding_json_file, 'r') as f:
                onboarding_data = json.load(f)

            node_id = onboarding_data.get("node_id")
            if not node_id:
                raise AdapterConfigureError("Missing node_id in onboarding.json")

            services = onboarding_data.get("services", [])
            inbs_service = None
            for service in services:
                if service.get("type") == "INBS":
                    inbs_service = service
                    break

            if not inbs_service:
                raise AdapterConfigureError("No INBS service found in onboarding.json")

            hostname = inbs_service.get("host")
            if not hostname:
                raise AdapterConfigureError("Missing host in INBS service from onboarding.json")

            port = inbs_service.get("port")
            if not port:
                raise AdapterConfigureError("Missing port in INBS service from onboarding.json")
            try:
                port_int = int(port)
                if not (0 < port_int < 65536):
                    raise AdapterConfigureError("Port number must be between 1 and 65535")
            except ValueError:
                raise AdapterConfigureError("Port must be an integer")

            # Get the token (assuming jwt_token is used as token)
            token = onboarding_data.get("jwt_token")
            if not token:
                raise AdapterConfigureError("Missing jwt_token in onboarding.json")

            tls_cert = None  # TLS cert always comes from system
            tls_enabled = True  # TLS is always enabled in this mode

        else:
            # Existing mode
            hostname = configs.get("hostname")
            if not hostname:
                raise AdapterConfigureError("Missing hostname")

            port = configs.get("port")
            if not port:
                raise AdapterConfigureError("Missing port")
            try:
                port_int = int(port)
                if not (0 < port_int < 65536):
                    raise AdapterConfigureError("Port number must be between 1 and 65535")
            except ValueError:
                raise AdapterConfigureError("Port must be an integer")

            node_id = configs.get("node_id")
            if not node_id:
                raise AdapterConfigureError("Missing node_id")

            tls_enabled = configs.get("tls_enabled", True)
            tls_cert = None
            token = None

            if tls_enabled:
                tls_cert_path = configs.get("tls_cert_path")
                if not tls_cert_path or not os.path.exists(tls_cert_path):
                    raise AdapterConfigureError("TLS is enabled but missing or incorrect certificate file path")
                with open(tls_cert_path, 'rb') as f:
                    tls_cert = f.read()

                token_path = configs.get("token_path")
                if not token_path or not os.path.exists(token_path):
                    raise AdapterConfigureError("TLS is enabled but missing or incorrect token file path")
                with open(token_path, 'r') as f:
                    token = f.read().strip()
            else:
                if configs.get("token_path"):
                    raise AdapterConfigureError("Token path provided but TLS is not enabled")
                if configs.get("tls_cert_path"):
                    raise AdapterConfigureError("TLS cert path provided but TLS is not enabled")

        # Initialize the client with the gathered parameters
        self._client = InbsCloudClient(
            hostname=hostname,
            port=port,
            node_id=node_id,
            token=token if tls_enabled else None,
            tls_enabled=tls_enabled,
            tls_cert=tls_cert if tls_enabled else None
        )
        return self._client

    def bind_callback(self, name: str, callback: Callable) -> None:
        """Bind a callback to be triggered by a method called on the cloud
        The callback has the signature: (**kwargs) -> (str)
            (**kwargs): Keys/types are documented per action function
            (str): The success status and an accompanying message

        @param name:     callback method name
        @param callback: callback to trigger
        """
        self._client.bind_callback(name, callback)
