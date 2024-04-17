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
from typing import Callable
import logging

logger = logging.getLogger(__name__)


class InbsAdapter(Adapter):
    def __init__(self, configs: dict) -> None:
        super().__init__(configs)

    def configure(self, configs: dict) -> CloudClient:
        """Configure the INBS cloud adapter

        @param configs: schema conforming JSON config data
        @exception AdapterConfigureError: If configuration fails
        """
        hostname = configs.get("hostname")
        if not hostname:
            raise AdapterConfigureError("Missing hostname")

        port = configs.get("port")
        if not port:
            raise AdapterConfigureError("Missing port")

        node_id = configs.get("node-id")
        if not node_id:
            raise AdapterConfigureError("Missing node-id")

        token = configs.get("token")
        if not token:
            raise AdapterConfigureError("Missing token")

        self._client = InbsCloudClient(hostname=hostname,
                                       port=port,
                                       node_id=node_id,
                                       token=token)
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
