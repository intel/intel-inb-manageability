"""
Adapter for communication with the cloud agent on the device. It abstracts
creation of the cloud connection, termination, creating commands etc.

Connects to a custom cloud client via the General Cloud MQTT client

Copyright (C) 2017-2023 Intel Corporation
SPDX-License-Identifier: Apache-2.0
"""
from ...exceptions import AdapterConfigureError, ClientBuildError
from ..cloud_builders import build_client_with_config
from typing import Callable
from ..client.cloud_client import CloudClient
from .adapter import Adapter


class GenericAdapter(Adapter):
    def __init__(self, config: dict):
        super().__init__(config)

    def configure(self, config: dict) -> CloudClient:
        """Configure the adapter to connect to the server

        @param config: schema conforming JSON config data
        @exception AdapterConfigureError: If configuration fails
        """
        try:
            return build_client_with_config(config)
        except ClientBuildError as e:
            raise AdapterConfigureError(str(e))

    def bind_callback(self, name: str, callback: Callable) -> None:
        """Bind a callback to be triggered by a method called on the cloud
        The callback has the signature: (**kwargs) -> (str)
            (**kwargs): Keys/types are documented per action function
            (str): The success status and an accompanying message

        @param name:     (str) The name of the method to bind the callback to
        @param callback: (Callable) The callback to trigger
        """
        self._client.bind_callback(name, callback)
