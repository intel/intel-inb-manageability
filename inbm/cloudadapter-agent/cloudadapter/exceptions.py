"""
Exceptions used throughout the cloudadapter module

Copyright (C) 2017-2023 Intel Corporation
SPDX-License-Identifier: Apache-2.0
"""


# ========== Adapter Factory exceptions


class BadConfigError(Exception):
    """Indicates that the configuration file is bad"""
    pass


# ========== Adapters module exceptions


class AdapterConfigureError(Exception):
    """Raised when an Adapter configuration fails"""
    pass


class SubscribeError(Exception):
    """Raised when an MQTT subscribe fails"""
    pass


class PublishError(Exception):
    """Raised when an MQTT publish fails"""
    pass


class ConnectError(Exception):
    """Raised when an MQTT connect fails"""
    pass


class AuthenticationError(Exception):
    """Raised when there is an authentication error"""
    pass


class DisconnectError(Exception):
    """Raised when an MQTT disconnect fails"""
    pass


# ========== Cloud Client module exceptions


class ClientBuildError(Exception):
    """Raised when building the cloud client fails"""
