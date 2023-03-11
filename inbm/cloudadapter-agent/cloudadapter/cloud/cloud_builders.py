"""
Module containing functions that direct the building of CloudClients

Copyright (C) 2017-2023 Intel Corporation
SPDX-License-Identifier: Apache-2.0
"""
import logging

from .client.connections.mqtt_connection import MQTTConnection
from .client.messengers.one_way_messenger import OneWayMessenger
from .client.handlers.recieve_respond_handler import RecieveRespondHandler
from .client.handlers.echo_handler import EchoHandler
from .client.cloud_client import CloudClient
from .client.utilities import ProxyConfig, TLSConfig, Formatter, MethodParser
from cloudadapter.constants import GENERIC_SCHEMA_PATH
from cloudadapter.exceptions import ClientBuildError
from typing import Dict, Any
import jsonschema
import json

logger = logging.getLogger(__name__)


def validate_config(config: Dict[str, Any]) -> None:
    """Validate the given config

    @param config: (dict) Config object to check against schema
    @exception ValidationError: If it fails to validate
    """
    with open(GENERIC_SCHEMA_PATH) as schema_file:
        schema = json.loads(schema_file.read())
        jsonschema.validate(config, schema=schema)


def build_client_with_config(config: Dict[str, Any]) -> CloudClient:
    """Create CloudClient instance from a schema conforming config object

    @param config:  (dict) Config object
    @return: (CloudClient) Class instance
    """
    # Validate the config
    try:
        validate_config(config)
    except jsonschema.ValidationError as e:
        raise ClientBuildError(str(e))

    # Configure TLS
    tls_config = config.get("tls", None)
    x509 = config.get("x509", None)
    if x509 and tls_config:
        try:
            tls_config = TLSConfig(
                ca_certs=tls_config.get("certificates", None),
                device_cert=x509.get("device_cert", None),
                device_key=x509.get("device_key", None))
        except IOError as e:
            raise ClientBuildError(str(e))
    else:
        if tls_config:
            try:
                tls_config = TLSConfig(
                    ca_certs=tls_config.get("certificates", None))
            except IOError as e:
                raise ClientBuildError(str(e))

    # Configure Proxy
    proxy_config = config.get("proxy")
    if proxy_config:
        logger.debug("got proxy_config = {}".format(str(proxy_config)))
        proxy_config = ProxyConfig(
            hostname=proxy_config.get("hostname"),
            port=proxy_config.get("port"))

    # Build connection
    mqtt_config = config.get("mqtt")
    if mqtt_config:
        connection = MQTTConnection(
            username=mqtt_config.get("username"),
            password=mqtt_config.get("password", None),
            hostname=mqtt_config.get("hostname"),
            port=mqtt_config.get("port"),
            client_id=mqtt_config.get("client_id"),
            tls_config=tls_config,
            proxy_config=proxy_config)
    else:
        raise ClientBuildError(
            "Missing MQTT config information while setting up cloud connection.")

    # Set global formatter defaults
    defaults = {
        "username": mqtt_config.get("username"),
        "client_id": mqtt_config.get("client_id")
    }

    # Build messengers
    def build_messenger_with_config(config: Dict[str, Any]):
        """Create OneWayMessenger instance from a config object"""
        return OneWayMessenger(
            topic_formatter=Formatter(
                formatting=config.get("pub"),
                defaults=defaults),
            payload_formatter=Formatter(
                formatting=config.get("format"),
                defaults=defaults),
            connection=connection)

    telemetry = config.get("telemetry")
    attribute = config.get("attribute")
    event = config.get("event")
    if telemetry:
        telemetry = build_messenger_with_config(telemetry)
    else:
        raise ClientBuildError(
            "Missing 'attribute' information in the config to while setting up cloud connection.")
    if attribute:
        attribute = build_messenger_with_config(attribute)
    else:
        raise ClientBuildError(
            "Missing MQTT config information while setting up cloud connection.")
    if event:
        event = build_messenger_with_config(event)
    else:
        raise ClientBuildError(
            "Missing MQTT config information while setting up cloud connection.")

    # Build handler
    handler_config = config.get("method")
    if handler_config:
        parser_config = handler_config.get("parse")
        handler = RecieveRespondHandler(
            topic_formatter=Formatter(
                formatting=handler_config.get("pub"),
                defaults=defaults),
            payload_formatter=Formatter(
                formatting=handler_config.get("format"),
                defaults=defaults),
            subscribe_topic=handler_config.get("sub"),
            parser=MethodParser(
                parse_info=parser_config.get("single"),
                aggregate_info=parser_config.get("aggregate")),
            connection=connection)

    # Build echoers
    echoer_configs = config.get("echoers", [])
    for config in echoer_configs:
        EchoHandler(
            topic_formatter=Formatter(
                formatting=config.get("pub"),
                defaults=defaults),
            payload_formatter=Formatter(
                formatting=config.get("format"),
                defaults=defaults),
            subscribe_topic=config.get("sub"),
            connection=connection)

    # Build CloudClient
    return CloudClient(
        connection=connection,
        telemetry=telemetry,
        event=event,
        attribute=attribute,
        handler=handler)
