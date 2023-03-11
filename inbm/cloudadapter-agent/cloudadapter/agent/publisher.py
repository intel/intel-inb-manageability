"""
Responsible for publishing messages to Intel(R) In-Band Manageability, doing some pre-parsing
before calling appropriate Broker methods.

Copyright (C) 2017-2023 Intel Corporation
SPDX-License-Identifier: Apache-2.0
"""


from ..constants import MESSAGE
from .broker import Broker
from inbm_lib.create_xml_tags import create_xml_tags
from typing import Dict, List
import logging
logger = logging.getLogger(__name__)


class Publisher:
    """Publishes messages

    @param broker: (TCBroker) The TC Broker to use
    """

    def __init__(self, broker: Broker) -> None:
        self._broker = broker

    def _send_manifest(self, manifest: str) -> None:
        """Sends manifest to the MQTT Broker

        @param manifest: The properly formatted manifest to send
        """
        logger.info("Send manifest invoked")
        self._broker.publish_install(manifest)

    def _sanitize_values(self, arguments: Dict[str, str], valid_mapping: Dict[str, List[str]]) -> None:
        """Sanitizes and validates arguments against a set of valid inputs

        @param arguments: The arguments to validate / sanitize
        @param valid_mapping: The valid parameters/values
        @exception ValueError: If a parameter is set to an invalid value
        """
        error_message = ""

        for parameter, valid_values in valid_mapping.items():
            value = arguments.get(parameter)
            if not value:
                error_message += f"No input given for '{parameter}'. "
                continue
            valid = False
            for valid_value in valid_values:
                if value.lower() == valid_value.lower():
                    arguments[parameter] = valid_value
                    valid = True
                    break
            if not valid:
                error_message += f"'{value}' is not valid for '{parameter}'. "

        if error_message:
            raise ValueError(error_message)

    def _require_values(self, arguments: Dict[str, str], *required: str):
        """Checks arguments for the required values

        @param arguments: The arguments to check
        @param required: The required parameters
        @exception ValueError: If a parameter is missing a valid value
        """
        missing = []

        for parameter in required:
            if parameter not in arguments or not arguments.get(parameter):
                missing.append(parameter)

        if missing:
            raise ValueError(f"Missing required fields: {missing}")

    def publish_manifest(self, manifest: str = "") -> str:
        """Publishes a manifest update

        @param manifest: The manifest to update with
        @return: The accompanying message
        @exception ValueError: If an empty manifest is given
        """
        logger.debug("Manifest Update Triggered")

        if not manifest or not manifest.strip():
            raise ValueError("No manifest was given!")

        self._send_manifest(manifest)
        return MESSAGE.MANIFEST

    def publish_aota(self, **arguments: str) -> str:
        """Publishes an AOTA update

        @param arguments: (**kwargs: str) The AOTA arguments
        @return:          The accompanying message
        @exception ValueError: If an argument is an invalid value
        """
        logger.debug("AOTA Triggered")
        self._sanitize_values(
            arguments, {
                "app": ["docker", "compose", "application"],
                "cmd": ["down", "import", "list", "load", "pull", "remove", "stats", "up", "update"]
            }
        )

        # NOTE: It would be better if container_tag was containerTag
        container_tag = arguments.pop("container_tag", None)
        if container_tag:
            arguments.update(containerTag=container_tag)
        device_reboot = arguments.pop("device_reboot", None)
        if device_reboot:
            arguments.update(deviceReboot=device_reboot)

        manifest = ('<?xml version="1.0" encoding="utf-8"?>'
                    '<manifest>'
                    '<type>ota</type>'
                    '<ota>'
                    '<header>'
                    '<type>aota</type>'
                    '<repo>remote</repo>'
                    '</header>'
                    '<type><aota name="sample-rpm">{}</aota></type>'
                    '</ota>'
                    '</manifest>').format(
            create_xml_tags(arguments,
                            "cmd",
                            "app",
                            "fetch",
                            "file",
                            "version",
                            "signature",
                            "containerTag",
                            "deviceReboot",
                            "username",
                            "password",
                            "dockerRegistry",
                            "dockerUsername",
                            "dockerPassword"
                            )  # noqa: E127
        )

        self._send_manifest(manifest)
        return MESSAGE.AOTA

    def publish_fota(self, **arguments: str) -> str:
        """Publishes a FOTA update

        @param arguments: (**kwargs: str) The FOTA arguments
        @return:          The accompanying message
        """
        logger.debug("FOTA Triggered")

        # NOTE: It would be better if release_date was releasedate
        release_date = arguments.pop("release_date", None)
        if release_date:
            arguments.update(releasedate=release_date)

        self._require_values(
            arguments,
            "fetch", "biosversion", "manufacturer", "product", "vendor", "releasedate"
        )

        manifest = ('<?xml version="1.0" encoding="utf-8"?>'
                    '<manifest>'
                    '<type>ota</type>'
                    '<ota>'
                    '<header>'
                    '<type>fota</type>'
                    '<repo>remote</repo>'
                    '</header>'
                    '<type><fota name="sample">{}</fota></type>'
                    '</ota>'
                    '</manifest>').format(
            create_xml_tags(arguments,
                            "signature",
                            "fetch",
                            "biosversion",
                            "vendor",
                            "manufacturer",
                            "product",
                            "releasedate",
                            "path",
                            "tooloptions",
                            "username",
                            "password"
                            )  # noqa: E127
        )

        self._send_manifest(manifest)
        return MESSAGE.FOTA

    def publish_sota(self, **arguments: str) -> str:
        """Publish a SOTA update

        @param arguments: (**kwargs: str) The SOTA arguments
        @return:          The accompanying message
        @exception ValueError: If an argument is an invalid value
        """
        logger.debug("SOTA Triggered")
        self._sanitize_values(
            arguments, {
                "cmd": ["update", "upgrade"],
                "log_to_file": ["N", "Y"]
            }
        )

        manifest = ('<?xml version="1.0" encoding="utf-8"?>'
                    '<manifest>'
                    '<type>ota</type>'
                    '<ota>'
                    '<header>'
                    '<type>sota</type>'
                    '<repo>remote</repo>'
                    '</header>'
                    '<type><sota>'
                    '<cmd logtofile="{}">{}</cmd>'
                    '{}'
                    '</sota></type>'
                    '</ota>'
                    '</manifest>').format(
            arguments.get("log_to_file"),
            arguments.get("cmd"),
            create_xml_tags(arguments,
                            "fetch",
                            "signature",
                            "version",
                            "username",
                            "password",
                            "release_date"
                            )  # noqa: E127
        )

        self._send_manifest(manifest)
        return MESSAGE.SOTA

    def publish_config(self, **arguments: str) -> str:
        """Publishes a configuration update

        @param arguments: (**kwargs: str) The config arguments
        @return:          The accompanying message
        @exception ValueError: If an argument is an invalid value
        """
        logger.debug("Configuration Method Triggered")
        self._sanitize_values(
            arguments, {
                "cmd": ["get", "load", "set", "append", "remove"]
            }
        )

        manifest = ('<?xml version="1.0" encoding="UTF-8"?>'
                    '<manifest>'
                    '<type>config</type>'
                    '<config>'
                    '<cmd>{0}</cmd>'
                    '<configtype>'
                    '<{1}>{2}</{1}>'
                    '</configtype>'
                    '</config>'
                    '</manifest>')  # noqa: E127

        command = arguments.get("cmd")
        if command == "load":
            self._require_values(arguments, "fetch")
            manifest = manifest.format(
                command,
                command,
                create_xml_tags(arguments, "fetch", "signature")
            )
        else:
            self._require_values(arguments, "path")
            # Following line will only execute in testing
            assert command  # noqa: S101
            if command == "append" or command == "remove":
                add_tag = ""
            else:
                add_tag = "_element"
            manifest = manifest.format(
                command + add_tag,
                command,
                create_xml_tags(arguments, "path")
            )

        self._send_manifest(manifest)
        return MESSAGE.CONFIG

    def publish_query(self, **arguments: str) -> str:
        """Publishes a configuration update

        @param arguments: (**kwargs: str) Query arguments
        @return:          The accompanying message
        @exception ValueError: If an argument is an invalid value
        """
        logger.debug("Query Method Triggered")
        self._sanitize_values(
            arguments, {
                "option": ["all", "hw", "fw", "guid", "os", "security", "status", "swbom", "version"]
            }
        )

        manifest = ('<?xml version="1.0" encoding="UTF-8"?>'
                    '<manifest>'
                    '<type>cmd</type>'
                    '<cmd>query</cmd>'
                    '<query>'
                    '<option>{0}</option>'
                    '</query>'
                    '</manifest>')

        option = arguments.get("option")
        manifest = manifest.format(option,
                                   create_xml_tags(arguments, "option"))

        self._send_manifest(manifest)
        return MESSAGE.QUERY
