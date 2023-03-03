"""
Adapter for communication with the cloud agent on the device. It abstracts
creation of the cloud connection, termination, creating commands etc.

Uses Wind River HDC Python bindings within the adapter APIs.

Copyright (C) 2017-2023 Intel Corporation
SPDX-License-Identifier: Apache-2.0
"""


from ...exceptions import AdapterConfigureError, ClientBuildError
from .adapter import Adapter
from ..cloud_builders import build_client_with_config
from ..client.cloud_client import CloudClient
from ...constants import TELIT_APP_ID, TELIT_DATETIME_FORMAT
from typing import Callable, Dict
import json


class TelitAdapter(Adapter):
    def __init__(self, config: dict) -> None:
        super().__init__(config)

    def configure(self, config: dict) -> CloudClient:
        """Configure the Telit cloud adapter

        @param config: configuration string
        @exception AdapterConfigureError: If adapter configuration fails
        """
        publish_topic = "api/{request_id}"
        config = {
            "mqtt": {
                "username": config.get("key"),
                "password": config.get("token"),
                "hostname": config.get("hostname"),
                "port": config.get("port"),
                "client_id": TELIT_APP_ID,
            },
            "proxy": {
                "auto": True
            },
            "tls": {
                "version": "TLSv1.2"
            },
            "event": {
                "pub": publish_topic,
                "format": json.dumps({
                    "cmd": {
                        "command": "log.publish",
                        "params": {
                            "thingKey": "{username}",
                            "msg": "{value}"
                        }
                    }
                })
            },
            "telemetry": {
                "pub": publish_topic,
                "format": json.dumps({
                    "cmd": {
                        "command": "property.publish",
                        "params": {
                            "thingKey": "{username}",
                            "key": "{key}",
                            "value": "{value}",
                            "ts": "{timestamp=" + TELIT_DATETIME_FORMAT + "}"
                        }
                    }
                })
            },
            "attribute": {
                "pub": publish_topic,
                "format": json.dumps({
                    "cmd": {
                        "command": "attribute.publish",
                        "params": {
                            "thingKey": "{username}",
                            "key": "{key}",
                            "value": "{value}"
                        }
                    }
                })
            },
            "method": {
                "pub": publish_topic,
                "format": json.dumps({
                    "cmd": {
                        "command": "mailbox.ack",
                        "params": {
                            "id": "{execution_id}",
                            "thingKey": "{username}",
                            "params": {
                                "Time": "{timestamp}",
                                "Response": "{message}"
                            }
                        }
                    }
                }),
                "sub": "reply/#",
                "parse": {
                    "aggregate": {
                        "path": "cmd/params/messages"
                    },
                    "single": {
                        "method": {
                            "path": "params/method"
                        },
                        "args": {
                            "path": "params/params"
                        },
                        "execution_id": {
                            "path": "id"
                        }
                    }
                }
            },
            "echoers": [{
                "sub": "notify/mailbox_activity",
                "pub": publish_topic,
                "format": json.dumps({
                    "cmd": {
                        "command": "mailbox.check",
                        "params": {
                            "autoComplete": False
                        }
                    }
                })
            }]
        }

        try:
            return build_client_with_config(config)
        except ClientBuildError as e:
            raise AdapterConfigureError(str(e))

    def _parse_payload(self, payload: Dict) -> Dict:
        """Update the payload keys to match internally used ones

        @param payload: (dict) The payload dict
        @return:        (dict) The modified payload dict
        """

        update_manifest_tag_name = {
            'vv_username': 'username',
            'vw_password': 'password',
            'vx_docker_registry': 'dockerRegistry',
            'vy_docker_username': 'dockerUsername',
            'vz_docker_password': 'dockerPassword'
        }

        for key in update_manifest_tag_name.keys():
            if key in payload:
                payload[update_manifest_tag_name[key]] = payload.pop(key)

        return payload

    def bind_callback(self, name: str, callback: Callable) -> None:
        def callback_wrapper(**payload):
            payload = self._parse_payload(payload)
            return callback(**payload)
        self._client.bind_callback(name, callback_wrapper)
