"""
    Masks passwords and user names in log files, etc.

    @copyright: Copyright 2017-2023 Intel Corporation All Rights Reserved.
    @license: SPDX-License-Identifier: Apache-2.0
"""


DOCKER_PASSWORD_TAG_BEGIN = '<dockerPassword>'  # noqa: S105
DOCKER_PASSWORD_TAG_END = '</dockerPassword>'  # noqa: S105

PASSWORD_TAG_BEGIN = '<password>'  # noqa: S105
PASSWORD_TAG_END = '</password>'  # noqa: S105

DOCKER_USERNAME_TAG_BEGIN = '<dockerUsername>'  # noqa: S105
DOCKER_USERNAME_TAG_END = '</dockerUsername>'  # noqa: S105

USERNAME_TAG_BEGIN = '<username>'
USERNAME_TAG_END = '</username>'

MASK = 'XXXXX'


def mask_security_info(payload: str) -> str:
    """Mask username and password in payload with XXXXX

    @param payload: Payload (XML)
    """
    masked = _mask_password(payload)
    return _mask_username(masked)


def _mask_password(payload: str) -> str:
    """Mask <password> and <dockerPassword> fields in payload with XXXXX.

    @param payload: Payload (XML)
    """
    assert isinstance(payload, str)
    i = payload.find(DOCKER_PASSWORD_TAG_BEGIN)
    e = payload.find(DOCKER_PASSWORD_TAG_END)
    remove_docker_pwd = payload[0:i + len(DOCKER_PASSWORD_TAG_BEGIN)] + MASK + payload[e:] \
        if i > 0 else payload

    s = payload.find(PASSWORD_TAG_BEGIN)
    t = payload.find(PASSWORD_TAG_END)
    return remove_docker_pwd[0:s + len(PASSWORD_TAG_BEGIN)] + MASK + remove_docker_pwd[t:] if \
        s > 0 else remove_docker_pwd


def _mask_username(payload: str) -> str:
    """Mask <username> and <dockerUsername> fields in payload with XXXXX.

    @param payload: Payload (XML)
    """
    assert isinstance(payload, str)
    i = payload.find(DOCKER_USERNAME_TAG_BEGIN)
    e = payload.find(DOCKER_USERNAME_TAG_END)
    remove_docker_username = payload[0:i + len(DOCKER_USERNAME_TAG_BEGIN)] + \
        MASK + payload[e:] if i > 0 else payload

    s = payload.find(USERNAME_TAG_BEGIN)
    t = payload.find(USERNAME_TAG_END)
    return remove_docker_username[0:s + len(USERNAME_TAG_BEGIN)] + MASK + \
        remove_docker_username[t:] if s > 0 else remove_docker_username
