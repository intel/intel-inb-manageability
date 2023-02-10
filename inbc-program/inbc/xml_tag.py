""" Creates XML formatted tags.

    Copyright (C) 2020-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from typing import Dict
from inbm_common_lib.utility import clean_input
from .constants import FOTA_SIGNATURE, SIGNATURE


def create_xml_tag(tags: Dict[str, str], *names: str) -> str:
    """Creates XML formatted tags.

    @param tags:    The tags dict from which to get a tag value
    @param names: (*args: str) The names of the desired tags
    @return:      The accompanying message
    """
    xml = ''
    for name in names:
        val = tags.get(name)
        name = name[0].lower() + name[1:]
        if val is not None:
            val = clean_input(val)
            xml += create_signature_tag(val, name)
    return xml


def create_signature_tag(val: str, name: str) -> str:
    """Creates XML formatted tags for signature.

    @param val:    value of tag
    @param name: name of tag
    @return:      The xml tag
    """
    if name == FOTA_SIGNATURE or name == SIGNATURE:
        return "<signature>{0}</signature>".format(val) if val != "None" else ""
    else:
        return "<{0}>{1}</{0}>".format(name, val)
