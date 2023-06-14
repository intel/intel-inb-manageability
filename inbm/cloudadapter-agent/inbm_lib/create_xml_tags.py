"""Creates XML formatted tags.

    @copyright: Copyright 2021-2023 Intel Corporation All Rights Reserved.
    @license: Intel, see licenses/LICENSE for more details.
"""
from typing import Dict
from inbm_common_lib.utility import clean_input


def create_xml_tags(tags: Dict[str, str], *names: str) -> str:
    """Creates XML formatted tags.

    @param tags:    The tags dict from which to get a tag value
    @param names: (*args: str) The names of the desired tags
    @return:      The accompanying message
    """
    xml = ''
    for name in names:
        value = tags.get(name)
        if value is not None:
            sanitized_value = clean_input(value)
            xml += "<{0}>{1}</{0}>".format(name, sanitized_value)
    return xml
