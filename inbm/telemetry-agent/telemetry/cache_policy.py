"""
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


from future import standard_library
from typing import List, Any
standard_library.install_aliases()


def trim_cache(input_collection: List[Any], max_cache_size: int) -> List[Any]:
    """Trims the telemetry data about to be sent to a maximum size before sending.
    It will take the latest items from the collection up to the specified max cache size.

    @param input_collection: telemetry data
    @param max_cache_size: maximum cache size allowed
    @return: Telemetry data to be sent that has an array equal or less than the specified
    max cache size.
    """
    if max_cache_size < 0:
        raise ValueError
    if len(input_collection) <= max_cache_size:
        return input_collection

    return input_collection[-max_cache_size:]
