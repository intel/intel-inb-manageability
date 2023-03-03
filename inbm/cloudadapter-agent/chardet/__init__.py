# dummy chardet
"""
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
from typing import Dict

__version__ = '3.0.4'


def detect(content: str) -> Dict[str, str]:
    return {'encoding': 'utf-8'}
