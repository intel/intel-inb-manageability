"""
    Intel Manageability path prefixes

    @copyright: Copyright 2017-2023 Intel Corporation All Rights Reserved.
    @license: SPDX-License-Identifier: Apache-2.0
"""

import platform
from pathlib import Path

if platform.system() == 'Windows':
    C_COLON = Path("c:\\")
    INBM_PATH = C_COLON / 'intel-manageability' / 'inbm'
    BROKER_ETC_PATH = C_COLON / 'intel-manageability' / 'broker' / 'etc'
    INTEL_MANAGEABILITY_RAW_ETC = INBM_PATH / 'etc'
    INTEL_MANAGEABILITY_ETC_PATH_PREFIX = INBM_PATH / 'etc'
    INTEL_MANAGEABILITY_VAR_PATH_PREFIX = INBM_PATH / 'var'
    INTEL_MANAGEABILITY_SHARE_PATH_PREFIX = INBM_PATH / 'usr' / 'share'
    INTEL_MANAGEABILITY_CACHE_PATH_PREFIX = INBM_PATH / 'cache'
    INTEL_MANAGEABILITY_BINARY_SEARCH_PATHS = [
        C_COLON / 'Windows' / 'System32' / 'wbem']  # wmic tool
else:
    ROOT = Path('/')
    INTEL_MANAGEABILITY_RAW_ETC = ROOT / 'etc'
    INTEL_MANAGEABILITY_ETC_PATH_PREFIX = ROOT / 'etc' / 'intel-manageability'
    BROKER_ETC_PATH = INTEL_MANAGEABILITY_ETC_PATH_PREFIX
    INTEL_MANAGEABILITY_VAR_PATH_PREFIX = ROOT / 'var' / 'intel-manageability'
    INTEL_MANAGEABILITY_SHARE_PATH_PREFIX = ROOT / 'usr' / 'share'
    INTEL_MANAGEABILITY_CACHE_PATH_PREFIX = ROOT / 'var' / 'cache' / 'manageability'
    INTEL_MANAGEABILITY_BINARY_SEARCH_PATHS = [ROOT / 'bin',
                                               ROOT / 'usr' / 'sbin',
                                               ROOT / 'usr' / 'bin',
                                               ROOT / 'sbin']
