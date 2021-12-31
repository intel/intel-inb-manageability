"""
    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import platform
from pathlib import Path

if platform.system() == 'Windows':
    C_COLON = Path("c:\\")
    BROKER_ETC_PATH = C_COLON / 'intel-manageability' / 'broker' / 'etc'
    BIT_CREEK_PATH = C_COLON / 'intel-manageability' / 'inbm-vision'
    INBM_VISION_ETC_PATH_PREFIX = BIT_CREEK_PATH / 'etc'
    INBM_VISION_VAR_PATH_PREFIX = BIT_CREEK_PATH / 'var'
    INBM_VISION_SHARE_PATH_PREFIX = BIT_CREEK_PATH / 'usr' / 'share'
    INBM_VISION_CACHE_PATH_PREFIX = BIT_CREEK_PATH / 'var' / 'cache' / 'manageability'
    INBM_VISION_XLINK_PATH_PREFIX = BIT_CREEK_PATH / 'usr' / 'lib'
    INBM_VISION_XLINK_PROVISION_PATH_PREFIX = BIT_CREEK_PATH / 'usr' / 'lib64'
    INBM_VISION_USR_BIN_PREFIX = BIT_CREEK_PATH / 'usr' / 'bin'
    INBM_VISION_BINARY_SEARCH_PATHS = [
        C_COLON / 'Windows' / 'System32' / 'wbem']  # wmic tool
    INBM_VISION_XLINK_LIB_PATH = C_COLON / 'Program Files' / 'Intel' / 'XLink-Keembay' / 'XLink_DLL.dll'
    IS_WINDOWS = True


else:
    ROOT = Path('/')
    INBM_VISION_ETC_PATH_PREFIX = ROOT / 'etc' / 'intel-manageability'
    INBM_VISION_VAR_PATH_PREFIX = ROOT / 'var' / 'intel-manageability'
    INBM_VISION_SHARE_PATH_PREFIX = ROOT / 'usr' / 'share'
    INBM_VISION_CACHE_PATH_PREFIX = ROOT / 'var' / 'cache' / 'manageability'
    INBM_VISION_XLINK_PATH_PREFIX = ROOT / 'usr' / 'lib'
    INBM_VISION_XLINK_PROVISION_PATH_PREFIX = ROOT / 'usr' / 'lib64'
    INBM_VISION_USR_BIN_PREFIX = ROOT / 'usr' / 'bin'
    INBM_VISION_BINARY_SEARCH_PATHS = [ROOT / 'bin',
                                               ROOT / 'usr' / 'sbin',
                                               ROOT / 'usr' / 'bin',
                                               ROOT / 'sbin']
    INBM_VISION_XLINK_LIB_PATH = INBM_VISION_XLINK_PATH_PREFIX / 'libXLink.so'
    BROKER_ETC_PATH = INBM_VISION_ETC_PATH_PREFIX
    IS_WINDOWS = False
