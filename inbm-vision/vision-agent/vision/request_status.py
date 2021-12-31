"""
    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


from enum import Enum


class RequestStatus(Enum):
    """Enum containing Request status in Vision-agent"""
    (
        NoneState,
        SendDownloadRequest,
        SendFile,
        SendManifest,
        RequestComplete,
        Error
    ) = range(6)
