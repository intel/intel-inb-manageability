# Copyright (c) 2021-2023 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

include(`image.kmb.m4')

FROM ubuntu:20.04 as output-yocto
COPY --from=output-kmb /output /kmb
RUN mkdir -p /output && \
    cp -rv \
    /kmb/* \
    /output

