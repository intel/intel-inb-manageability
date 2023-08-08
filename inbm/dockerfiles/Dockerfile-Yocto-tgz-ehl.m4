# Copyright (c) 2021-2023 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

include(`image.ehl.m4')

FROM ubuntu:20.04 as output-yocto
COPY --from=output-ehl /output /ehl
RUN mkdir -p /output && \
    cp -rv \
    /ehl/* \
    /output

