# Copyright (c) 2021-2025 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

include(`image.kmb.m4')

FROM registry.hub.docker.com/library/ubuntu:20.04 AS output-yocto
COPY --from=output-kmb /output /kmb
RUN mkdir -p /output && \
    cp -rv \
    /kmb/* \
    /output

# Create and switch to non-root user
RUN groupadd --system appgroup && useradd --system --gid appgroup appuser
RUN chown -R appuser:appgroup /output
USER appuser
