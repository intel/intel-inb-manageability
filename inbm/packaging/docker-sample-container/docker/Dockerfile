# Copyright (c) 2021-2024 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

FROM registry.hub.docker.com/library/ubuntu:20.04

# Create a non-root user and group
RUN groupadd --system appgroup && useradd --system --gid appgroup appuser

USER appuser

ENTRYPOINT sleep infinity

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD curl -f http://localhost/ || exit 1
