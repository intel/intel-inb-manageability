# Copyright (c) 2021-2025 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

FROM registry.hub.docker.com/library/nginx:1.26.1

COPY content.txt /usr/share/nginx/html

# Create non-root user
RUN groupadd --system appgroup && useradd --system --gid appgroup appuser
RUN mkdir -p /home/appuser && chown -R appuser:appgroup /home/appuser

# Switch to non-root user for running the app
USER appuser

# (Optional) Set workdir for the user
WORKDIR /home/appuser

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
 CMD curl -f http://localhost/ || exit 1
