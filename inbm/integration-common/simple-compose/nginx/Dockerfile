# Copyright (c) 2021-2024 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

FROM registry.hub.docker.com/library/nginx:latest

COPY content.txt /usr/share/nginx/html

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
 CMD curl -f http://localhost/ || exit 1

USER nginx