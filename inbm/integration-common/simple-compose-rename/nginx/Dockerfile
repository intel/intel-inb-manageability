# Copyright (c) 2021-2024 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

FROM registry.hub.docker.com/library/nginx:1.27.5

# Create and switch to non-root user
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser
RUN chown -R appuser:appgroup /app
USER appuser

COPY content.txt /usr/share/nginx/html

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD curl -f http://localhost/ || exit 1
