# Copyright (C) 2021-2023 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

# This is a Dockerfile to make a single image that could launch
# any of the INBM services. The service to run is passed in via
# the startup command via docker-compose. For example, to start
# dispatcher agent, command will be /usr/bin/inbm-dispatcher.
#  It can also be used to launch a container with the inbc
# environment. The CMD here would be /keep-container-running.sh

FROM debian:bookworm-slim as fetch
COPY ../Intel-Manageability.preview.tar.gz /src/Intel-Manageability.preview.tar.gz
WORKDIR /src/
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
RUN curl -fsSLO https://download.docker.com/linux/static/stable/x86_64/docker-24.0.5.tgz \
    && tar xzvf docker-24.0.5.tgz \
    && mv docker/docker /usr/bin \
    && rm -r docker docker-24.0.5*
RUN tar zxvf Intel-Manageability.preview.tar.gz
RUN dpkg -X /src/inbm-dispatcher*.deb /extract
RUN dpkg -X /src/inbm-configuration*.deb /extract
RUN dpkg -X /src/inbm-telemetry*.deb /extract
RUN dpkg -X /src/inbm-diagnostic*.deb /extract
RUN dpkg -X /src/trtl*.deb /extract
RUN dpkg -X /src/inbc*.deb /extract
RUN sed -i "s/ERROR/DEBUG/g" /extract/etc/intel-manageability/public/*-agent/logging.ini
# lib is a symlink in debian/ubuntu
RUN mv /extract/lib/* /extract/usr/lib && rm -rf /extract/lib

FROM debian:bookworm-slim as final
ARG http_proxy https_proxy no_proxy HTTP_PROXY HTTPS_PROXY NO_PROXY
ENV http_proxy=$http_proxy https_proxy=$https_proxy no_proxy=$no_proxy HTTP_PROXY=$HTTP_PROXY HTTPS_PROXY=$HTTPS_PROXY NO_PROXY=$NO_PROXY
ENV container docker
COPY --from=fetch /usr/bin/docker /usr/bin/docker
COPY --from=fetch /extract /
COPY scripts/keep-container-running.sh /keep-container-running.sh
COPY scripts/wait-for-certs.sh /wait-for-certs.sh
RUN chmod +x /wait-for-certs.sh
ENTRYPOINT [ "/wait-for-certs.sh" ]
CMD [ "echo", "needs startup cmd passed into container"]
