# Copyright (C) 2021-2023 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

# This is a Dockerfile to make a single image that could launch
# any of the INBM services. The service to run is passed in via
# the startup command via docker-compose. For example, to start
# dispatcher agent, command will be /usr/bin/inbm-dispatcher.
#  It can also be used to launch a container with the inbc
# environment. The CMD here would be /keep-container-running.sh

FROM ubuntu:22.04 as untar
COPY ../Intel-Manageability.preview.tar.gz /src/Intel-Manageability.preview.tar.gz
WORKDIR /src/
RUN tar zxvf Intel-Manageability.preview.tar.gz

FROM ubuntu:22.04 as final
ARG http_proxy https_proxy no_proxy HTTP_PROXY HTTPS_PROXY NO_PROXY
ENV http_proxy=$http_proxy https_proxy=$https_proxy no_proxy=$no_proxy HTTP_PROXY=$HTTP_PROXY HTTPS_PROXY=$HTTPS_PROXY NO_PROXY=$NO_PROXY
ENV container docker
RUN apt-get update && apt-get install -y lxc curl && rm -rf /var/lib/apt/lists/*
RUN curl -fsSLO https://download.docker.com/linux/static/stable/x86_64/docker-24.0.5.tgz \
    && tar xzvf docker-24.0.5.tgz \
    && mv docker/docker /usr/bin \
    && rm -r docker docker-24.0.5*
RUN mkdir /debs
COPY --from=untar /src/inbm-dispatcher*.deb /debs
COPY --from=untar /src/inbm-configuration*.deb /debs
COPY --from=untar /src/inbm-telemetry*.deb /debs
COPY --from=untar /src/inbm-diagnostic*.deb /debs
COPY --from=untar /src/trtl*.deb /debs
COPY --from=untar /src/inbc*.deb /debs
WORKDIR /debs
RUN dpkg -i ./inbm-dispatcher*.deb ./inbm-configuration*.deb ./inbm-telemetry*.deb ./inbm-diagnostic*.deb ./trtl*.deb ./inbc*.deb
RUN sed -i "s/ERROR/DEBUG/g" /etc/intel-manageability/public/*-agent/logging.ini
COPY scripts/keep-container-running.sh /keep-container-running.sh
COPY scripts/wait-for-certs.sh /wait-for-certs.sh
RUN chmod +x /wait-for-certs.sh
ENTRYPOINT [ "/wait-for-certs.sh" ]
CMD [ "echo", "needs startup cmd passed into container"]
