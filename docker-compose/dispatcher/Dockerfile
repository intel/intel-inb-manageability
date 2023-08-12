# Copyright (C) 2021-2023 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

FROM ubuntu:22.04 as untar
COPY ../Intel-Manageability.preview.tar.gz /src/Intel-Manageability.preview.tar.gz
WORKDIR /src/
RUN tar zxvf Intel-Manageability.preview.tar.gz

FROM ubuntu:22.04 as final
ARG http_proxy
ARG https_proxy
ARG no_proxy
ENV http_proxy=$http_proxy https_proxy=$https_proxy no_proxy=$no_proxy
ENV container docker
RUN apt-get update && apt-get install -y lxc curl
RUN curl -fsSLO https://download.docker.com/linux/static/stable/x86_64/docker-24.0.5.tgz \
    && tar xzvf docker-24.0.5.tgz \
    && mv docker/docker /usr/bin \
    && rm -r docker docker-24.0.5*
RUN mkdir /debs
COPY --from=untar /src/inbm-dispatcher*.deb /debs
COPY --from=untar /src/trtl*.deb /debs
COPY --from=untar /src/inbc*.deb /debs
WORKDIR /debs
RUN dpkg -i ./inbm-dispatcher*.deb ./trtl*.deb ./inbc*.deb
RUN sed -i "s/ERROR/DEBUG/g" /etc/intel-manageability/public/dispatcher-agent/logging.ini
COPY wait-for-certs.sh /wait-for-certs.sh
RUN chmod +x /wait-for-certs.sh
ENTRYPOINT [ "/wait-for-certs.sh", "/usr/bin/inbm-dispatcher" ]

