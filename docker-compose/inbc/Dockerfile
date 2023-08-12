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
RUN apt-get update && apt-get install -y lxc
RUN mkdir /debs
COPY --from=untar /src/inbc*.deb /debs
WORKDIR /debs
RUN dpkg -i ./inbc*.deb
COPY wait-for-certs.sh /wait-for-certs.sh
RUN chmod +x /wait-for-certs.sh
ENTRYPOINT [ "/wait-for-certs.sh", "sleep", "infinity" ] # inbc exists only to be execed into