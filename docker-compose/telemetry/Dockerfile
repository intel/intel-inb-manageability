# Copyright (C) 2021-2023 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

FROM ubuntu:22.04 as untar
COPY ../Intel-Manageability.preview.tar.gz /src/Intel-Manageability.preview.tar.gz
WORKDIR /src/
RUN tar zxvf Intel-Manageability.preview.tar.gz
RUN mkdir dispatcher-extract && dpkg -X inbm-dispatcher*.deb dispatcher-extract

FROM ubuntu:22.04 as final
ARG http_proxy
ARG https_proxy
ARG no_proxy
ENV http_proxy=$http_proxy https_proxy=$https_proxy no_proxy=$no_proxy
ENV container docker
RUN apt-get update && apt-get install -y lxc
RUN mkdir /debs
COPY --from=untar /src/inbm-telemetry*.deb /debs
# telemetry agent needs the manifest schema
COPY --from=untar /src/dispatcher-extract/usr/share/dispatcher-agent/manifest_schema.xsd /usr/share/dispatcher-agent/manifest_schema.xsd
WORKDIR /debs
RUN dpkg -i ./inbm-telemetry*.deb
RUN sed -i "s/ERROR/DEBUG/g" /etc/intel-manageability/public/telemetry-agent/logging.ini
COPY wait-for-certs.sh /wait-for-certs.sh
RUN chmod +x /wait-for-certs.sh
ENTRYPOINT [ "/wait-for-certs.sh", "/usr/bin/inbm-telemetry" ]