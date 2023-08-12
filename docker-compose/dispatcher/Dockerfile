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
RUN apt-get update && apt-get install -y netcat-openbsd
RUN mkdir /debs
COPY --from=untar /src/inbm-dispatcher*.deb /debs
WORKDIR /debs
RUN dpkg -i --force-all ./inbm-dispatcher*.deb
RUN sed -i "s/ERROR/DEBUG/g" /etc/intel-manageability/public/dispatcher-agent/logging.ini
COPY wait-for-certs.sh /wait-for-certs.sh
RUN chmod +x /wait-for-certs.sh
ENTRYPOINT [ "/wait-for-certs.sh", "/usr/bin/inbm-dispatcher" ]

# ENV container docker

# # Set the proxy environment
# RUN if [ ! -z "$http_proxy" ]; then echo "container=docker" >> /etc/environment; fi
# RUN if [ ! -z "$http_proxy" ]; then echo "http_proxy=$http_proxy" >> /etc/environment; fi
# RUN if [ ! -z "$https_proxy" ]; then echo "https_proxy=$https_proxy" >> /etc/environment; fi
# RUN if [ ! -z "$HTTP_PROXY" ]; then echo "HTTP_PROXY=$HTTP_PROXY" >> /etc/environment; fi
# RUN if [ ! -z "$HTTPS_PROXY" ]; then echo "HTTPS_PROXY=$HTTPS_PROXY" >> /etc/environment; fi
# RUN if [ ! -z "$NO_PROXY" ]; then echo "NO_PROXY=$NO_PROXY" >> /etc/environment; fi
# RUN if [ ! -z "$no_proxy" ]; then echo "no_proxy=$no_proxy" >> /etc/environment; fi

# # Install required packages
# RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y upgrade && DEBIAN_FRONTEND=noninteractive apt-get install -y mosquitto cryptsetup openssl dmidecode dbus vim net-tools rsyslog libffi-dev pciutils lxc dkms libglib2.0 libssl1.0 udev docker.io docker-compose && \
#     apt-get clean && \ 
#     rm -rf /var/lib/apt/lists/*

# # Install TC artifacts within the container
# COPY ./Intel-Manageability.preview.tar.gz /src/Intel-Manageability.preview.tar.gz
# COPY ./adapter.cfg /src/adapter.cfg

# RUN mkdir -p /etc/intel-manageability/public/ \
# && mkdir -p /etc/intel-manageability/secret/ \
# && touch /etc/intel-manageability/public/tpm_flag \
# && echo FALSE >> /etc/intel-manageability/public/tpm_flag \
# && tar -zxvf *.preview.tar.gz \
# && dpkg --force-all -i ./mqtt*.deb \
# && dpkg -i ./inbm-dispatcher*.deb \
# && dpkg -i ./inbm-diagnostic*.deb \
# && dpkg -i ./inbm-configuration*.deb \
# && dpkg -i ./inbm-cloudadapter*.deb \
# && dpkg -i ./inbm-telemetry*.deb \
# && dpkg -i ./trtl*.deb \
# && groupadd -f mqtt-broker \
# && groupadd -f dispatcher-agent \
# && groupadd -f telemetry-agent \
# && groupadd -f configuration-agent \
# && groupadd -f cloudadapter-agent \
# && groupadd -f diagnostic-agent \
# && mkdir -p /var/persistent-log/mosquitto \
# && chgrp mqtt-broker /var/persistent-log/mosquitto \
# && chmod g+rwx /var/persistent-log/mosquitto \
# && chmod -R g+rw /var/persistent-log/mosquitto  \
# && mkdir -p /var/cache/manageability/repository-tool/sota
# RUN systemctl enable mqtt inbm inbm-dispatcher inbm-diagnostic inbm-cloudadapter inbm-configuration inbm-telemetry && \
# systemctl disable docker
# COPY ./cloud_source /src/cloud_source
# RUN sed -i '/^ExecStart=.*/a ExecStartPost=/src/cloud_source' /lib/systemd/system/mqtt.service
# RUN sed -i 's/^[ \t]*docker[ \t]*$//g' /etc/intel_manageability.conf
# RUN mkdir -p /var/certs

# # If thingsboard.pub.pem exist, copy it to container
# COPY ./thingsboard.pub.pe[m] /src/thingsboard.pub.pem

# # If client.nopass.pem(device x509 cert) exist, copy it to container
# COPY ./client.nopass.pe[m] /src/client.nopass.pem
