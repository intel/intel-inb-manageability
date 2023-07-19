# Copyright (C) 2021-2023 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

FROM jrei/systemd-ubuntu:22.04
WORKDIR /src/

ENV container docker

# Set the proxy environment
RUN if [ ! -z "$http_proxy" ]; then echo "container=docker" >> /etc/environment; fi
RUN if [ ! -z "$http_proxy" ]; then echo "http_proxy=$http_proxy" >> /etc/environment; fi
RUN if [ ! -z "$https_proxy" ]; then echo "https_proxy=$https_proxy" >> /etc/environment; fi
RUN if [ ! -z "$HTTP_PROXY" ]; then echo "HTTP_PROXY=$HTTP_PROXY" >> /etc/environment; fi
RUN if [ ! -z "$HTTPS_PROXY" ]; then echo "HTTPS_PROXY=$HTTPS_PROXY" >> /etc/environment; fi
RUN if [ ! -z "$NO_PROXY" ]; then echo "NO_PROXY=$NO_PROXY" >> /etc/environment; fi
RUN if [ ! -z "$no_proxy" ]; then echo "no_proxy=$no_proxy" >> /etc/environment; fi

# Install required packages
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y upgrade && DEBIAN_FRONTEND=noninteractive apt-get install -y mosquitto openssl dmidecode dbus net-tools rsyslog libffi-dev pciutils lxc udev && \
    apt-get clean && \ 
    rm -rf /var/lib/apt/lists/*

# Install TC artifacts within the container
COPY ./Intel-Manageability.preview.tar.gz /src/Intel-Manageability.preview.tar.gz
COPY ./adapter.cfg /src/adapter.cfg

RUN mkdir -p /etc/intel-manageability/public/ \
&& mkdir -p /etc/intel-manageability/secret/ \
&& touch /etc/intel-manageability/public/tpm_flag \
&& echo FALSE >> /etc/intel-manageability/public/tpm_flag \
&& tar -zxvf *.preview.tar.gz \
&& dpkg --force-all -i ./mqtt*.deb \
&& dpkg -i ./inbm-dispatcher*.deb \
&& dpkg -i ./inbm-diagnostic*.deb \
&& dpkg -i ./inbm-configuration*.deb \
&& dpkg -i ./inbm-cloudadapter*.deb \
&& dpkg -i ./inbm-telemetry*.deb \
&& dpkg -i ./trtl*.deb \
&& dpkg -i ./inbc-program*.deb \
&& groupadd -f mqtt-broker \
&& groupadd -f dispatcher-agent \
&& groupadd -f telemetry-agent \
&& groupadd -f configuration-agent \
&& groupadd -f cloudadapter-agent \
&& groupadd -f diagnostic-agent \
&& mkdir -p /var/persistent-log/mosquitto \
&& chgrp mqtt-broker /var/persistent-log/mosquitto \
&& chmod g+rwx /var/persistent-log/mosquitto \
&& chmod -R g+rw /var/persistent-log/mosquitto  \
&& mkdir -p /var/cache/manageability/repository-tool/sota
RUN sed -i 's/ERROR/DEBUG/g' /etc/intel-manageability/public/dispatcher-agent/logging.ini
RUN systemctl enable mqtt inbm inbm-dispatcher inbm-diagnostic inbm-cloudadapter inbm-configuration inbm-telemetry 
COPY ./cloud_source /src/cloud_source
RUN sed -i '/^ExecStart=.*/a ExecStartPost=/src/cloud_source' /lib/systemd/system/mqtt.service
RUN sed -i 's/^[ \t]*docker[ \t]*$//g' /etc/intel_manageability.conf
RUN mkdir -p /var/certs
COPY docker-socket.service /etc/systemd/system/docker-socket.service
RUN systemctl enable docker-socket

# If thingsboard.pub.pem exist, copy it to container
COPY ./thingsboard.pub.pe[m] /src/thingsboard.pub.pem

# If client.nopass.pem(device x509 cert) exist, copy it to container
COPY ./client.nopass.pe[m] /src/client.nopass.pem
