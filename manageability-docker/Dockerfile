FROM ubuntu:18.04 as base
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
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y mosquitto cryptsetup openssl dmidecode dbus vim net-tools rsyslog libffi-dev pciutils lxc-common dkms && \
    apt-get clean && \ 
    rm -rf /var/lib/apt/lists/*

# Set the container running as systemd
RUN find /etc/systemd/system \
    /lib/systemd/system \
    -path '*.wants/*' \
    -not -name '*journald*' \
    -not -name '*systemd-tmpfiles*' \
    -not -name '*systemd-user-sessions*' \
    -exec rm \{} \;

RUN systemctl set-default multi-user.target


STOPSIGNAL SIGRTMIN+3

# Install TC artifacts within the container
COPY ./Intel-Manageability.preview.tar.gz /src/Intel-Manageability.preview.tar.gz

RUN mkdir -p /etc/intel-manageability/public/
RUN mkdir -p /etc/intel-manageability/secret/
COPY ./adapter.cfg /src/adapter.cfg
COPY ./thingsboard.pub.pem /src/thingsboard.pub.pem
RUN touch /etc/intel-manageability/public/tpm_flag
RUN echo FALSE >> /etc/intel-manageability/public/tpm_flag
RUN tar -zxvf *.preview.tar.gz
RUN dpkg --force-all -i ./mqtt*.deb
RUN dpkg -i ./inbm-dispatcher*.deb
RUN dpkg -i ./inbm-diagnostic*.deb
RUN dpkg -i ./inbm-configuration*.deb
RUN dpkg -i ./inbm-cloudadapter*.deb
RUN dpkg -i ./inbm-telemetry*.deb
RUN dpkg -i ./trtl*.deb
RUN groupadd -f mqtt-broker
RUN groupadd -f dispatcher-agent
RUN groupadd -f telemetry-agent
RUN groupadd -f configuration-agent
RUN groupadd -f cloudadapter-agent
RUN groupadd -f diagnostic-agent
RUN mkdir -p /var/persistent-log/mosquitto
RUN chgrp mqtt-broker /var/persistent-log/mosquitto
RUN chmod g+rwx /var/persistent-log/mosquitto
RUN chmod -R g+rw /var/persistent-log/mosquitto
RUN systemctl enable mqtt inbm inbm-dispatcher inbm-diagnostic inbm-cloudadapter inbm-configuration inbm-telemetry

COPY ./cloud_source /src/cloud_source
RUN sed -i '/^ExecStart=.*/a ExecStartPost=/src/cloud_source' /lib/systemd/system/mqtt.service

CMD ["/sbin/init"]
