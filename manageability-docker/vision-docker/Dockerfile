FROM jrei/systemd-ubuntu:20.04 as base
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
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y upgrade && DEBIAN_FRONTEND=noninteractive apt-get install -y mosquitto cryptsetup openssl dmidecode dbus vim net-tools rsyslog libffi-dev pciutils lxc dkms libglib2.0 libssl1.0 udev docker.io openssh-server wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN systemctl disable docker
RUN systemctl set-default multi-user.target

COPY ./Intel-Manageability.preview.tar.gz /src/Intel-Manageability.preview.tar.gz
COPY ./*.deb /src/
COPY ./adapter.cfg /src/adapter.cfg
RUN mkdir -p /etc/intel-manageability/public
RUN mkdir -p /etc/intel-manageability/secret
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
RUN mkdir -p /lib/firmware/intel-flashless
RUN mkdir -p /cache
RUN dpkg -i ./inbc-program*.deb
RUN dpkg -i ./inbm-vision-agent-*.deb
RUN sed -i 's/level=ERROR/level=DEBUG/g' /etc/intel-manageability/public/*/logging.ini
RUN sed -i -z 's|docker||1' /etc/intel_manageability.conf
RUN sed -i -z 's|inbm-telemetry||1' /etc/intel_manageability.conf
RUN groupadd -f mqtt-broker
RUN groupadd -f dispatcher-agent
RUN groupadd -f telemetry-agent
RUN groupadd -f configuration-agent
RUN groupadd -f cloudadapter-agent
RUN groupadd -f diagnostic-agent
RUN groupadd -f vision-agent
RUN groupadd -f inbc-program
RUN mkdir -p /var/persistent-log/mosquitto
RUN chgrp mqtt-broker /var/persistent-log/mosquitto
RUN chmod g+rwx /var/persistent-log/mosquitto
RUN chmod -R g+rw /var/persistent-log/mosquitto
RUN chgrp vision-agent /lib/firmware/flashless_backup
RUN chmod g+rw /lib/firmware/flashless_backup
# Install pms
RUN dpkg -i pms-host*.deb

# Link RM/RAS socket 
RUN ln -sf /host/var/rm-daemon /var/rm-daemon
RUN ln -sf /host/var/rm-daemon-notify /var/rm-daemon-notify

#COPY pem file
COPY ./dummy.file ./ota_signature_cert.pem* /etc/intel-manageability/public/dispatcher-agent/

RUN systemctl enable mqtt inbm inbm-dispatcher inbm-diagnostic inbm-cloudadapter inbm-configuration inbm-telemetry inbm-vision
COPY ./cloud_source /src/cloud_source
RUN sed -i '/^ExecStart=.*/a ExecStartPost=/src/cloud_source' /lib/systemd/system/mqtt.service

CMD ["/sbin/init"]
