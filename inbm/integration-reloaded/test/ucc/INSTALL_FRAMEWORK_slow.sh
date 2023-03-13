#!/bin/bash

set -euxo pipefail

cd /vagrant/input
cp /scripts/succeed_rpm_cert.pem .

# Update apt database
apt-get update

# Remove/uninstall prereqs to ensure installer deals with them
apt-get purge -y --allow-change-held-packages lxc mosquitto cryptsetup less docker-compose

# Simulate user calling the installer
mkdir "install TC" # test install dir with spaces
cd "install TC"
cp ../*.preview.tar.gz .
cp ../*-tc.sh .
rm -rf /etc/intel-manageability/public/cloudadapter-agent
mkdir -p /etc/intel-manageability/public/cloudadapter-agent
apt-get purge -y docker-ce docker-ce-cli || true
rm -rf /var/lib/apt/lists/*
sudo -H UCC_MODE=true ACCEPT_INTEL_LICENSE=true bash -x ./install-tc.sh

date

for i in cloudadapter ; do
  sed -i 's/ERROR/DEBUG/g' /etc/intel-manageability/public/"$i"-agent/logging.ini
done


cp /scripts/iotg_inb_developer.conf /etc/intel_manageability.conf
cp /scripts/inb_fw_tool_info.conf /etc/firmware_tool_info.conf
touch /etc/intel-manageability/public/cloudadapter-agent/iot-dispatcher.cfg
sudo -H NO_CLOUD=x PROVISION_TPM=disable NO_OTA_CERT=1 LOCAL_MQTT_PORT=9999 bash -x /usr/bin/provision-tc

touch /etc/intel-manageability/public/cloudadapter-agent/iot-dispatcher.cfg

sleep 5
ps -G cloudadapter-agent | grep cloudadapter

for i in /etc/intel-manageability/secret/* ; do
    BASENAME="$(basename $i)"
    if ! [ "$BASENAME" == "lost+found" ] ; then
        : Check permissions of "$i"
        stat -c %A "$i" | egrep -- "^drwxr-x---$"

        : Check group of "$i"
        stat -c %G "$i" | egrep -- "^$BASENAME$"

        : Check owner of "$i"
        stat -c %U "$i" | egrep -- "^root$"
    fi
done

systemctl disable mqtt-keygen || true
rm -rf /lib/systemd/system/mqtt-keygen.service

systemctl start mqtt inbm-cloudadapter
