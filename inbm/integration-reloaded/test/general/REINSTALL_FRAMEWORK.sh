#!/bin/bash

set -euxo pipefail

cd /vagrant/input

# Simulate user calling the installer
rm -rf "install TC"
mkdir -p "install TC" # test install dir with spaces
cd "install TC"
cp ../*.preview.tar.gz .
cp ../*-tc.sh .

ACCEPT_INTEL_LICENSE=true bash -x ./uninstall-tc.sh

INSTALL_TPM2_SIMULATOR=false ACCEPT_INTEL_LICENSE=true bash -x ./install-tc.sh

cp /scripts/iotg_inb_developer.conf /etc/intel_manageability.conf
cp /scripts/inb_fw_tool_info.conf /etc/firmware_tool_info.conf

touch /etc/intel-manageability/public/cloudadapter-agent/iot-dispatcher.cfg

# don't connect to Telit in Integration Reloaded
NO_CLOUD=1 PROVISION_TPM=disable NO_OTA_CERT=1 TELIT_HOST="localhost" bash -x /usr/bin/provision-tc

# we don't connect to Telit in Integration Reloaded so we don't expect
# cloudadapter-agent to function (it primarily connects to Telit)
systemctl disable inbm-cloudadapter
systemctl stop inbm-cloudadapter

sleep 3

ps -G dispatcher-agent | grep dispatcher
ps -G telemetry-agent | grep telemetry
ps -G configuration-agent | grep configur
ps -G diagnostic-agent | grep diagnos
ps -G mqtt-broker | grep mosquitto

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

systemctl start mqtt inbm
systemctl disable inbm-cloudadapter
systemctl stop inbm-cloudadapter

for i in cloudadapter dispatcher telemetry configuration diagnostic ; do
  sed -i 's/ERROR/DEBUG/g' /etc/intel-manageability/public/"$i-agent"/logging.ini
done
