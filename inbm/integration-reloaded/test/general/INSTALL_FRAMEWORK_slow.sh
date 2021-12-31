#!/bin/bash

set -euxo pipefail

cd /vagrant/input
cp /scripts/succeed_rpm_cert.pem .

# Remove/uninstall prereqs to ensure installer deals with them
apt-get purge -y --allow-change-held-packages lxc-common mosquitto cryptsetup less docker-compose docker.io

# Simulate user calling the installer
mkdir "install TC" # test install dir with spaces
cd "install TC"
cp ../*.preview.tar.gz .
cp ../*-tc.sh .
rm -rf /etc/intel-manageability/public/cloudadapter-agent
mkdir -p /etc/intel-manageability/public/cloudadapter-agent
apt-get purge -y docker-ce docker-ce-cli || true
rm -rf /var/lib/apt/lists/*
sudo -H ACCEPT_INTEL_LICENSE=true bash -x ./install-tc.sh

echo "Will install TPM Simulator"
if [ "$(lsb_release -rs)" == "20.04" ]; then
  dpkg -i ../tpm2-simulator20.04-0.1332-1.deb
  sed -i -e 's#ConditionPathExistsGlob=/dev/tpm.##g' /lib/systemd/system/tpm2-abrmd.service
  sed -i -e 's#ExecStart=/usr/sbin/tpm2-abrmd#ExecStart=/usr/sbin/tpm2-abrmd --tcti=libtss2-tcti-mssim.so.0#g' /lib/systemd/system/tpm2-abrmd.service
else
  dpkg -i ../tpm2-simulator18.04-0.1332-1.deb
  sed -i -e 's#ExecStart=/usr/sbin/tpm2-abrmd#ExecStart=/usr/sbin/tpm2-abrmd --tcti=libtss2-tcti-mssim.so#g' /lib/systemd/system/tpm2-abrmd.service
fi

sed -i -e 's#After=dev-tpm0.device##g' /lib/systemd/system/tpm2-abrmd.service || true
sed -i -e 's#Requires=dev-tpm0.device##g' /lib/systemd/system/tpm2-abrmd.service || true

# Reload / Restart Services
systemctl daemon-reload
systemctl enable --now tpm2-simulator
systemctl restart tpm2-simulator
systemctl restart tpm2-abrmd

echo "Checking TPM simulator..."
sleep 1
tpm2_startup -c
tpm2_clear
/usr/bin/tc-get-tpm-passphrase >/dev/null

date

for i in cloudadapter dispatcher telemetry configuration diagnostic ; do
  sed -i 's/ERROR/DEBUG/g' /etc/intel-manageability/public/"$i"-agent/logging.ini
done


cp /scripts/iotg_inb_developer.conf /etc/intel_manageability.conf
cp /scripts/inb_fw_tool_info.conf /etc/firmware_tool_info.conf
touch /etc/intel-manageability/public/cloudadapter-agent/iot-dispatcher.cfg
# don't connect to Telit in Integration Reloaded
sudo -H NO_CLOUD=x PROVISION_TPM=enable NO_OTA_CERT=1 LOCAL_MQTT_PORT=9999 bash -x /usr/bin/provision-tc

cp /scripts/iotg_inb_developer.conf /etc/intel_manageability.conf
cp /scripts/inb_fw_tool_info.conf /etc/firmware_tool_info.conf
touch /etc/intel-manageability/public/cloudadapter-agent/iot-dispatcher.cfg
/usr/bin/tc-get-secret-passphrase 2>/dev/null | md5sum

# we don't connect to Telit in Integration Reloaded so we don't expect
# cloudadapter-agent to function (it primarily connects to Telit)
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

# Check to see if all TC agents are running in enforce mode or not
SERVICE="sudo aa-status"
APPARMOR_PROFILES=`${SERVICE}`
ENFORCE_MODE_PROCESS=${APPARMOR_PROFILES#*"processes are in enforce mode."}
PROCESS=${APPARMOR_PROFILES%"$ENFORCE_MODE_PROCESS"}

RESULT2=${ENFORCE_MODE_PROCESS}

if  [[ "$ENFORCE_MODE_PROCESS" == *"/usr/bin/inbm-dispatcher"* ]] && [[ "$ENFORCE_MODE_PROCESS" == *"/usr/bin/inbm-diagnostic"* ]] && [[ "$ENFORCE_MODE_PROCESS" == *"/usr/bin/inbm-telemetry"* ]] && [[ "$ENFORCE_MODE_PROCESS" == *"/usr/bin/inbm-configuration"* ]]; then
	echo " TC- agents [dispatcher, diagnostic, configuration, telemetry] are running in enforce mode"
else
	echo "TC- agents [dispatcher, diagnostic, configuration, telemetry] are not running in enforce mode"
	exit 1
fi

systemctl disable mqtt-keygen || true
rm -rf /lib/systemd/system/mqtt-keygen.service

systemctl start mqtt inbm
systemctl disable inbm-cloudadapter
systemctl stop inbm-cloudadapter

# Disable TPM lockout for integration testing.
tpm2_dictionarylockout --setup-parameters --max-tries=4294967295 --clear-lockout
