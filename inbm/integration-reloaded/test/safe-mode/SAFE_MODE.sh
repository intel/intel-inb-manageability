#!/bin/bash
set -e
set -x

source /scripts/test_util.sh

trap 'kill -9 $(jobs -p) || true'  EXIT

test_failed() {
   echo "Return code: $?"
   echo "TEST FAILED!!!"
   show_certs
}
trap test_failed ERR

show_certs() {
    ls -la /etc/intel-manageability/secret/mqtt-broker/ || true
    ls -la /etc/intel-manageability/public/mqtt-broker/ || true
    ls -la /etc/intel-manageability/secret/mqtt-ca/ || true
    ls -la /etc/intel-manageability/public/mqtt-ca/ || true
    mount
}

echo "Starting safe mode test." | systemd-cat


TC_PUBLIC="/etc/intel-manageability/public"
TC_SECRET="/etc/intel-manageability/secret"
SECRET_FILE="/var/intel-manageability/secret.img"

systemctl stop mqtt # this should also stop all the agents

: Unmounting secret directory.
umount "$TC_SECRET"

sync
sleep 1

: Closing secret crypt device.
cryptsetup -v close /dev/mapper/intel-manageability-secret || true

systemctl stop tpm2-simulator tpm2-abrmd
echo Before safe mode --
show_certs
systemctl start mqtt
echo After safe mode --
show_certs
[ -f "$TC_SECRET"/.provisioned ]
[ -f "$TC_SECRET"/SAFE_MODE ]
systemctl stop mqtt
umount "$TC_SECRET"
umount "$TC_PUBLIC"

systemctl start tpm2-simulator
systemctl start tpm2-abrmd
systemctl start mqtt inbm
[ -f "$TC_SECRET"/.provisioned ]
