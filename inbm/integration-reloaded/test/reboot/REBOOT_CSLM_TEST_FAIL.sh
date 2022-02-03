#!/bin/bash
set -e
set -x

source /scripts/test_util.sh

mkdir -p /etc/opt/csl/csl-node
cp /scripts/test.py /usr/bin/test.py
cp /scripts/csl-agent.service /lib/systemd/system/csl-agent.service
cp /scripts/long-lived-token /etc/opt/csl/csl-node/.
cp /scripts/csl-manager /etc/opt/csl/csl-node/.
cp /scripts/csl-ca-cert.pem  /etc/.
cp /scripts/iotg_inb_bmp.conf /etc/intel_manageability.conf
systemctl restart inbm csl-agent
sleep 2

trap 'kill -9 $(jobs -p) || true'  EXIT

test_failed() {
   echo "Return code: $?"
   echo "TEST FAILED!!!"
}
trap test_failed ERR

echo "Starting reboot test." | systemd-cat

GOOD_XML='<?xml version="1.0" encoding="UTF-8"?><manifest><type>cmd</type><cmd>restart</cmd></manifest>'

test_echo RUNNING REBOOT CSLM TEST FAIL
trigger_ota "${GOOD_XML}"
sleep 1
if ! listen_ota | tee /tmp/ota.txt | grep 400 ; then
  echo "listen_ota output did not contain 400: " $(cat /tmp/ota.txt)
fi
systemctl stop csl-agent
systemctl disable csl-agent
rm -rf /etc/opt/csl/csl-node/*
clean_up_subscribe
