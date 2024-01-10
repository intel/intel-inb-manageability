#!/bin/bash
set -euxo pipefail

source /scripts/test_util.sh

trap 'kill -9 $(jobs -p) || true'  EXIT

test_failed() {
   echo "Return code: $?"
   echo "TEST FAILED!!!"
}
trap test_failed ERR

echo "Starting APPLICATION UPDATE SIGNATURE preboot test." | systemd-cat

echo cp...
cp /scripts/succeed_rpm_cert.pem /etc/intel-manageability/public/dispatcher-agent/ota_signature_cert.pem
echo chmod...
chmod a+r /vagrant/nginx-data/*

echo purge...
test_echo AOTA APLICATION UPDATE SIGNATURE

dpkg --purge sample-application || true

echo XML with signature..
XML="<?xml version=\"1.0\" encoding=\"utf-8\"?><manifest><type>ota</type><ota><header><type>aota</type><repo>remote</repo></header><type><aota><cmd>update</cmd><app>application</app><fetch>http://127.0.0.1:80/sample-application-1.0-1.deb</fetch><signature>`python3 /scripts/create_signature.py ${VAGRANT_INPUT_PATH}/succeed_rpm_key.pem ${VAGRANT_INPUT_PATH}/sample-application-1.0-1.deb 1234`</signature><sigversion>384</sigversion><deviceReboot>yes</deviceReboot><version>0</version></aota></type></ota></manifest>"

echo trigger OTA...
trigger_ota "${XML}"

if listen_event | grep Rebooting... ; then
  echo AOTA APPLICATION UPDATE SIGNATURE preboot test good so far.
else
  echo Error in AOTA APPLICATION UPDATE SIGNATURE test preboot.  Showing recent journalctl.
  journalctl -a --no-pager -n 50
  exit 1
fi

