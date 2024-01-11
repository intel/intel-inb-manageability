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

cp /scripts/succeed_rpm_cert.pem /etc/intel-manageability/public/dispatcher-agent/ota_signature_cert.pem
echo chmod...
chmod a+r /vagrant/nginx-data/*

test_echo AOTA APLICATION UPDATE SIGNATURE

dpkg --purge sample-application || true

inbc aota --uri http://127.0.0.1:80/sample-application-1.0-1.deb -a "application" -c "update" --signature `python3 /scripts/create_signature.py ${VAGRANT_INPUT_PATH}/succeed_rpm_key.pem ${VAGRANT_INPUT_PATH}/sample-application-1.0-1.deb 1234`
