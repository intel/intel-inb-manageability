#!/bin/bash
set -euxo pipefail

source /scripts/test_util.sh

trap 'kill -9 $(jobs -p) || true'  EXIT

test_failed() {
   echo "Return code: $?"
   echo "TEST FAILED!!!"
}
trap test_failed ERR

echo "Starting config load success test." | systemd-cat

cp /scripts/succeed_rpm_cert.pem /etc/intel-manageability/public/dispatcher-agent/ota_signature_cert.pem

cp /etc/intel_manageability.conf "$NGINX_DATA"
echo "<!-- CONFIG LOAD TEST -->" >>"$NGINX_DATA"/intel_manageability.conf

CONFIG_LOAD_XML="<?xml version='1.0' encoding='UTF-8'?><manifest><type>config</type><config><cmd>load</cmd><configtype><load><fetch>https://ci_nginx/intel_manageability.conf</fetch><signature>`python3 /scripts/create_signature.py ${VAGRANT_INPUT_PATH}/succeed_rpm_key.pem ${NGINX_DATA}/intel_manageability.conf  1234`</signature></load></configtype></config></manifest>"

! grep "CONFIG LOAD TEST" /etc/intel_manageability.conf

test_echo SUCCESS CONFIG LOAD TEST
trigger_ota "${CONFIG_LOAD_XML}"
listen_ota | grep 200

rm -rf /etc/intel_manageability/secret/dispatcher-agent/ota_signature_cert.pem

grep "CONFIG LOAD TEST" /etc/intel_manageability.conf
clean_up_subscribe
