#!/bin/bash
set -e
set -x

source /scripts/test_util.sh

trap 'kill -9 $(jobs -p) || true'  EXIT

test_failed() {
   echo "Return code: $?"
   echo "TEST FAILED!!!"
}
trap test_failed ERR

echo "Starting config local load success test." | systemd-cat

CONFIG_LOAD_XML='<?xml version="1.0" encoding="UTF-8"?><manifest><type>config</type><config><cmd>load</cmd><configtype><load><path>/var/cache/manageability/intel_manageability.conf</path></load></configtype></config></manifest>'

cp /etc/intel_manageability.conf /var/cache/manageability/
echo "<!-- CONFIG LOCAL LOAD TEST -->" >>/var/cache/manageability/intel_manageability.conf

! grep "CONFIG LOCAL LOAD TEST" /var/cache/manageability/intel_manageability.conf

test_echo SUCCESS CONFIG LOCAL LOAD TEST
trigger_ota "${CONFIG_LOAD_XML}"
listen_ota | grep 200

grep "CONFIG LOCAL LOAD TEST" /etc/intel_manageability.conf
cp /etc/intel_manageability.conf_bak /etc/intel_manageability.conf
clean_up_subscribe