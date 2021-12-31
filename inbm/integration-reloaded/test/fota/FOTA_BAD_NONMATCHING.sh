#!/bin/bash
set -euxo pipefail # DO NOT REMOVE -- used to fail test if intermediate command fails

source /scripts/test_util.sh

start_time=$(get_time)
print_all_error() {
   echo "TEST FAILED!!!"
}
trap print_all_error ERR

cp /scripts/dmi_bios_info/* /scripts/dmi_id_bios_info/

sleep 10

FOTA_BAD_XML1="<?xml version='1.0' encoding='utf-8'?><manifest><type>ota</type><ota><header><id>sample</id><name>sample</name><description>sample</description><type>fota</type><repo>remote</repo></header><type><fota name='sample'><fetch>http://127.0.0.1:80/BIOSUPDATE.tar</fetch><signature>`python3 /scripts/create_signature.py ${VAGRANT_INPUT_PATH}/succeed_rpm_key.pem ${VAGRANT_INPUT_PATH}/${BIOSUPDATE_TAR}  1234`</signature><biosversion>A..ZZZZ.B11.1</biosversion><vendor>Intel Corp.</vendor><manufacturer>testmanufacturer</manufacturer><product>invalidproduct</product><releasedate>2017-06-23</releasedate><path>/boot/efi/</path></fota></type></ota></manifest>"

rm -rf /boot/efi
mkdir /boot/efi
test_echo TC18 Triggering FOTA integration test 2- non-matching product name

trigger_ota "${FOTA_BAD_XML1}"
listen_ota | grep 400
sleep 5

echo "Checking health of all services"
check_health_tc_services
echo "Health check passed"

echo After reboot, we are looking for exactly 0 capsule file in /boot/efi/
ls /boot/efi/
ls /boot/efi/ | wc -l | grep 0

clean_up_subscribe
sleep 3
