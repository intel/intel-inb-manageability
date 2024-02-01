#!/bin/bash
set -euxo pipefail # DO NOT REMOVE -- used to fail test if intermediate command fails

source /scripts/test_util.sh

start_time=$(get_time)
print_all_error() {
   echo "TEST FAILED!!!"
}
trap print_all_error ERR

test_echo "Copying new dmi Bios info"
cp /scripts/dmi_bios_info/* /scripts/dmi_id_bios_info/

cp /scripts/succeed_rpm_cert.pem /etc/intel-manageability/public/dispatcher-agent/ota_signature_cert.pem

FOTA_GOOD_XML="<?xml version='1.0' encoding='utf-8'?><manifest><type>ota</type><ota><header><id>sampleId</id><name>Sample</name><description>Sample</description><type>fota</type><repo>remote</repo></header><type><fota name='sample'><fetch>http://127.0.0.1:80/BIOSUPDATE.tar</fetch><signature>`python3 /scripts/create_signature.py ${VAGRANT_INPUT_PATH}/succeed_rpm_key.pem ${VAGRANT_INPUT_PATH}/${BIOSUPDATE_TAR}  1234`</signature><biosversion>A..ZZZZ.B11.1</biosversion><vendor>Intel Corp.</vendor><manufacturer>testmanufacturer</manufacturer><product>Broxton P</product><releasedate>2017-06-23</releasedate><path>/boot/efi/</path></fota></type></ota></manifest>"

rm -rf /boot/efi
mkdir /boot/efi

test_echo Triggering Good FOTA Test
trigger_ota "${FOTA_GOOD_XML}"
if listen_event | grep Rebooting ; then
  echo Fota good test preboot good so far.
  rm -rf /etc/intel-manageability/public/dispatcher-agent/ota_signature_cert.pem
else
  echo Error in fota good test preboot.  Showing recent journalctl.
  journalctl -a --no-pager -n 50
  exit 1
fi


