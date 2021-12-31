#!/bin/bash
set -euxo pipefail # DO NOT REMOVE -- used to fail test if intermediate command fails

source /scripts/test_util.sh

start_time=$(get_time)
print_all_error() {
   echo "TEST FAILED!!!"
}
trap print_all_error ERR

cp /scripts/dmi_bios_info/* /scripts/dmi_id_bios_info/

BIOS_UPDATE_TAR_FILE="BIOSUPDATE.tar"
FOTA_LOCAL_XML="<?xml version='1.0' encoding='utf-8'?><manifest><type>ota</type><ota><header><id>sampleId</id><name>Sample</name><description>Sample</description><type>fota</type><repo>local</repo></header><type><fota name='sample'><biosversion>A..ZZZZ.B11.1</biosversion><vendor>Intel Corp.</vendor><manufacturer>testmanufacturer</manufacturer><product>Broxton P</product><releasedate>2017-06-23</releasedate><path>/var/cache/manageability/repository-tool/BIOSUPDATE.tar</path></fota></type></ota></manifest>"

rm -rf /boot/efi
mkdir /boot/efi
# place a copy of BIOSUPDATE.tar file in /var/cache/manageability/repository-tool directory
#cp ${VAGRANT_INPUT_PATH}/${BIOS_UPDATE_TAR_FILE} /boot/efi
cp ${VAGRANT_INPUT_PATH}/${BIOS_UPDATE_TAR_FILE} /var/cache/manageability/repository-tool

test_echo Triggering Good Local FOTA Test
trigger_ota "${FOTA_LOCAL_XML}"
if listen_event | grep Rebooting ; then
  echo FOTA good test preboot good so far.
else
  echo Error in FOTA good local test preboot.  Showing recent journalctl.
  journalctl -a --no-pager -n 50
  exit 1
fi
