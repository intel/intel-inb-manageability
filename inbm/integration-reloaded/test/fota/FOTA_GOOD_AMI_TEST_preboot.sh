#!/bin/bash
set -euxo pipefail # DO NOT REMOVE -- used to fail test if intermediate command fails 

source /scripts/test_util.sh

start_time=$(get_time)
print_all_error() {
   echo "TEST FAILED!!!"
   rm -rf /etc/intel_manageability/secret/dispatcher-agent/ota_signature_cert.pem
}
trap print_all_error ERR

test_echo "Copying new dmi Bios info for AMI"
cp /scripts/dmi_ami_bios_info/* /scripts/dmi_id_bios_info/

rm -rf /opt/afulnx
mkdir -p /opt/afulnx
cp /scripts/afulnx_64 /opt/afulnx/afulnx_64

cp /scripts/succeed_rpm_cert.pem /etc/intel-manageability/public/dispatcher-agent/ota_signature_cert.pem

FOTA_GOOD_XML="<?xml version='1.0' encoding='utf-8'?><manifest><type>ota</type><ota><header><id>sampleID</id><name>Sample FOTA</name><description>Sample FOTA manifest file</description><type>fota</type><repo>remote</repo></header><type><fota name='sample'><fetch>http://127.0.0.1:80/U1170000F60X043.bin</fetch><signature>`python3 /scripts/create_signature.py ${VAGRANT_INPUT_PATH}/succeed_rpm_key.pem ${VAGRANT_INPUT_PATH}/${AMI_BIOSUPDATE_FILE}  1234`</signature><biosversion>5.12</biosversion><vendor>American Megatrends Inc.</vendor><manufacturer>AMI Corporation</manufacturer><product>Aptio CRB</product><releasedate>2017-12-29</releasedate><path>/var/cache/manageability/repository-tool</path><tooloptions>abc</tooloptions></fota></type></ota></manifest>"

test_echo Triggering Good FOTA AMI Test

trigger_ota "${FOTA_GOOD_XML}"
if listen_event | grep Rebooting ; then
  echo Fota good AMI test preboot good so far.
else
  print_all_error
  echo Error in fota good AMI test preboot.  Showing recent journalctl.
  journalctl -a --no-pager -n 50
  exit 1
fi
