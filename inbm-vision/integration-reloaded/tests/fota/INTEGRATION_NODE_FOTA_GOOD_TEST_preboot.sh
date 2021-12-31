#!/bin/bash
set -euxo # DO NOT REMOVE -- used to fail test if intermediate command fails

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
source "$DIR"/../test_util.sh

start_time=$(get_time)
print_all_error() {
   echo "TEST FAILED!!!"
}
trap print_all_error ERR

rm -rf /boot/efi
mkdir /boot/efi

test_echo "Copying new DMI BIOS info"
cp /scripts/dmi_bios_info/* /scripts/dmi_id_bios_info/

echo Start to detect rebooting message...
(if listen_reboot_message | grep Rebooting ; then
  echo Integration Node Fota good test preboot good pass.
else
  echo Test failed to detect rebooting message...
  cat /tmp/listen_event_last_log
  echo Error in Integration Node fota good test preboot.  Showing recent journalctl.
  journalctl -a --no-pager -n 150 | egrep "( cat|dispatcher in system mode)"
  exit 1
fi) &

cp ${VAGRANT_INPUT_PATH}/succeed_rpm_cert.pem /etc/intel-manageability/public/dispatcher-agent/ota_signature_cert.pem

test_echo Triggering INTEGRATION_NODE_FOTA_GOOD_TEST_preboot test via inbc
inbc fota -p ${VAGRANT_INPUT_PATH}/BIOSUPDATE.tar -pr "Broxton P" -m testmanufacturer -v "Intel Corp." -pr "Broxton P" -s `python3 /scripts/create_signature.py ${VAGRANT_INPUT_PATH}/succeed_rpm_key.pem ${VAGRANT_INPUT_PATH}/BIOSUPDATE.tar  1234` -t 389C0A
