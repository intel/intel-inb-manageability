#!/bin/bash
set -euxo pipefail # DO NOT REMOVE -- used to fail test if intermediate command fails

source /scripts/test_util.sh
BIOSUPDATE_NO_TAR=U1170000F60X043.bin

start_time=$(get_time)
print_all_error() {
   echo "TEST FAILED!!!"
}
trap print_all_error ERR

test_echo "Copying new dmidecode response for AMI"
cp /scripts/dmi_ami_bios_info/* /scripts/dmi_id_bios_info/

rm -rf /opt/afulnx
mkdir -p /opt/afulnx
cp /scripts/afulnx_64 /opt/afulnx/afulnx_64

test_echo Triggering FOTA GOOD No Tar Test

inbc fota --nohddl --uri http://127.0.0.1:80/U1170000F60X043.bin -to abc

RESULT=$?
if [ $RESULT -eq 0 ]; then
   echo "<PASS> FOTA GOOD INBC NO TAR TEST"
else
  echo Test failed to detect non-zero exit code...
  echo "<FAILED> FOTA GOOD NO TAR TEST"
  exit 1
fi

sleep 3


