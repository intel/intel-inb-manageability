#!/bin/bash
set -euxo pipefail # DO NOT REMOVE -- used to fail test if intermediate command fails

source /scripts/test_util.sh
BIOSUPDATE_NO_TAR=U1170000F60X043.bin

start_time=$(get_time)
print_all_error() {
   echo "TEST FAILED!!!"
}
trap print_all_error ERR

test_echo "Copying new dmi Bios info for AMI"
cp /scripts/dmi_ami_bios_info/* /scripts/dmi_id_bios_info/

rm -rf /opt/afulnx
mkdir -p /opt/afulnx
cp /scripts/afulnx_64 /opt/afulnx/afulnx_64

test_echo Triggering FOTA GOOD INBC PLATFORM INFO MATCH TEST

inbc fota --uri http://127.0.0.1:80/U1170000F60X043.bin --tooloptions abc --product "Aptio CRB" --manufacturer "AMI Corporation" --biosversion 5.12 --vendor "American Megatrends Inc."

RESULT=$?
if [ $RESULT -eq 0 ]; then
   echo "<PASS> FOTA GOOD INBC PLATFORM INFO MATCH TEST"
else
  echo Test failed to detect non-zero exit code...
  echo "<FAILED> FOTA GOOD INBC PLATFORM INFO MATCH TEST"
  exit 1
fi

sleep 3