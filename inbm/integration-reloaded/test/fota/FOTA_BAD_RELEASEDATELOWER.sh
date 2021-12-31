#!/bin/bash

source /scripts/test_util.sh

start_time=$(get_time)

cp /scripts/dmi_bios_info/* /scripts/dmi_id_bios_info/

BIOSUPDATETAR_FILE="BIOSUPDATE.tar"

SIGNATURE=$(python3 /scripts/create_signature.py ${VAGRANT_INPUT_PATH}/succeed_rpm_key.pem ${VAGRANT_INPUT_PATH}/${BIOSUPDATE_TAR}  1234)

test_echo TC19 Triggering FOTA integration test 3- releasedate lower

inbc fota --nohddl --uri http://127.0.0.1:80/BIOSUPDATE.tar --tooloptions abc --signature "$SIGNATURE" --releasedate 2010-06-23

RESULT=$?
if [ $RESULT -ne 0 ]; then
   echo "<PASS> FOTA BAD RELEASE_DATE"
else
  echo Test failed to detect non-zero exit code...
  echo "<FAILED> FOTA BAD RELEASE_DATE."
  exit 1
fi

echo "Checking health of all services"
check_health_tc_services
echo "Health check passed"

sleep 3