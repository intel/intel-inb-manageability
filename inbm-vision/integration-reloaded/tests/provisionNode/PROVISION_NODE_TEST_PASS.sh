#!/bin/bash
set -exuo pipefail # DO NOT REMOVE -- used to fail test if intermediate command fails

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
source "$DIR"/../test_util.sh

PROVISION_NODE_CMD="<?xml version='1.0' encoding='utf-8'?><manifest><type>cmd</type><cmd>provisionNode</cmd><provisionNode><fetch>http://127.0.0.1:80/sample_provision.tar</fetch></provisionNode></manifest>"
PROVISION_FOLDER="/opt/xlink_provision"
CERT_FILE_NAME="$PROVISION_FOLDER"/"e4bd65bd6f64a54dc2e78ead455e9f0e_cert.crt"
BLOB_FILE_NAME="$PROVISION_FOLDER"/"e4bd65bd6f64a54dc2e78ead455e9f0e_blob.bin"

echo "Checking health of all services"
check_health_vision_services
echo "Health check passed"
echo "Wait 10 seconds for all agent come up..."
sleep 10

systemctl start nginx

echo Send provision-node manifest
trigger_cloud_ota "${PROVISION_NODE_CMD}"

echo "Wait 5 seconds..."
sleep 5

if journalctl -u inbm-dispatcher | grep provisionNode ; then
  echo Dispacther receive provision-node manifest
else
  journalctl -u inbm-dispatcher
  echo Error in provision-node test.  Showing recent journalctl.
  exit 1
fi

echo "Wait 5 seconds for vision-agent to process the manifest..."
sleep 5

if ! [ -f "$CERT_FILE_NAME" ]; then
  echo Cert file being deleted due to command failed and not found under $PROVISION_FOLDER.
else
  echo ProvisionNode command fail. Showing recent journalctl.
  journalctl -a --no-pager -n 50 | egrep "( cat|vision|dispatcher in system mode)"

  echo VISION-AGENT JOURNAL LOG...
  journalctl -u inbm-vision

  echo NODE AGENT JOURNAL LOG...
  journalctl -u inbm-node
  exit 1
fi

if ! [ -f "$BLOB_FILE_NAME" ]; then
  echo Blob file being deleted due to command failed and not found under $PROVISION_FOLDER.
  echo ProvisionNode test passed.
else
  echo ProvisionNode command fail. Showing recent journalctl.
  journalctl -a --no-pager -n 50 | egrep "( cat|vision|dispatcher in system mode)"

  echo VISION_AGENT JOURNAL LOG...
  journalctl -u inbm-vision

  echo NODE AGENT JOURNAL LOG...
  journalctl -u inbm-node
  exit 1
fi

