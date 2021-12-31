#!/bin/bash
set -e # DO NOT REMOVE -- used to fail test if intermediate command fails

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
source "$DIR"/../test_util.sh

FOTA_XML="<?xml version='1.0' encoding='utf-8'?><manifest><type>ota</type><ota><header><id>sampleID</id><name>Sample FOTA</name><description>Sample FOTA manifest file</description><type>fota</type><repo>remote</repo></header><type><fota name='sample'> <targetType>node</targetType>                 <targets>                     <target>389C0A</target>                 </targets><fetch>http://127.0.0.1:80/U1170000F60X043.tar</fetch><signature>`python3 /scripts/create_signature.py ${VAGRANT_INPUT_PATH}/succeed_rpm_key.pem ${VAGRANT_INPUT_PATH}/${AMI_BIOSUPDATE_TAR}  1234`</signature><biosversion>5.12</biosversion><vendor>American Megatrends Inc.</vendor><manufacturer>AMI Corporation</manufacturer><product>Broxton P</product><releasedate>2017-12-29</releasedate><tooloptions>abc</tooloptions></fota></type></ota></manifest>"

FOTA_FAIL_MESSAGE="No eligible nodes found to perform the requested update.OTA update failed."

echo "Checking health of all services"
check_health_vision_services
echo "Health check passed"
echo "Wait 10 seconds for all agent come up..."
sleep 10

systemctl start nginx

# Listen the channel first
(if listen_vision_ota | grep 389C0A; then
  echo Target FOTA manifest is received by vision-agent.
else
  echo printing errors...
  #print_all_error
  echo Error in sending target FOTA manifest.  Showing recent journalctl.
  #journalctl -a --no-pager -n 50 | egrep "( cat|vision|dispatcher in system mode)"
  echo VISION-AGENT JOURNAL LOG...
  journalctl -u inbm-vision

  echo NODE AGENT JOURNAL LOG...
  journalctl -u inbm-node
  exit 1
fi) &

echo Send FOTA update manifest
trigger_cloud_ota "${FOTA_XML}"

echo "Wait 5 seconds..."
sleep 5

if journalctl -u inbm-dispatcher | grep 200 ; then
  echo Fota manifest publish good so far.
else
  echo === ERROR LOG ===
  echo Error in FOTA test.  Showing recent journalctl.
  journalctl -u inbm-dispatcher -u configuration
  echo === END ERROR LOG ===
  exit 1
fi

if journalctl -u inbm-vision | grep "$FOTA_FAIL_MESSAGE"; then
  echo FOTA fail test passed.
  clean_up_subscribe
else
  #print_all_error
  echo FOTA fail test fail. Showing recent journalctl.
  journalctl -a --no-pager -n 50 | egrep "(cat|vision|node|dispatcher|diagnostic|in system mode|telemetry|configuration)"

  echo AGENT JOURNAL LOG...
  journalctl -u inbm-vision -u inbm-node -u dispatcher -u diagnostic -u telemetry -u configuration

  exit 1
fi
