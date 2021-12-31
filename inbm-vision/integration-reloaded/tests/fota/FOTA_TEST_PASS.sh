#!/bin/bash
set -exuo pipefail # DO NOT REMOVE -- used to fail test if intermediate command fails

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
source "$DIR"/../test_util.sh

cp ${VAGRANT_INPUT_PATH}/succeed_rpm_cert.pem /etc/intel-manageability/public/dispatcher-agent/ota_signature_cert.pem

FOTA_XML="<?xml version='1.0' encoding='utf-8'?><manifest><type>ota</type><ota><header><type>fota</type><repo>remote</repo></header><type><fota name='sample'> <targetType>node</targetType>                 <targets>                     <target>389C0A</target>                 </targets><fetch>http://127.0.0.1:80/U1170000F60X043.tar</fetch><signature>`python3 /scripts/create_signature.py ${VAGRANT_INPUT_PATH}/succeed_rpm_key.pem ${VAGRANT_INPUT_PATH}/${AMI_BIOSUPDATE_TAR}  1234`</signature><biosversion>5.12</biosversion><vendor>Intel Corp.</vendor><manufacturer>testmanufacturer</manufacturer><product>Broxton P</product><releasedate>2017-12-29</releasedate><tooloptions>abc</tooloptions></fota></type></ota></manifest>"

echo "Checking health of all services"
check_health_vision_services
echo "Health check passed"
echo "Wait 10 seconds for all agent come up..."
sleep 10

systemctl start nginx

# Listen the channel first
(if listen_vision_ota | grep 389C0A; then
  echo Target FOTA manifest received by vision-agent.
else
  echo printing errors...
  #print_all_error
  echo Error in sending target FOTA manifest.  Showing recent journalctl.
  #journalctl -a --no-pager -n 50 | egrep "( cat|vision|dispatcher in system mode)"
  echo VISION-AGENT JOURNAL LOG...
  journalctl -u inbm-vision

  echo VISION-AGENT JOURNAL LOG...
  journalctl -u inbm-node
  exit 1
fi) &

echo Send FOTA update manifest
trigger_cloud_ota "${FOTA_XML}"

echo "Wait 5 seconds..."
sleep 5

if journalctl -u inbm-dispatcher | grep 200 ; then
  echo FOTA manifest publish good so far.
  rm -rf /etc/intel-manageability/public/dispatcher-agent/ota_signature_cert.pem
else
  journalctl -u inbm-dispatcher
  echo Error in FOTA test.  Showing recent journalctl.
  # journalctl -a --no-pager -n 50
  exit 1
fi

echo "Wait 60 seconds for node processing the manifest..."
sleep 60

if journalctl -u inbm-node | grep "push_ota message"; then
  # Wait 60 seconds for timer expired
  sleep 60
  echo FOTA test passed.
  clean_up_subscribe
else
  #print_all_error
  echo Node process fota update request fail. Showing recent journalctl.
  journalctl -a --no-pager -n 50 | egrep "( cat|vision|dispatcher in system mode)"
  
  echo VISION-AGENT JOURNAL LOG...
  journalctl -u inbm-vision

  echo NODE AGENT JOURNAL LOG...
  journalctl -u inbm-node
  exit 1
fi
