#!/bin/bash
set -e # DO NOT REMOVE -- used to fail test if intermediate command fails

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
source "$DIR"/../test_util.sh

test_failed() {
  print_all_error
  echo "Return code: $?"
  echo "TEST FAILED"
}
trap test_failed ERR

CONFIG_LOAD_XML='<?xml version="1.0" encoding="UTF-8"?><manifest><type>config</type><config><cmd>load</cmd><targetType>node</targetType><configtype><targets><target>389C0A</target></targets><load><fetch>https://ci_nginx/intel_manageability_node.conf</fetch></load></configtype></config></manifest>'

FAILED_MESSAGE='Only one update is allowed at a time. Please try again after'

echo "Checking health of all services"
check_health_vision_services
echo "Health check passed"
echo "Wait 10 seconds for all agent come up..."
sleep 10

cp /etc/intel-manageability/public/node-agent/intel_manageability_node.conf "$NGINX_DATA"

systemctl start nginx

echo "Starting config load negative test on node." | systemd-cat

test_echo RUNNING CONFIG LOAD TEST NODE FAIL WITH OTA IN PROGRESS
trigger_cloud_ota "${CONFIG_LOAD_XML}"
echo "Testing dispatcher logs..."
sleep 10
if journalctl -u inbm-dispatcher | grep 200; then
    echo "Status 200"
else
    echo Test FAILED
    journalctl -u inbm-dispatcher
    exit 1
fi

if journalctl -u inbm-vision | grep "$FAILED_MESSAGE" ; then
  echo NODE CONFIG LOAD TEST FAIL WITH OTA IN PROGRESS passed.
  clean_up_subscribe
  # Wait 60 seconds for ota timer expired
  sleep 60
else
  echo Node process config load request negative test fail. Showing recent journalctl.
  journalctl -a --no-pager -n 150 | egrep "( cat|vision|node in system mode)"
  exit 1
fi
