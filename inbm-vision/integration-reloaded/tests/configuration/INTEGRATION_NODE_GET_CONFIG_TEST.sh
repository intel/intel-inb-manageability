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

GET_CONFIG_MESSAGE='Publish message to manageability/event, message is: id=389C0A-Got response back for command: get_element response: {telemetry/maxCacheSize:100}'

echo "Checking health of all services"
check_health_vision_services
echo "Health check passed"
echo "Wait 10 seconds for all agent come up..."
sleep 10

echo RUNNING INTEGRATION NODE CONFIG - GET TEST via inbc
inbc get -tt node_client -p maxCacheSize -t 389C0A

echo "Wait 5 seconds for node processing the manifest..."
sleep 5

echo Check configuration agent process the config request
if journalctl -u inbm-configuration | grep "telemetry/maxCacheSize:100"; then
    echo "node-client - Configuration agent process get config request."
else
    echo "node-client - Configuration agent failed to process get config request."
    echo Test FAILED
    journalctl -u inbm-vision
    journalctl -u inbm-node
    journalctl -u inbm-dispatcher
    journalctl -u inbm-configuration
    exit 1
fi

echo Check if vision-agent published the config response
if journalctl -u inbm-vision | grep "$GET_CONFIG_MESSAGE"; then
    echo "vision-agent published the response of the get config request."
else
    echo "vision-agent failed to publish the response of the get config request."
    echo Test FAILED
    journalctl -u inbm-vision
    journalctl -u inbm-node
    journalctl -u inbm-dispatcher
    journalctl -u inbm-configuration
    exit 1
fi
