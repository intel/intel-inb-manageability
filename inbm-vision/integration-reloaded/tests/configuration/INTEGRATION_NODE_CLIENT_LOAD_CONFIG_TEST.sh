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

GET_CONFIG_MESSAGE='telemetryMessage: Got response back for command: get_element response: {telemetry/maxCacheSize:110}'

echo "Checking health of all services"
check_health_vision_services
echo "Health check passed"
echo "Wait 10 seconds for all agent come up..."
sleep 10

cp /tmp/turtle_creek_developer.conf /var/cache/manageability/intel_manageability.conf
# Change values in the conf file to test config load on node_client
echo "<!-- CONFIG LOAD TEST NODE TC -->" >>/var/cache/manageability/intel_manageability.conf
sed -i "s|<maxCacheSize>100</maxCacheSize>|<maxCacheSize>110</maxCacheSize>|g" /var/cache/manageability/intel_manageability.conf

echo RUNNING INTEGRATION NODE CONFIG - LOAD TEST via inbc
inbc load -tt node_client -p /var/cache/manageability/intel_manageability.conf -t 389C0A

echo "Wait 10 seconds for node processing the manifest..."
sleep 10

echo Send get config request
inbc get -tt node_client -p maxCacheSize -t 389C0A

echo "Wait 10 seconds for node processing the manifest..."
sleep 10

echo Check vision-agent get the correct GET value which is 110

! grep "CONFIG LOAD TEST NODE TC" /etc/intel_manageability.conf
# the value within the location's conf file is being changed in the INSTALL_FRAMEWORK_slow.sh
if journalctl -u inbm-vision | grep "$GET_CONFIG_MESSAGE"; then
    echo "vision-agent got the correct get value for node client config."
    # Wait 100 seconds for config timer expired
    sleep 100
else
    echo "vision-agent failed to get the correct get value for node client config."
    echo Test FAILED
    journalctl -u inbm-vision
    journalctl -u inbm-node
    journalctl -u inbm-dispatcher
    journalctl -u inbm-configuration
    exit 1
fi