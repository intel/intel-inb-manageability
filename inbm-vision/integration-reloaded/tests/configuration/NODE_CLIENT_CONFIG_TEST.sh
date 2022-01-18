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

GET_CONFIG_MANIFEST='<?xml version="1.0" encoding="utf-8"?><manifest><type>config</type><config><cmd>get_element</cmd><targetType>node_client</targetType><configtype><targets><target>389C0A</target></targets><get><path>maxCacheSize</path></get></configtype></config></manifest>'

SET_CONFIG_MANIFEST='<?xml version="1.0" encoding="utf-8"?><manifest><type>config</type><config><cmd>set_element</cmd><targetType>node_client</targetType><configtype><targets><target>389C0A</target></targets><set><path>maxCacheSize:149</path></set></configtype></config></manifest>'

LOAD_CONFIG_MANIFEST='<?xml version="1.0" encoding="UTF-8"?><manifest><type>config</type><config><cmd>load</cmd><targetType>node_client</targetType><configtype><targets><target>389C0A</target></targets><load><fetch>https://ci_nginx/intel_manageability.conf</fetch></load></configtype></config></manifest>'

GET_CONFIG_MESSAGE='push_ota message to manageability/request/install, message is <?xml version="1.0" encoding="utf-8"?><manifest>    <type>config</type>        <config>            <cmd>get_element</cmd>                <configtype>                    <get>                        <path>maxCacheSize</path>                    </get>                </configtype>        </config></manifest>'

SET_CONFIG_MESSAGE='push_ota message to manageability/request/install, message is <?xml version="1.0" encoding="utf-8"?><manifest>    <type>config</type>        <config>            <cmd>set_element</cmd>                <configtype>                    <set>                        <path>maxCacheSize:149</path>                    </set>                </configtype>        </config></manifest>'

LOAD_CONFIG_MESSAGE='push_ota message to manageability/request/install, message is <?xml version="1.0" encoding="utf-8"?><manifest>    <type>config</type>        <config>            <cmd>load</cmd>                <configtype>                    <load>                        <path>/var/cache/manageability/intel_manageability.conf</path>                    </load>                </configtype>        </config></manifest>'


echo "Checking health of all services"
check_health_vision_services
echo "Health check passed"
echo "Wait 10 seconds for all agents to come up..."
sleep 10

cp /etc/intel_manageability.conf "$NGINX_DATA"
echo "<!-- CONFIG LOAD TEST NODE TC -->" >>"$NGINX_DATA"/intel_manageability.conf

systemctl start nginx

check_request_on_channel() {
  if listen_config_request | grep maxCacheSize ; then
    echo Config command received by vision-agent
  else
    echo Config command failed to reach the vision-agent.
    echo Printing DISPATCHER logs...
    journalctl -u inbm-dispatcher
    exit 1
  fi
}

check_request_on_load() {
  if listen_config_request | grep intel_manageability.conf ; then
    echo Config command received by vision-agent
  else
    echo Config command failed to reach the vision-agent.
    echo Printing DISPATCHER logs...
    journalctl -u inbm-dispatcher
    exit 1
  fi
}

echo "Starting node_client config get test." | systemd-cat

test_echo RUNNING NODE_CLIENT CONFIG GET TEST
test_echo
trigger_cloud_ota "${GET_CONFIG_MANIFEST}"
check_request_on_channel

echo "Wait 5 seconds for node processing the manifest..."
sleep 5

if journalctl -u inbm-node | grep "$GET_CONFIG_MESSAGE" ; then
  echo GET CONFIG test for NODE_CLIENT passed.
else
  echo Node process node_client config get request fail. Showing recent journalctl.
  journalctl -a --no-pager -n 150 | egrep "( cat|vision|node|dispatcher in system mode)"
  exit 1
fi

echo "Starting node_client config set test." | systemd-cat
test_echo RUNNING NODE_CLIENT CONFIG SET TEST
trigger_cloud_ota "${SET_CONFIG_MANIFEST}"
check_request_on_channel

echo "Wait 5 seconds for node processing the manifest..."
sleep 5

if journalctl -u inbm-node | grep "$SET_CONFIG_MESSAGE" ; then
  echo SET CONFIG test for NODE_CLIENT passed.
  clean_up_subscribe
else
  echo Node process node_client config set request fail. Showing recent journalctl.
  journalctl -a --no-pager -n 150 | egrep "( cat|vision|node|dispatcher in system mode)"
  exit 1
fi

echo "Starting node_client config load test." | systemd-cat
test_echo RUNNING NODE_CLIENT CONFIG LOAD TEST
trigger_cloud_ota "${LOAD_CONFIG_MANIFEST}"
check_request_on_load

echo "Wait 20 seconds for node processing the manifest..."
sleep 20

if journalctl -u inbm-node | grep "$LOAD_CONFIG_MESSAGE" ; then
  echo LOAD CONFIG test for NODE_CLIENT passed.
  # Wait 60 seconds for config timer to expired
  sleep 60
  clean_up_subscribe
else
  echo Node process node_client config load request fail. Showing recent journalctl.
  journalctl -a --no-pager -n 150 | egrep "( cat|vision|node|dispatcher in system mode)"
  exit 1
fi
