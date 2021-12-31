#!/bin/bash
set -e
set -x

source /scripts/test_util.sh

CONFIG_DBS_ON_XML='<?xml version="1.0" encoding="UTF-8"?><manifest><type>config</type><config><cmd>set_element</cmd><configtype><set><path>{"all": [{"dbs": "ON"}]}</path> </set></configtype></config></manifest>'
CONFIG_DBS_OFF_XML='<?xml version="1.0" encoding="UTF-8"?><manifest><type>config</type><config><cmd>set_element</cmd><configtype><set><path>{"all": [{"dbs": "OFF"}]}</path> </set></configtype></config></manifest>'
GOOD_XML="<?xml version='1.0'  ?><manifest><type>ota</type><ota><header><id>sampleId</id><name>Sample AOTA</name><description>Sample AOTA manifest file</description><type>aota</type><repo>remote</repo></header><type><aota name='sample-rpm'><cmd>load</cmd><app>docker</app><fetch>http://127.0.0.1:80/sample-container-load.tgz</fetch><containerTag>sample-container</containerTag></aota></type></ota></manifest>"

cleanup() {
    kill -9 $(jobs -p) || true
    trigger_ota "${CONFIG_DBS_OFF_XML}"
}

trap cleanup EXIT
journalctl -a -f &

systemctl start mqtt
systemctl start inbm

start_time=$(get_time)
print_all_error() {
   echo "Return code: $?"
   echo "TEST FAILED!!!"
   cleanup
}
trap print_all_error ERR


setup_hdc_rpmlite() {
    zcat ${VAGRANT_INPUT_PATH}/sample-container.tgz | docker import - sample-container:1
}

test_echo Setting up sample-container.
setup_hdc_rpmlite

test_echo Set DBS to ON.
(if (listen_ota | grep 200); then
echo passed
clean_up_subscribe
else
print_all_error
fi) &
trigger_ota "${CONFIG_DBS_ON_XML}"
sleep 5
clean_up_subscribe
test_echo Failed DBS check
test_echo
trigger_ota "${GOOD_XML}"
listen_ota | grep 400
if (trtl -cmd=list | grep sample-container); then
print_all_error
fi
clean_up_subscribe
