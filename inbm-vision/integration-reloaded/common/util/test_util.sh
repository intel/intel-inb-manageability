#!/bin/bash
set -e # DO NOT REMOVE -- used to fail test if intermediate command fails

VAGRANT_INPUT_PATH=/vagrant/input
BIOSUPDATE_FILE=BIOSUPDATE.fv
BIOSUPDATE_TAR=BIOSUPDATE.tar
AMI_BIOSUPDATE_FILE=U1170000F60X043.bin
AMI_BIOSUPDATE_TAR=U1170000F60X043.tar

cleanup_after_test() {
    rm -rf /var/lib/dispatcher/upload/*
    rm -rf /var/log/sota_test/*
    rm -rf /boot/efi/*
    rm -rf /etc/intel-manageability/public/dispatcher-agent/ota_signature_cert.pem
}

trigger_cloud_ota() {
    CA_FILE=/etc/intel-manageability/public/mqtt-ca/mqtt-ca.crt
    CERT_FILE=/etc/intel-manageability/public/cloudadapter-agent/cloudadapter-agent.crt
    KEY=/etc/intel-manageability/secret/cloudadapter-agent/cloudadapter-agent.key
    ID=cloudadapter-agent
    TOPIC=manageability/request/install
    XML=$1
    mosquitto_pub -h localhost -p 8883 --cafile ${CA_FILE} --cert ${CERT_FILE} --key ${KEY} -i ${ID} -t ${TOPIC} -m "${XML}"
}

trigger_vision_ota() {
    CA_FILE=/etc/intel-manageability/public/mqtt-ca/mqtt-ca.crt
    CERT_FILE=/etc/intel-manageability/public/dispatcher-agent/dispatcher-agent.crt
    KEY=/etc/intel-manageability/secret/dispatcher-agent/dispatcher-agent.key
    ID=vision-dispatcher-agent
    TOPIC=$1
    XML=$2
    mosquitto_pub -h localhost -p 8883 --cafile ${CA_FILE} --cert ${CERT_FILE} --key ${KEY} -i ${ID} -t ${TOPIC} -m "${XML}"
}

listen_config_request(){
    CA_FILE=/etc/intel-manageability/public/mqtt-ca/mqtt-ca.crt
    CERT_FILE=/etc/intel-manageability/public/vision-agent/vision-agent.crt
    KEY=/etc/intel-manageability/secret/vision-agent/vision-agent.key
    ID=ReceiveConfig
    TOPIC=ma/configuration/update/+
    timeout 300 mosquitto_sub -h localhost -p 8883 --cafile ${CA_FILE} --cert ${CERT_FILE} --key ${KEY} -i ${ID} -t ${TOPIC} -C 1 --keepalive 10| tee /tmp/listen_config_request_last_log
}

listen_vision_ota() {
    CA_FILE=/etc/intel-manageability/public/mqtt-ca/mqtt-ca.crt
    CERT_FILE=/etc/intel-manageability/public/vision-agent/vision-agent.crt
    KEY=/etc/intel-manageability/secret/vision-agent/vision-agent.key
    ID=ReceiveOTA
    TOPIC=ma/request/install
    timeout 300 mosquitto_sub -h localhost -p 8883 --cafile ${CA_FILE} --cert ${CERT_FILE} --key ${KEY} -i ${ID} -t ${TOPIC} -C 1 --keepalive 10| tee /tmp/listen_vision_ota_last_log
}

listen_vision_query() {
    CA_FILE=/etc/intel-manageability/public/mqtt-ca/mqtt-ca.crt
    CERT_FILE=/etc/intel-manageability/public/vision-agent/vision-agent.crt
    KEY=/etc/intel-manageability/secret/vision-agent/vision-agent.key
    ID=ReceiveQuery
    TOPIC=ma/request/query
    timeout 300 mosquitto_sub -h localhost -p 8883 --cafile ${CA_FILE} --cert ${CERT_FILE} --key ${KEY} -i ${ID} -t ${TOPIC} -C 1 --keepalive 10| tee /tmp/listen_vision_ota_last_log
}

listen_reboot_message() {
  # Edit -C parameter based on the number of message will be received until getting Rebooting message
    CA_FILE=/etc/intel-manageability/public/mqtt-ca/mqtt-ca.crt
    CERT_FILE=/etc/intel-manageability/public/node-agent/node-agent.crt
    KEY=/etc/intel-manageability/secret/node-agent/node-agent.key
    ID=ListenToEvent
    TOPIC=manageability/event
    timeout 300 mosquitto_sub -h localhost -p 8883 --cafile ${CA_FILE} --cert ${CERT_FILE} --key ${KEY} -i ${ID} -t ${TOPIC} -C 8 --keepalive 10| tee /tmp/listen_event_last_log
}

clean_up_subscribe() {
if pgrep mosquitto_sub ; then
pkill mosquitto_sub
else
test_echo passed
fi
}

test_echo() {
    echo "[TOP LEVEL TEST]: " $@
}

check_health_vision_services() {
  systemctl start mqtt inbm-node
  systemctl start inbm-vision
  sleep 1
}

check_health_tc_services() {
   systemctl start inbm-dispatcher inbm-diagnostic inbm-configuration inbm-telemetry docker mqtt
   sleep 1
}

get_time() {
   date +"%Y-%m-%d %T"
}

start_time=$(date +"%Y-%m-%d %T")
print_all_error() {
  echo "TEST FAILED"
  end_time=$(date +"%Y-%m-%d %T")
  echo "Dumping all logs between $start_time and $end_time"
  journalctl -a -l --no-pager --since "$start_time"
}
trap print_all_error ERR

NGINX_DATA="/vagrant/nginx-data"
