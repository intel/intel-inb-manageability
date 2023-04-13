#!/bin/bash
BIOSUPDATE_FILE=BIOSUPDATE.fv
BIOSUPDATE_TAR=BIOSUPDATE.tar
AMI_BIOSUPDATE_FILE=U1170000F60X043.bin
AMI_BIOSUPDATE_TAR=U1170000F60X043.tar
VAGRANT_INPUT_PATH=/vagrant/input
CONFIG_FILE=intel_manageability.txt
LOCAL_MQTT_PORT=$(cat /etc/intel-manageability/local-mqtt-port.txt)


cleanup_after_test() {
    rm -rf /var/lib/dispatcher/upload/*
    rm -rf /var/log/sota_test/*
    rm -rf /boot/efi/*
    rm -rf /etc/intel-manageability/public/dispatcher-agent/ota_signature_cert.pem
}

trigger_ota() {
    CA_FILE=/etc/intel-manageability/public/mqtt-ca/mqtt-ca.crt
    CERT_FILE=/etc/intel-manageability/public/inbc-program/inbc-program.crt
    KEY=/etc/intel-manageability/secret/inbc-program/inbc-program.key
    ID=inbc-program
    TOPIC=manageability/request/install
    XML=$1
    mosquitto_pub -h localhost -p "$LOCAL_MQTT_PORT" --cafile ${CA_FILE} --cert ${CERT_FILE} --key ${KEY} -i ${ID} -t ${TOPIC} -m "${XML}"
}


listen_ota() {
    CA_FILE=/etc/intel-manageability/public/mqtt-ca/mqtt-ca.crt
    CERT_FILE=/etc/intel-manageability/public/inbc-program/inbc-program.crt
    KEY=/etc/intel-manageability/secret/inbc-program/inbc-program.key
    ID=inbc-program
    TOPIC=manageability/response
    timeout 300 mosquitto_sub -h localhost -p "$LOCAL_MQTT_PORT" --cafile ${CA_FILE} --cert ${CERT_FILE} --key ${KEY} -i ${ID} -t ${TOPIC} -C 1 --keepalive 10| tee /tmp/listen_ota_last_log
}


listen_event() {
    CA_FILE=/etc/intel-manageability/public/mqtt-ca/mqtt-ca.crt
    CERT_FILE=/etc/intel-manageability/public/inbc-program/inbc-program.crt
    KEY=/etc/intel-manageability/secret/inbc-program/inbc-program.key
    ID=inbc-program
    TOPIC=manageability/event
    timeout 120 mosquitto_sub -h localhost -p "$LOCAL_MQTT_PORT" --cafile ${CA_FILE} --cert ${CERT_FILE} --key ${KEY} -i ${ID} -t ${TOPIC} -C 13 --keepalive 10| tee /tmp/listen_event_last_log
}

trigger_ucc() {
    CA_FILE=/etc/ucc_mosquitto/certs/ca.crt
    CERT_FILE=/etc/ucc_mosquitto/certs/client.crt
    KEY=/etc/ucc_mosquitto/certs/client.key
    ID=test
    TOPIC=TopicRemoteCommands/12345678abcd
    MSG=$1
    UCC_MQTT_PORT=4000
    sudo mosquitto_pub -h localhost -p $UCC_MQTT_PORT --cafile ${CA_FILE} --cert ${CERT_FILE} --key ${KEY} -i ${ID} -t ${TOPIC} -m "${MSG}"
}

listen_ucc_telemetry() {
    CA_FILE=/etc/ucc_mosquitto/certs/ca.crt
    CERT_FILE=/etc/ucc_mosquitto/certs/client.crt
    KEY=/etc/ucc_mosquitto/certs/client.key
    ID=test
    TOPIC=TopicRemoteCommands/response/12345678abcd
    UCC_MQTT_PORT=4000
    sudo timeout 300 mosquitto_sub -h localhost -p $UCC_MQTT_PORT --cafile ${CA_FILE} --cert ${CERT_FILE} --key ${KEY} -i ${ID} -t ${TOPIC} -C 1 --keepalive 10| tee ucc-telemetry-response &
}

listen_ucc_command() {
    CA_FILE=/etc/ucc_mosquitto/certs/ca.crt
    CERT_FILE=/etc/ucc_mosquitto/certs/client.crt
    KEY=/etc/ucc_mosquitto/certs/client.key
    ID=test
    TOPIC=manageability/request/command
    UCC_MQTT_PORT=4000
    sudo timeout 300 mosquitto_sub -h localhost -p $UCC_MQTT_PORT --cafile ${CA_FILE} --cert ${CERT_FILE} --key ${KEY} -i ${ID} -t ${TOPIC} -C 1 --keepalive 10| tee ucc-command-response &
}

clean_up_subscribe() {
if pgrep mosquitto_sub ; then
pkill mosquitto_sub
else
test_echo passed
fi
}

get_time() {
   date +"%Y-%m-%d %T"
}

check_health_tc_services() {
   systemctl start inbm docker mqtt
   sleep 1
}

test_echo() {
    echo "[TOP LEVEL TEST]: " $@
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
