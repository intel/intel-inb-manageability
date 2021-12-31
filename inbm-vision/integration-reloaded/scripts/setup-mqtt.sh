#!/bin/bash
set -e
# Setup MQTT key and cert
MQTT_PUBLIC="/etc/intel-manageability/public"
MQTT_SECRET="/etc/intel-manageability/secret"
RANDFILE="/etc/intel-manageability/secret/randfile"
DAYS_EXPIRY="2555"

mkdir -p "$MQTT_PUBLIC"/mqtt-ca
mkdir -p "$MQTT_SECRET"/mqtt-ca
mkdir -p "$MQTT_PUBLIC"/mqtt-broker
mkdir -p "$MQTT_SECRET"/mqtt-broker

cd "$MQTT_SECRET"/mqtt-ca
openssl genrsa -out mqtt-ca.key 3072
openssl req -new -key mqtt-ca.key -subj "/C=US/ST=Oregon/L=Hillsboro/O=Intel/OU=EVAL/CN=mqtt-ca.example.com" -out mqtt-ca.csr
openssl x509 -req -days "$DAYS_EXPIRY" -sha384 -extensions v3-ca -signkey mqtt-ca.key -in mqtt-ca.csr -out mqtt-ca.crt
chmod 644 mqtt-ca.crt
chgrp mqtt-ca *
cp "$MQTT_SECRET"/mqtt-ca/mqtt-ca.crt "$MQTT_PUBLIC"/mqtt-ca

cd "$MQTT_SECRET"/mqtt-broker
openssl genrsa -out mqtt-broker.key 3072
cat >openssl-san.cnf <<EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[ v3_req ]

# Extensions to add to a certificate request

basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost

[req_distinguished_name]
EOF

openssl req -new -out mqtt-broker.csr -key mqtt-broker.key -config openssl-san.cnf -subj "/C=US/ST=Oregon/L=Hillsboro/O=Intel/OU=EVAL/CN=localhost"
openssl x509 -req -days "$DAYS_EXPIRY" -sha384 -extensions v3_req -CA "$MQTT_SECRET"/mqtt-ca/mqtt-ca.crt -CAkey "$MQTT_SECRET"/mqtt-ca/mqtt-ca.key -CAcreateserial -in mqtt-broker.csr -out mqtt-broker.crt
chmod 664 mqtt-broker.crt
cp "$MQTT_SECRET"/mqtt-broker/mqtt-broker.crt "$MQTT_PUBLIC"/mqtt-broker

groupadd -f mqtt-ca
groupadd -f mqtt-broker

chgrp mqtt-ca "$MQTT_PUBLIC"/mqtt-ca
chgrp mqtt-ca "$MQTT_PUBLIC"/mqtt-ca/*
chgrp mqtt-ca "$MQTT_SECRET"/mqtt-ca
chgrp mqtt-ca "$MQTT_SECRET"/mqtt-ca/*
chgrp mqtt-broker "$MQTT_PUBLIC"/mqtt-broker
chgrp mqtt-broker "$MQTT_PUBLIC"/mqtt-broker/*
chgrp mqtt-broker "$MQTT_SECRET"/mqtt-broker/
chgrp mqtt-broker "$MQTT_SECRET"/mqtt-broker/*

# Setup mqtt service file
touch /etc/systemd/system/mqtt.service
cat >> /etc/systemd/system/mqtt.service <<EOF
[Unit]
Description=Bit Creek MQTT
ConditionPathExists=/etc/intel-manageability/public/mqtt-broker/mosquitto.conf
ConditionPathExists=/etc/intel-manageability/public/mqtt-broker/acl.file
Requires=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/mosquitto -c /etc/intel-manageability/public/mqtt-broker/mosquitto.conf
ExecReload=/bin/kill -HUP $MAINPID
StandardOutput=journal
StandardError=journal
Restart=always
Group=mqtt-broker
TimeoutSec=120

[Install]
WantedBy=multi-user.target

EOF

touch /etc/intel-manageability/public/mqtt-broker/mosquitto.conf
cat >> /etc/intel-manageability/public/mqtt-broker/mosquitto.conf <<EOF
pid_file /var/run/mosquitto.pid

persistence true
persistence_location /var/lib/mosquitto/

require_certificate true
port 8883
user root

cafile /etc/intel-manageability/public/mqtt-ca/mqtt-ca.crt
certfile /etc/intel-manageability/public/mqtt-broker/mqtt-broker.crt
keyfile /etc/intel-manageability/secret/mqtt-broker/mqtt-broker.key

allow_anonymous false
use_identity_as_username true
acl_file /etc/intel-manageability/public/mqtt-broker/acl.file

log_dest file /var/persistent-log/mosquitto/mosquitto.log
log_dest stdout
EOF

touch /etc/intel-manageability/public/mqtt-broker/acl.file
cat >> /etc/intel-manageability/public/mqtt-broker/acl.file <<EOF
user vision-agent
topic vision/#
topic readwrite ma/request/+
topic readwrite manageability/response
topic readwrite manageability/event
topic readwrite manageability/telemetry
topic readwrite vision/state
topic readwrite ma/configuration/update/+
topic readwrite ma/configuration/response/#
topic readwrite ma/configuration/command/+

user node-agent
topic node/#
topic readwrite manageability/request/+
topic readwrite manageability/telemetry
topic readwrite manageability/event
topic readwrite manageability/response
topic readwrite node/state

user dispatcher-agent
topic write ma/configuration/update/+

EOF

mkdir -p /var/persistent-log/mosquitto/
touch /var/persistent-log/mosquitto/mosquitto.log
chmod 666 /var/persistent-log/mosquitto/mosquitto.log
