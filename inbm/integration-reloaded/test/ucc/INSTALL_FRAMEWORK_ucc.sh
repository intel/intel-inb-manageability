#!/bin/bash

set -euxo pipefail

cd /vagrant/input

apt-get update

# Simulate user calling the installer
mkdir "install TC" # test install dir with spaces
cd "install TC"
cp ../ucc/*.tar.gz .
cp ../ucc/*.sh .
cp ../ucc/LICENSE .
rm -rf /etc/intel-manageability/public/cloudadapter-agent
mkdir -p /etc/intel-manageability/public/cloudadapter-agent
dpkg --purge docker-compose docker.io

# Check before install that docker is gone

fail_on_docker_packages() {
    set +e
    # Check if any installed package starts with the word 'docker'
    installed_packages=$(dpkg-query -W -f='${Package}\n' | grep -i '^docker')

    if [ ! -z "$installed_packages" ]; then
        echo "FAIL: Found installed packages starting with the word 'docker':"
        echo "$installed_packages"
        exit 1
    else
        echo "PASS: No installed packages starting with the word 'docker' found."
    fi
    set -e
}

fail_on_docker_packages


rm -rf /var/lib/apt/lists/*

## No TPM simulator in quicker mode
## DEV_MODE=true INSTALL_TPM2_SIMULATOR=false ACCEPT_INTEL_LICENSE=true bash -x ./install-tc.sh
## date

# Update shell to force dpkg to use bash during installation.
echo "dash dash/sh boolean false" | debconf-set-selections
if ! dpkg-reconfigure dash -f noninteractive; then
  echo "Unable to configure environment (dash->bash)"
  exit 1
fi


## SET UP MOCK UCC MOSQUITTO

# Create directories for certificates and configuration
sudo mkdir -p /etc/ucc_mosquitto/certs
sudo mkdir -p /etc/ucc_mosquitto/conf.d
sudo mkdir -p /var/run/ucc_mosquitto
sudo chown mosquitto: /var/run/ucc_mosquitto

# Generate CA key and certificate
sudo openssl genrsa -out /etc/ucc_mosquitto/certs/ca.key 2048
sudo openssl req -new -x509 -days 3650 -key /etc/ucc_mosquitto/certs/ca.key -out /etc/ucc_mosquitto/certs/ca.crt -subj "/CN=CA"

# Generate server key and certificate, sign with CA
sudo openssl genrsa -out /etc/ucc_mosquitto/certs/server.key 2048
sudo openssl req -new -key /etc/ucc_mosquitto/certs/server.key -out /etc/ucc_mosquitto/certs/server.csr -subj "/CN=localhost"
sudo openssl x509 -req -in /etc/ucc_mosquitto/certs/server.csr -CA /etc/ucc_mosquitto/certs/ca.crt -CAkey /etc/ucc_mosquitto/certs/ca.key -CAcreateserial -out /etc/ucc_mosquitto/certs/server.crt -days 3650

# Generate client key and certificate, sign with CA
sudo openssl genrsa -out /etc/ucc_mosquitto/certs/client.key 2048
sudo openssl req -new -key /etc/ucc_mosquitto/certs/client.key -out /etc/ucc_mosquitto/certs/client.csr -subj "/CN=localhost"
sudo openssl x509 -req -in /etc/ucc_mosquitto/certs/client.csr -CA /etc/ucc_mosquitto/certs/ca.crt -CAkey /etc/ucc_mosquitto/certs/ca.key -CAcreateserial -out /etc/ucc_mosquitto/certs/client.crt -days 3650

sudo chmod g+r /etc/ucc_mosquitto/certs/*
sudo chown root.mosquitto /etc/ucc_mosquitto/certs/*

# Set up mosquitto configuration
echo "pid_file /var/run/ucc_mosquitto/mosquitto.pid
listener 4000
cafile /etc/ucc_mosquitto/certs/ca.crt
certfile /etc/ucc_mosquitto/certs/server.crt
keyfile /etc/ucc_mosquitto/certs/server.key
require_certificate true
tls_version tlsv1.2" | sudo tee /etc/ucc_mosquitto/conf.d/mosquitto.conf

# Create systemd unit file
echo "[Unit]
Description=UCC Mosquitto MQTT Broker
After=network.target
Requires=network.target

[Service]
Type=simple
User=mosquitto
Group=mosquitto
ExecStart=/usr/sbin/mosquitto -c /etc/ucc_mosquitto/conf.d/mosquitto.conf
Restart=always

[Install]
WantedBy=multi-user.target" | sudo tee /etc/systemd/system/ucc-mosquitto.service

# Reload systemd and enable Mosquitto service
sudo systemctl daemon-reload
sudo systemctl enable ucc-mosquitto.service
sudo systemctl start ucc-mosquitto.service


tar -zxvf *ucc*.tar.gz

# no UCC_MODE=true here as the ucc install script should include it automatically
sudo -H DEV_MODE=true INSTALL_TPM2_SIMULATOR=false ACCEPT_INTEL_LICENSE=true bash -x ./install-tc-ucc.sh

fail_on_docker_packages

for i in cloudadapter ; do
  sed -i 's/ERROR/DEBUG/g' /etc/intel-manageability/public/"$i"-agent/logging.ini
done

cp /scripts/inb_fw_tool_info.conf /etc/firmware_tool_info.conf

NO_CLOUD=1 PROVISION_TPM=auto NO_OTA_CERT=1 TELIT_HOST="localhost" bash -x /usr/bin/provision-tc

# Copy certs/keys to paths expected by INBM
cp /etc/ucc_mosquitto/certs/client.crt /etc/intel-manageability/secret/cloudadapter-agent/client.crt
cp /etc/ucc_mosquitto/certs/client.key /etc/intel-manageability/secret/cloudadapter-agent/client.key
cp /etc/ucc_mosquitto/certs/ca.crt /etc/intel-manageability/secret/cloudadapter-agent/ucc.ca.pem.crt
chown root.cloudadapter-agent /etc/intel-manageability/secret/cloudadapter-agent/*
chmod u=rw,g=r,o= /etc/intel-manageability/secret/cloudadapter-agent/*

# NOTE: this has to be redone if we change the template or the
# inb-provision-cloud binary. Alternately we could create a script
# interface to inb-provision-cloud.
sudo dd of=/etc/intel-manageability/secret/cloudadapter-agent/adapter.cfg <<EOF
{
    "cloud": "ucc",
    "config": {
        "mqtt": {
            "client_id": "12345678abcd",
            "username": "",
            "hostname": "localhost",
            "port": 4000
        },
        "tls": {
            "version": "TLSv1.2",
            "certificates": "/etc/intel-manageability/secret/cloudadapter-agent/ucc.ca.pem.crt"
        },
        "x509": {
            "device_cert": "/etc/intel-manageability/secret/cloudadapter-agent/client.crt",
            "device_key": "/etc/intel-manageability/secret/cloudadapter-agent/client.key"
        },
        "event": {
            "pub": "uccctl/tel/req/123/12345678abcd",
            "format": "{raw_value}"
        },
        "telemetry": {
            "pub": "",
            "format": ""
        },
        "attribute": {
            "pub": "",
            "format": ""
        },
        "method": {
            "pub": "uccctl/cmd/res/123/12345678abcd",
            "format": "OK",
            "sub": "uccctl/cmd/req/123/12345678abcd"
        }
    }
}
EOF

systemctl restart inbm-cloudadapter

sleep 5
echo All processes:
ps -ax
echo Cloudadapter:
ps -ax | grep cloudadapter

UCC_NATIVE_CERTS_DIR="/etc/intel-manageability/secret/ucc-native-service"

if [ -d "$UCC_NATIVE_CERTS_DIR" ]; then
    echo "Directory $UCC_NATIVE_CERTS_DIR exists."
else
    echo "Directory $UCC_NATIVE_CERTS_DIR does not exist."
    exit 1
fi

pip3 install paho-mqtt==1.6.1
