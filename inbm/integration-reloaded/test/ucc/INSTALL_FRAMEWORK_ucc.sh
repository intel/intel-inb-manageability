#!/bin/bash

set -euxo pipefail

cd /vagrant/input

apt-get update

# Simulate user calling the installer
mkdir "install TC" # test install dir with spaces
cd "install TC"
cp ../*.preview.tar.gz .
cp ../*-tc.sh .
rm -rf /etc/intel-manageability/public/cloudadapter-agent
mkdir -p /etc/intel-manageability/public/cloudadapter-agent
apt-get purge -y docker-ce docker-ce-cli || true
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


tar -zxvf *.preview.tar.gz

sudo -H UCC_MODE=true DEV_MODE=true INSTALL_TPM2_SIMULATOR=false ACCEPT_INTEL_LICENSE=true bash -x ./install-tc.sh

for i in cloudadapter ; do
  sed -i 's/ERROR/DEBUG/g' /etc/intel-manageability/public/"$i"-agent/logging.ini
done

cp /scripts/inb_fw_tool_info.conf /etc/firmware_tool_info.conf

NO_CLOUD=1 PROVISION_TPM=auto NO_OTA_CERT=1 TELIT_HOST="localhost" bash -x /usr/bin/provision-tc
# NOTE: this has to be redone if we change the template or the
# inb-provision-cloud binary. Alternately we could create a script
# interface to inb-provision-cloud.
sudo dd of=/etc/intel-manageability/secret/cloudadapter-agent/adapter.cfg <<EOF
{ "cloud": "ucc", 
  "config": {
    "mqtt": {
        "username": "aabbccddeeff",
        "hostname": "127.0.0.1",
        "port": 1234
    },
    "event": {
        "pub": "TopicTelemetryInfo",
        "format": "{ \"ts\": \"{ts}\", \"values\": {\"telemetry\": \"{value}\"}}"
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
        "pub": "",
        "format": "",
        "sub": "",
        "parse": {
            "single": {
                "request_id": {
                    "regex": "",
                    "group": 1
                },
                "method": {
                    "path": "method"
                },
                "args": {
                    "path": "params"
                }
            }
        }
    }
  }
}
EOF

sleep 5
echo All processes:
ps -ax
echo Cloudadapter:
ps -ax | grep cloudadapter

