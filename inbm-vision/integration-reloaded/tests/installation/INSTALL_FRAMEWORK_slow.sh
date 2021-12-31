#!/bin/bash

set -euxo pipefail

INTEL_MANAGEABILITY_PUBLIC="/etc/intel-manageability/public"

# Install TC
cd /vagrant/input
cp /scripts/succeed_rpm_cert.pem .
mkdir "install_TC"
cd "install_TC"

# File is generated from the 'Turtle Creek Evaluation release files' build in TeamCity.  Then added to the artifactory location designated in the link below.
cp /vagrant/input/Intel-Manageability.preview.tar.gz .
cp /vagrant/input/install-tc.sh .

rm -rf /etc/intel-manageability/public/cloudadapter-agent
mkdir -p /etc/intel-manageability/public/cloudadapter-agent
apt-get purge -y docker-ce docker-ce-cli || true
rm -rf /var/lib/apt/lists/*
echo "Installing Turtle Creek"
sudo -H ACCEPT_INTEL_LICENSE=true bash -x "$(pwd)"/install-tc.sh

sudo -H NO_CLOUD=x PROVISION_TPM=disable NO_OTA_CERT=1 /usr/bin/provision-tc

for i in dispatcher telemetry configuration diagnostic ; do
  sed -i 's/ERROR/DEBUG/g' /etc/intel-manageability/public/"$i"-agent/logging.ini
done

cp /tmp/turtle_creek_developer.conf /etc/intel_manageability.conf

echo "TC installation complete..."

# Install BC
echo "Install BC"
echo "Install node agent."
BC_DIR="/vagrant/input/output"

# Ensure Intel Manageability folder is exist
if  [ "$(ls -A $INTEL_MANAGEABILITY_PUBLIC)" ]; then
    echo "$INTEL_MANAGEABILITY_PUBLIC exist"
    echo "Confirmed TC is installed"
else
    echo "$INTEL_MANAGEABILITY_PUBLIC not exist"
    echo "Create $INTEL_MANAGEABILITY_PUBLIC"
    mkdir -p $INTEL_MANAGEABILITY_PUBLIC
fi

# Ensure BC folder is exist
if  [ "$(ls -A $BC_DIR)" ]; then
    echo "BC directory exist."
else
    echo "$BC_DIR not exist."
    echo "Change directory to input folder."
    BC_DIR="/vagrant/input"
fi

# Set environment for xlink simulator
XLINK_SIMULATOR=True

# Create dummy BIOS file
touch /var/cache/manageability/X041_BIOS.tar

cd $BC_DIR
# Disable start on node and vision agents after installation and before setting them to use xlink simulator
sed -i 's/systemctl start inbm-vision//g' install-bc.sh
sed -i 's/systemctl start inbm-node//g' install-bc.sh
chmod +x install-bc.sh

$BC_DIR/install-bc.sh << EOF
N
EOF

$BC_DIR/install-bc.sh << EOF
V
EOF

sed -i "s|XLINK_SIMULATOR=False|XLINK_SIMULATOR=True|g" /lib/systemd/system/inbm-vision.service
sed -i "s|XLINK_SIMULATOR=False|XLINK_SIMULATOR=True|g" /lib/systemd/system/inbm-node.service
# Set OTA time in vision-agent conf file to 120s to speed up the integration test
sed -i "s|600|120|g" /etc/intel-manageability/public/vision-agent/intel_manageability_vision.conf
# for sota and pota timer
sed -i "s|900|120|g" /etc/intel-manageability/public/vision-agent/intel_manageability_vision.conf
sed -i "s|900|120|g" /etc/intel-manageability/public/vision-agent/intel_manageability_vision.conf

# Temporarily disable vision-agent write access to event,telemetry and response channel
sed -i -z "s|topic write manageability/event|#topic write manageability/event|4" /etc/intel-manageability/public/mqtt-broker/acl.file
sed -i -z "s|topic write manageability/telemetry|#topic write manageability/telemetry|2" /etc/intel-manageability/public/mqtt-broker/acl.file
sed -i -z "s|topic write manageability/response|#topic write manageability/response|2" /etc/intel-manageability/public/mqtt-broker/acl.file
 
for i in node vision ; do
  sed -i 's/ERROR/DEBUG/g' /etc/intel-manageability/public/"$i"-agent/logging.ini
done

sleep 5 

# Daemon-reload to apply the changes in service file
systemctl disable inbm-vision inbm-node
systemctl stop inbm-vision inbm-node
systemctl daemon-reload
systemctl restart mqtt

echo "Bit Creek Installation Complete"

# Start TC and BC agents
systemctl enable inbm-node 
systemctl start inbm-node 
sleep 5
# Add write access so that vision-agent can access it
chmod a+w /tmp/xlink_mock
systemctl enable inbm-vision
systemctl start inbm-vision
sleep 5

# We don't connect to Telit in Integration Reloaded.
# Skipping cloudadapter.
systemctl enable inbm-telemetry inbm-diagnostic inbm-configuration inbm-dispatcher
systemctl start inbm-telemetry inbm-diagnostic inbm-configuration inbm-dispatcher

if ! timeout 5 systemctl stop inbm-telemetry inbm-diagnostic inbm-configuration inbm-dispatcher
then
  echo Agents took too long to stop or failed to stop.
fi

if ! timeout 5 systemctl start inbm-telemetry inbm-diagnostic inbm-configuration inbm-dispatcher
then
  echo Agents took too long to start or failed to start.
fi

# give agents a few seconds to stabilize
sleep 15

# show last few lines of journal for context
journalctl -a --no-pager -n 50

# check for agents being up
ps -G dispatcher-agent | grep dispatch
ps -G telemetry-agent | grep teleme
ps -G configuration-agent | grep config
ps -G diagnostic-agent | grep diagnos
ps -G mqtt-broker | grep mosquitto

echo "Install Framework Complete"
