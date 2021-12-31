#!/bin/bash

set -euxo pipefail

pip list
sed -i 's/ADAPTER_TYPE=hdc/ADAPTER_TYPE=test/g' /etc/dispatcher.environment
systemctl enable mqtt-keygen
systemctl start mqtt-keygen
systemctl enable inbm
systemctl start inbm

# Next step: enable these
# ps -G dispatcher-agent | grep dispatcher
# ps -G telemetry-agent | grep telemetry
# ps -G configuration-agent | grep configuration
# ps -G diagnostic-agent | grep diagnostic
# ps -G mqtt-broker | grep mosquitto
