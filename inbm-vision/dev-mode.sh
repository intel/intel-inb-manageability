#!/bin/bash
set -euxo pipefail

# This script allows a developer to run Bit Creek with xlink simulator.
# The flows:
# 1. Change constants in libraries/manageability_library/constants.py.
#    a. Change VISION to vision.py
# 2. Change constants in vision and node constant.py.
#    a. RESPONSE_CHANNEL, EVENT_CHANNEL, TELEMETRY_CHANNEL in vision/constant.py
#    b. Schema and configuration location constants in both agent.
#
# To use the dev-mode.sh, enter command below:
# 1. To enable dev mode, enter: ./dev-mode.sh enable
#    a. To start vision agent with simulator:
#       i.  cd vision-agent
#       ii. sudo MQTT_HOST=localhost MQTT_CA_CERTS=/etc/intel-manageability/public/mqtt-ca/mqtt-ca.crt XLINK_SIMULATOR=True python3 -m vision.vision
#    b. To start inbm-node agent with simulator:
#       i.  cd node-agent
#       ii. sudo MQTT_HOST=localhost MQTT_CA_CERTS=/etc/intel-manageability/public/mqtt-ca/mqtt-ca.crt XLINK_SIMULATOR=True python3 -m node.node
#
# 2. To disable dev mode, enter: ./dev-mode.sh disable
#

CURRENT_DIRECTORY=$PWD
MANAGEABILITY_CONS_DIR="$CURRENT_DIRECTORY"/../inbm-lib/inbm_vision_lib/constants.py
VISION_CONS_DIR="$CURRENT_DIRECTORY"/vision-agent/vision/constant.py
NODE_CONS_DIR="$CURRENT_DIRECTORY"/node-agent/node/constant.py

if [ $1 = "enable" ]; then
    sed -i 's|VISION = "vision"|VISION = "vision.py"|g' $MANAGEABILITY_CONS_DIR

    sed -i "s|RESPONSE_CHANNEL = 'manageability/response'|RESPONSE_CHANNEL = 'manageability/response/'|g" $VISION_CONS_DIR
    sed -i "s|EVENT_CHANNEL = 'manageability/event'|EVENT_CHANNEL = 'manageability/event/'|g" $VISION_CONS_DIR
    sed -i "s|TELEMETRY_CHANNEL = 'manageability/telemetry'|TELEMETRY_CHANNEL = 'manageability/telemetry/'|g" $VISION_CONS_DIR
    sed -i "s|SCHEMA_LOCATION = '/usr/share/vision-agent/manifest_schema.xsd'|SCHEMA_LOCATION = 'fpm-template/usr/share/vision-agent/manifest_schema.xsd'|g" $VISION_CONS_DIR
    sed -i "s|CONFIG_LOCATION = '/etc/intel-manageability/public/vision-agent/intel_manageability_vision.conf'|CONFIG_LOCATION = 'fpm-template/etc/intel-manageability/public/vision-agent/intel_manageability_vision.conf'|g" $VISION_CONS_DIR
    sed -i "s|CONFIG_SCHEMA_LOCATION = '/usr/share/vision-agent/intel_manageability_vision_schema.xsd'|CONFIG_SCHEMA_LOCATION = 'fpm-template/usr/share/vision-agent/intel_manageability_vision_schema.xsd'|g" $VISION_CONS_DIR
    sed -i "s|XLINK_SCHEMA_LOCATION = '/usr/share/vision-agent/vision_xlink_schema.xsd'|XLINK_SCHEMA_LOCATION = 'fpm-template/usr/share/vision-agent/vision_xlink_schema.xsd'|g" $VISION_CONS_DIR

    sed -i "s|SCHEMA_LOCATION = '/usr/share/node-agent/manifest_schema.xsd'|SCHEMA_LOCATION = 'fpm-template/usr/share/node-agent/manifest_schema.xsd'|g" $NODE_CONS_DIR
    sed -i "s|CONFIG_LOCATION = '/etc/intel-manageability/public/node-agent/intel_manageability_node.conf'|CONFIG_LOCATION = 'fpm-template/etc/intel-manageability/public/node-agent/intel_manageability_node.conf'|g" $NODE_CONS_DIR
    sed -i "s|CONFIG_SCHEMA_LOCATION = '/usr/share/node-agent/intel_manageability_node_schema.xsd'|CONFIG_SCHEMA_LOCATION = 'fpm-template/usr/share/node-agent/intel_manageability_node_schema.xsd'|g" $NODE_CONS_DIR
    sed -i "s|XLINK_SCHEMA_LOCATION = '/usr/share/node-agent/node_xlink_schema.xsd'|XLINK_SCHEMA_LOCATION = 'fpm-template/usr/share/node-agent/node_xlink_schema.xsd'|g" $NODE_CONS_DIR
fi

if [ $1 = "disable" ]; then
    sed -i 's|VISION = "vision.py"|VISION = "vision"|g' $MANAGEABILITY_CONS_DIR

    sed -i "s|RESPONSE_CHANNEL = 'manageability/response/'|RESPONSE_CHANNEL = 'manageability/response'|g" $VISION_CONS_DIR
    sed -i "s|EVENT_CHANNEL = 'manageability/event/'|EVENT_CHANNEL = 'manageability/event'|g" $VISION_CONS_DIR
    sed -i "s|TELEMETRY_CHANNEL = 'manageability/telemetry/'|TELEMETRY_CHANNEL = 'manageability/telemetry'|g" $VISION_CONS_DIR
    sed -i "s|SCHEMA_LOCATION = 'fpm-template/usr/share/vision-agent/manifest_schema.xsd'|SCHEMA_LOCATION = '/usr/share/vision-agent/manifest_schema.xsd'|g" $VISION_CONS_DIR
    sed -i "s|CONFIG_LOCATION = 'fpm-template/etc/intel-manageability/public/vision-agent/intel_manageability_vision.conf'|CONFIG_LOCATION = '/etc/intel-manageability/public/vision-agent/intel_manageability_vision.conf'|g" $VISION_CONS_DIR
    sed -i "s|CONFIG_SCHEMA_LOCATION = 'fpm-template/usr/share/vision-agent/intel_manageability_vision_schema.xsd'|CONFIG_SCHEMA_LOCATION = '/usr/share/vision-agent/intel_manageability_vision_schema.xsd'|g" $VISION_CONS_DIR
    sed -i "s|XLINK_SCHEMA_LOCATION = 'fpm-template/usr/share/vision-agent/vision_xlink_schema.xsd'|XLINK_SCHEMA_LOCATION = '/usr/share/vision-agent/vision_xlink_schema.xsd'|g" $VISION_CONS_DIR

    sed -i "s|SCHEMA_LOCATION = 'fpm-template/usr/share/node-agent/manifest_schema.xsd'|SCHEMA_LOCATION = '/usr/share/node-agent/manifest_schema.xsd'|g" $NODE_CONS_DIR
    sed -i "s|CONFIG_LOCATION = 'fpm-template/etc/intel-manageability/public/node-agent/intel_manageability_node.conf'|CONFIG_LOCATION = '/etc/intel-manageability/public/node-agent/intel_manageability_node.conf'|g" $NODE_CONS_DIR
    sed -i "s|CONFIG_SCHEMA_LOCATION = 'fpm-template/usr/share/node-agent/intel_manageability_node_schema.xsd'|CONFIG_SCHEMA_LOCATION = '/usr/share/node-agent/intel_manageability_node_schema.xsd'|g" $NODE_CONS_DIR
    sed -i "s|XLINK_SCHEMA_LOCATION = 'fpm-template/usr/share/node-agent/node_xlink_schema.xsd'|XLINK_SCHEMA_LOCATION = '/usr/share/node-agent/node_xlink_schema.xsd'|g" $NODE_CONS_DIR
fi

echo Done

