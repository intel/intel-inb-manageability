#!/bin/bash

# Copyright (C) 2021-2023 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

set -euxo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd "$DIR"
rm -rf "$DIR"/output
mkdir -p "$DIR"/output
cd ../inbm

./build.sh

cp output/Intel-Manageability.preview.tar.gz "$DIR"/output

cp cloudadapter-agent/fpm-template/usr/share/cloudadapter-agent/thingsboard/config_tls.json.template cloudadapter-agent/fpm-template/usr/share/cloudadapter-agent/thingsboard/config.json.template "$DIR"/output

cd "$DIR"
mv output tmp-output
cp cloud_source docker-manageability-policy Dockerfile docker-compose.yml sample_customer_mqtt_client.py run_thingsboard.sh thingsboard_conf_file "$DIR"/tmp-output

cd tmp-output
mv run_thingsboard.sh run.sh
mkdir -p ../output
zip -r ../output/inb_thingsboard_container.zip *
cd ..
rm -rf tmp-output
