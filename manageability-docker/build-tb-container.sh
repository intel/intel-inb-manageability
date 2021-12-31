#!/bin/bash
set -euxo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd "$DIR"
rm -rf "$DIR"/output
mkdir -p "$DIR"/output
cd ../inbm

DOCKER_BUILDKIT=1 ./build.sh

cp output/Intel-Manageability.preview.tar.gz "$DIR"/output

cp cloudadapter-agent/fpm-template/usr/share/cloudadapter-agent/thingsboard/config_tls.json.template cloudadapter-agent/fpm-template/usr/share/cloudadapter-agent/thingsboard/config.json.template "$DIR"/output

cd "$DIR"
cp cloud_source docker-ble-policy Dockerfile docker-compose.yml mqtt_client.py run.sh tb_conf_file "$DIR"/output

cd output
zip -r inb_tb_container.zip *
