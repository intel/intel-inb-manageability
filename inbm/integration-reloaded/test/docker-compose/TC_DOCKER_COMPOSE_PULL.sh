#!/bin/bash
set -e # DO NOT REMOVE -- used to fail test if intermediate command fails
set -x

source /scripts/test_util.sh

DOCKER_COMPOSE_PULL_XML="<?xml version='1.0' encoding='utf-8'?><manifest><type>ota</type><ota><header><id>sampleId</id><name>Sample AOTA</name><description>Sample AOTA manifest file</description><type>aota</type><repo>remote</repo></header><type><aota name='sample-docker-compose-up'><cmd>pull</cmd><app>compose</app><fetch>http://127.0.0.1:80/simple-compose.tar.gz</fetch><version>1.0</version><containerTag>simple-compose</containerTag></aota></type></ota></manifest>"

test_echo Simple docker-compose pull test via manifest.
trigger_ota "${DOCKER_COMPOSE_PULL_XML}"
listen_ota | grep 200
test_echo docker-compose pull test passed.
sleep 3
clean_up_subscribe
