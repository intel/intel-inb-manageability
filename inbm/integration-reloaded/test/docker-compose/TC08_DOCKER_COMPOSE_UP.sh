#!/bin/bash
set -e # DO NOT REMOVE -- used to fail test if intermediate command fails
set -x

source /scripts/test_util.sh

DOCKER_COMPOSE_UP_XML="<?xml version='1.0' encoding='utf-8'?><manifest><type>ota</type><ota><header><id>sampleId</id><name>Sample AOTA</name><description>Sample AOTA manifest file</description><type>aota</type><repo>remote</repo></header><type><aota name='sample-docker-compose-up'><cmd>up</cmd><app>compose</app><fetch>http://127.0.0.1:80/simple-compose.tar.gz</fetch><version>1.0</version><containerTag>simple-compose</containerTag></aota></type></ota></manifest>"

start_time=$(get_time)
test_echo TC08 Docker Compose Up
test_echo Check that docker-compose container is not already running.
! (curl http://localhost:9876/content.txt | grep ABC) >&/dev/null
test_echo Container is not already running, good.
test_echo Simple docker-compose up test via manifest.
trigger_ota "${DOCKER_COMPOSE_UP_XML}"
listen_ota | grep 200
curl http://localhost:9876/content.txt | grep ABC
test_echo docker-compose up test passed.
sleep 3
clean_up_subscribe

