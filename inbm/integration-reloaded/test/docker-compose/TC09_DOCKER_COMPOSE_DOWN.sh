#!/bin/bash
set -e # DO NOT REMOVE -- used to fail test if intermediate command fails

source /scripts/test_util.sh

DOCKER_COMPOSE_DOWN_XML="<?xml version='1.0' encoding='utf-8'?><manifest><type>ota</type><ota><header><id>sampleId</id><name>Sample AOTA</name><description>Sample AOTA manifest file</description><type>aota</type><repo>remote</repo></header><type><aota name='sample-docker-compose-down'><cmd>down</cmd><app>compose</app><version>1.0</version><containerTag>simple-compose</containerTag></aota></type></ota></manifest>"

start_time=$(get_time)
test_echo TC09 Docker Compose Down
test_echo Simple docker-compose down test via manifest.
(if (listen_ota | grep 300); then
echo  passed
clean_up_subscribe
else
print_all_error
fi) &
trigger_ota "${DOCKER_COMPOSE_DOWN_XML}"
sleep 3
! (curl http://localhost:9876/content.txt | grep ABC) >&/dev/null
test_echo docker-compose down test passed.


