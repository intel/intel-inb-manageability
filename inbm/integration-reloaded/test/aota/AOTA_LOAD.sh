#!/bin/bash
set -e
set -x

source /scripts/test_util.sh

trap 'kill -9 $(jobs -p) || true'  EXIT

test_failed() {
   echo "Return code: $?"
   echo "TEST FAILED!!!"
}
trap test_failed ERR

echo "Starting AOTA LOAD test." | systemd-cat

GOOD_XML='<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><id>sampleId</id><name>Sample AOTA</name><description>Sample AOTA manifest file</description><type>aota</type><repo>remote</repo></header><type><aota name="sample-rpm"><cmd>load</cmd><app>docker</app><fetch>http://127.0.0.1:80/sample-container-load.tgz</fetch><version>1.0</version><containerTag>sample-container</containerTag></aota></type></ota></manifest>'

test_echo AOTA LOAD

test_echo Making sure docker is good.
systemctl restart docker

test_echo Making sure image is unloaded.
if docker images | grep sample-container ; then
    docker rmi sample-container
fi

test_echo Loading image via manifest.
trigger_ota "${GOOD_XML}"
listen_ota | grep 200

test_echo Checking that image was loaded.
docker images | grep sample-container

test_echo Removing image.
docker rmi -f sample-container
