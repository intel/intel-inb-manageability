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

echo "Starting AOTA IMPORT MULTIPLE test." | systemd-cat

GOOD_XML_1='<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><id>sampleId</id><name>Sample AOTA</name><description>Sample AOTA manifest file</description><type>aota</type><repo>remote</repo></header><type><aota name="sample-rpm"><cmd>import</cmd><app>docker</app><fetch>http://127.0.0.1:80/sample-container.tgz</fetch><version>1.0</version><containerTag>sample-container:5</containerTag></aota></type></ota></manifest>'
GOOD_XML_2='<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><id>sampleId</id><name>Sample AOTA</name><description>Sample AOTA manifest file</description><type>aota</type><repo>remote</repo></header><type><aota name="sample-rpm"><cmd>import</cmd><app>docker</app><fetch>http://127.0.0.1:80/sample-container.tgz</fetch><version>1.0</version><containerTag>sample-container:8</containerTag></aota></type></ota></manifest>'

test_echo AOTA IMPORT MULTIPLE
test_echo Making sure image version 5 is unloaded.
if docker images | grep sample-container | grep 5 ; then
    docker rmi sample-container:5
fi

test_echo Making sure image version 8 is unloaded.
if docker images | grep sample-container | grep 8 ; then
    docker rmi sample-container:8
fi

test_echo Loading image version 5 via manifest.
trigger_ota "${GOOD_XML_1}"
listen_ota | grep 200

test_echo Checking that image version 5 was loaded.
docker images | grep sample-container | grep 5

test_echo Loading image version 8 via manifest.
trigger_ota "${GOOD_XML_2}"
listen_ota | grep 200

test_echo Checking that image version 8 was loaded.
docker images | grep sample-container | grep 8

test_echo Removing image version 5.
docker rmi -f sample-container:5

test_echo Removing image version 8.
docker rmi -f sample-container:8
