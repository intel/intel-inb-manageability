#!/bin/bash
set -euxo pipefail
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO=$DIR/.. # Repository root
ls -l

PACKAGING=${REPO}/packaging
mkdir -p ${PACKAGING}/input/agents/certs

for i in telemetry dispatcher diagnostic configuration cloudadapter
do
    cd ${REPO}/$i-agent
    make deb
    cp dist/*agent*.deb ${PACKAGING}/input/agents
    make rpm
    cp dist/*agent*.rpm ${PACKAGING}/input/agents
    
    cp fpm-template/usr/share/$i-agent/*.crt ${PACKAGING}/input/agents/certs
    cp fpm-template/usr/share/$i-agent/*.key ${PACKAGING}/input/agents/certs
done