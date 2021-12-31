#!/bin/bash
set -e
set -x

DOCKER_BUILDKIT=0 docker build --build-arg http_proxy=http://proxy-chain.intel.com:911/ \
    --build-arg https_proxy=http://proxy-chain.intel.com:912/ \
    -t tpm2-tools \
    .

# Suppress output if there is no existing container
docker kill tpm2-tools-test 2>/dev/null || true
docker rm tpm2-tools-test 2>/dev/null || true

docker run -d --privileged -v /sys/fs/cgroup:/sys/fs/cgroup:ro --name tpm2-tools-test tpm2-tools

sleep 0.5
docker exec -it tpm2-tools-test /interactive-startup.sh
docker kill tpm2-tools-test
