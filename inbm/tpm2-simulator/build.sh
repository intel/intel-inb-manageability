#!/bin/bash
set -e
set -x

DOCKER_BUILDKIT=1 docker build \
    --build-arg HTTP_PROXY=${HTTP_PROXY:-} \
    --build-arg http_proxy=${http_proxy:-} \
    --build-arg HTTPS_PROXY=${HTTPS_PROXY:-} \
    --build-arg https_proxy=${https_proxy:-} \
    --build-arg NO_PROXY=${NO_PROXY:-} \
    --build-arg no_proxy=${no_proxy:-} \
    -t tpm2-tools \
    .

# Suppress output if there is no existing container
docker kill tpm2-tools-output 2>/dev/null || true
docker rm tpm2-tools-output 2>/dev/null || true

docker run -d --privileged -v /sys/fs/cgroup:/sys/fs/cgroup:ro --name tpm2-tools-output tpm2-tools

rm -rf debs*
docker cp 'tpm2-tools-output:/debs-20.04' ./debs-20.04/
[ -f debs-20.04/*simulator*deb ]
docker rm tpm2-tools-output
