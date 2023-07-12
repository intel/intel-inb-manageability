#!/bin/bash
set -eo pipefail


DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
INSTALL_DIR="$DIR"
touch "$DIR"/adapter.cfg

function start {
  ../inbm/build-main.sh
  cp ../inbm/output-main/Intel-Manageability.preview.tar.gz .
  docker_start
  echo "RUN 'docker exec -it inb /bin/bash' to enter the inb container"
}

function docker_start {

  docker build \
      --build-arg HTTP_PROXY=${HTTP_PROXY:-} \
      --build-arg http_proxy=${http_proxy:-} \
      --build-arg HTTPS_PROXY=${HTTPS_PROXY:-} \
      --build-arg https_proxy=${https_proxy:-} \
      --build-arg NO_PROXY=${NO_PROXY:-} \
      --build-arg no_proxy=${no_proxy:-} \
        \
      -t inb \
      -f Dockerfile \
      .

  docker run \
    -d \
    -it \
    --name inb \
    --restart always \
    --privileged=true \
    --network=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v /var/cache/manageability/repository-tool:/var/cache/manageability/repository-tool \
    -v /:/host \
    inb
}
start
