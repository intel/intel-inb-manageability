#!/bin/bash
set -eo pipefail


DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
INSTALL_DIR="$DIR"
CLOUD_FILE=$INSTALL_DIR/adapter.cfg # The main config file

function start {
  # Ensure we're running as root
  if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
  fi
  echo $INSTALL_DIR
  echo  "Generating cloud config file to onboard device to Thingsboard using INB container..."
  if [ ! -f $CLOUD_FILE ]; then
        install_and_provision
  else
    echo $CLOUD_FILE exist. Will not provision and create thingsboard.pub.pem.
    echo Please remove $CLOUD_FILE if you want to create thingsboard.pub.pem.
  fi

  docker_start
  echo "RUN 'docker exec -it inb /bin/bash' to enter the inb container"
}

function install_and_provision {
  conf_file=thingsboard_conf_file
  default_file=/usr/share/azure_conf_file
  while read -r line; do declare $line; done <$conf_file
  local IP=$TB_IP_ADDR
  local TOKEN=$DEVICE_TOKEN
  local TLS=$TLS
  local PEM_FILE_LOCATION=$TLS_PEM_FILE_LOCATION
  local PORT=$TB_PORT
  local DEVICE_CERTS=$x509_DEVICE_CERT
  CLOUD_DIR="/etc/intel-manageability/secret/cloudadapter-agent/"

  if [[ $TLS =~ ^[Yy]$ ]]; then
    if [[ -f $PEM_FILE_LOCATION && -r $PEM_FILE_LOCATION ]]; then
	PEM_INPUT=$(cat $PEM_FILE_LOCATION)
	echo $PEM_INPUT
	local CA_PATH="${INSTALL_DIR}/thingsboard.pub.pem"
	local CONTAINER_CA_PATH="${CLOUD_DIR}/thingsboard.pub.pem"
	rm CA_PATH || true
	printf "%s" "$PEM_INPUT" > $CA_PATH

	if [[ -f $DEVICE_CERTS && -r $DEVICE_CERTS ]]; then
	  CLIENT_PEM=$(cat $DEVICE_CERTS)
    echo $CLIENT_PEM
    local CLIENT_PEM_PATH="${INSTALL_DIR}/client.nopass.pem"
	  local CONTAINER_CLIENT_PEM_PATH="${CLOUD_DIR}/client.nopass.pem"
	  rm CLIENT_PEM_PATH || true
	  printf "%s" "$PEM_INPUT" > $CLIENT_PEM_PATH
	fi

	# Use the TLS ThingsBoard template
	JSON=$(cat $INSTALL_DIR/config_tls.json.template \
      	| sed "s|{CA_PATH}|${CONTAINER_CA_PATH}|g" \
        | sed "s|{CLIENT_CERT_PATH}|${CONTAINER_CLIENT_PEM_PATH}|g")
    else
        echo
        echo "Invalid PEM file!"
    fi
  else
    echo 'Non TLS mode'
    JSON=$(cat $INSTALL_DIR/config.json.template)
  fi
  # Format the configuration JSON
  JSON=$(echo $JSON \
    | sed "s/{TOKEN}/${TOKEN}/g" \
    | sed "s/{HOSTNAME}/${IP}/g" \
    | sed "s/{PORT}/${PORT}/g")

  # Format the configuration file
  cloud_config="{
    \"cloud\": \"thingsboard\",
    \"config\": $JSON
  }"
  echo $cloud_config > $INSTALL_DIR/adapter.cfg
  return 0
}


function docker_start {

  apparmor_parser -r docker-manageability-policy

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
    --cap-add SYS_ADMIN \
    --network=host \
    --tmpfs /run \
    --tmpfs /run/lock \
    --security-opt seccomp=unconfined --security-opt apparmor=docker-manageability-policy \
    -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v /var/cache/manageability/repository-tool:/var/cache/manageability/repository-tool \
    -v /:/host \
    inb
}

start
