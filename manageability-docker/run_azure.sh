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
  echo  "Onboard device to Azure (Installing In-band Manageability Framework and HDDL manageability)"
  if [ ! -f $CLOUD_FILE ]; then
        install_and_provision
  fi

  docker_start
  echo "RUN 'docker exec -it inb /bin/bash' to enter the inb container"
}

function install_and_provision {
  conf_file=azure_conf_file
  default_file=/usr/share/azure_conf_file
  rm -rf $default_file
  cp "$INSTALL_DIR/$conf_file" "$default_file"
  echo "Installing Dependencies"
  apt-get install -y npm uuid-runtime
  if timeout 120 npm i -g dps-keygen; then
    echo "dps-keygen installed"
  else
    echo "Time-out while installing dps-keygen using npm. Cannot proceed with cloud provisioning."
    exit 1
  fi
  while read -r line; do declare "$line"; done </usr/share/azure_conf_file
  SCOPE_ID=$SCOPE_ID
  #DEVICE_ID=$DEVICE_ID-$(uuidgen)
  echo "$DEVICE_ID"
  TEMPLATE_URN=$TEMPLATE_URN
  echo "$TEMPLATE_URN"
  #sed -ir "s/^[#]*\s*DEVICE_ID=.*/DEVICE_ID=$DEVICE_ID/" $default_file
  PRIMARY_KEY=$PRIMARY_KEY
  DEVICE_KEY=`dps-keygen -mk:"$PRIMARY_KEY" -di:"$DEVICE_ID" | tail -2 | xargs`
  echo "DEVICE_KEY=${DEVICE_KEY}" >> /usr/share/azure_conf_file
  configure_default_azure
  return 0
}

##################################
### Configuring Azure cloud services ###
##################################


cloud_config="" # The main config data

### Choose the cloud service to configure
function configure_default_azure {

  echo
  echo "Configuring to use Azure..."
  # Get the necessary information
  # TODO: Update the hints once the corresponding wiki entries are up
  while read -r line; do declare "$line"; done </usr/share/azure_conf_file
  local SCOPE_ID=$SCOPE_ID
  local DEVICE_ID=$DEVICE_ID
  local DEVICE_KEY=$DEVICE_KEY
  local TEMPLATE_URN=$TEMPLATE_URN
  
  echo "IN WRITING"
  # Format the configuration file
  cloud_config="{
    \"cloud\": \"azure\",
    \"config\": {
      \"scope_id\": \"$SCOPE_ID\",
      \"device_id\": \"$DEVICE_ID\",
      \"device_key\": \"$DEVICE_KEY\",
      \"template_urn\": \"$TEMPLATE_URN\"
    }
  }"

  # Write the config file
  echo $CLOUD_FILE
  echo $cloud_config
  echo $cloud_config > $CLOUD_FILE
  echo "END"
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
