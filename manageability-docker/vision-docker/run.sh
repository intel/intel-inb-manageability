#!/bin/bash
set -eox pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
INSTALL_DIR="$DIR"
CLOUD_FILE=$INSTALL_DIR/adapter.cfg # The main config file
PMSSHARE=build_pms_rm_container_pmsshare
export option=$1
function start {
  # Ensure we're running as root
  #echo $option
  if [ -z $option ]; then
    #echo $1
    echo "Please specify What would you want to do? sudo $0 --build or sudo $0 --deploy"
    exit 1
  fi
  if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
  fi
  echo $INSTALL_DIR
  echo  "Generating cloud config file to onboard device to Azure using INB container..."
  rm -rf adapter.cfg
  echo "removing file.."
  if [ ! -f $CLOUD_FILE ]; then
     configure_default_azure
  fi
  # Install xlink, flash logic and secure xlink
  check_driver
  # Remove flashless backup folder
  rm -r /lib/firmware/flashless_backup || true
  #docker_start
  echo "RUN 'docker exec -it inb /bin/bash' to enter the inb container"
}


function configure_default_azure {
  if [ "$(. /etc/os-release; echo $NAME)" == "Ubuntu" ]; then
     apt-get install -y npm uuid-runtime
  else
     echo "Make sure npm and nodejs v12 is installed on CentOS"
  fi

  if timeout 120 npm i -g dps-keygen; then
    echo "dps-keygen installed"
  else
    echo "Time-out while installing dps-keygen using npm. Cannot proceed with cloud provisioning."
    exit 1
  fi
  echo "Configuring to use Azure..."
  # Remove empty/blank lines in file
  sed -i '/^$/d' ./azure_conf_file
  # Get the necessary information
  # TODO: Update the hints once the corresponding wiki entries are up
  while read -r line; do declare "$line"; done < ./azure_conf_file
  local SCOPE_ID=$SCOPE_ID
  local DEVICE_ID=$DEVICE_ID-$(uuidgen)
  local DEVICE_KEY=$DEVICE_KEY
  local TEMPLATE_URN=$TEMPLATE_URN
  local DEVICE_CERT=$DEVICE_CERT

  PRIMARY_KEY=$PRIMARY_KEY
  DEVICE_SAS_KEY=`dps-keygen -mk:"$PRIMARY_KEY" -di:"$DEVICE_ID" | tail -2 | xargs`

  # Format the configuration file
  cloud_config="{
    \"cloud\": \"azure\",
    \"config\": {
      \"scope_id\": \"$SCOPE_ID\",
      \"device_id\": \"$DEVICE_ID\",
      \"device_cert\": \"$DEVICE_CERT\",
      \"device_key\": \"$DEVICE_KEY\",
      \"template_urn\": \"$TEMPLATE_URN\",
      \"device_sas_key\": \"$DEVICE_SAS_KEY\"
    }
  }"

  # Write the config file
  echo $cloud_config > $CLOUD_FILE
  echo
  echo "Created configuration to Azure cloud service!"
}

function check_driver {
  echo "Checking driver dependencies."
  if [[ $(lsmod | grep xlink | wc -l) -eq 0 ]]; then
    echo "Missing XLINK driver on the device. Please install and load the XLINK drivers and run the script again."
    exit 1
  fi
  if [[ $(lsmod | grep flash_logic | wc -l) -eq 0 ]]; then
    echo "Missing flash logic driver on the device. Please install and load the flash logic driver and run the script again."
    exit 1
  fi
  if ! [ -f /usr/lib/libSecureXLink.so ]; then
    echo "Missing libSecureXLink.so. Please install secure xlink on the device and run the script again."
    exit 1
  fi
  echo "Driver checking complete."
}
function containers_down() {
        echo "Wiping orphaned volumes/containers"
        docker-compose down
}

function docker_start {
  echo "Run inb container in detach mode."
  docker-compose up -d
  sleep 30
  rm -rf $CLOUD_FILE
  docker exec -it inb  systemctl --full --no-pager status mqtt inbm-dispatcher inbm-telemetry inbm-iagnostic inbm-configuration inbm-cloudadapter inbm-vision > inb.log
}
function build {
  echo "docker deploy.."
  docker-compose build
}
start
case $option in
        "--build")
                containers_down
                build
                exit 0
                ;;

        "--deploy")
                containers_down
                docker_start
                exit 0
                ;;

        *)
                exit 1
esac


