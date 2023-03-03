#!/bin/bash

# Shell script that configures the cloud service to use with the Cloudadapter Agent
# Copied and modified from iotg-inb/installer/install-tc.sh

# The purpose of this script is to allow quick cloud configuration
# without having to run the actual provision installer script

# Copyright (C) 2017-2023 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

# Usage:
# sudo ./config.sh
# Then follow onscreen instructions

set -eo pipefail

### INTEL PROXY
https_proxy_host="proxy-dmz.intel.com"
https_proxy_port="911"

### Ensure we're running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

########## FROM PROVISION-TC.SH ##########

CLOUD_DIR="/etc/intel-manageability/secret/cloudadapter-agent/"
CLOUD_FILE="adapter.cfg" # The main config file
cloud_config="" # The main config data

### Choose the cloud service to configure
function configure_cloud {
  mkdir -p $CLOUD_DIR

  if [[ -f $CLOUD_DIR$CLOUD_FILE ]]; then
    echo "A cloud configuration already exists: $(\
      grep -oP '"cloud":\s*\K"[_\-\w:\s]+"' $CLOUD_DIR$CLOUD_FILE)"
    echo "Replace configuration?"
    read -p "[Y/N] " -n 1 -r REPLY
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      find $CLOUD_DIR -maxdepth 1 -name "*.cfg" -type f -delete
    else
      return 0
    fi
  fi

  echo
  echo "Please choose a cloud service to use:"
  echo

  select cloud in "Telit Device Cloud" "Azure IoT Central" "ThingsBoard" "Custom"
  do
    case $cloud in
      "Telit Device Cloud")
        configure_telit
        break;;
      "Azure IoT Central")
        configure_azure
        break;;
      "ThingsBoard")
        configure_thingsboard
        break;;
      "Custom")
        configure_custom
        break;;
      *) echo "Invalid option!";;
    esac
  done

  # Write the config file
  echo $cloud_config > $CLOUD_DIR$CLOUD_FILE
  echo
  echo "Successfully configured cloud service!"
  echo
}

### Create Telit Configuration Files
function configure_telit {
  echo
  echo "Configuring to use Telit..."

  # Choose environment
  local TELIT_HOST="x"
  local TELIT_PORT="8883"
  local DEV_TELIT="api-dev.devicewise.com"
  local PRODUCTION_TELIT="api.devicewise.com"

  echo
  echo "Please select the Telit host to use:"

  select env in "Production  (${PRODUCTION_TELIT})" "Development (${DEV_TELIT})"
  do
    case $env in
      "Production  (${PRODUCTION_TELIT})")
        TELIT_HOST=$PRODUCTION_TELIT
        break;;
      "Development (${DEV_TELIT})")
        TELIT_HOST=$DEV_TELIT
        break;;
      *) echo "Invalid option!";;
    esac
  done

  # Get the Telit Token
  get_input "Provide Telit token:"\
            "Hint: https://wiki.ith.intel.com/display/TRTLCRK/Connecting+to+Helix+Device+Cloud"
  local TOKEN=$INPUT

  # Get the device id
  INPUT_DEFAULT="$(uuidgen)"
  get_input "Provide Telit Thing Key (leave blank to autogenerate):"
  local KEY=$INPUT

  # Let users know what key the device shows up as
  echo
  echo "Thing Key: $KEY"

  cloud_config="{
    \"cloud\": \"telit\",
    \"config\": {
      \"hostname\": \"$TELIT_HOST\",
      \"port\": $TELIT_PORT,
      \"key\": \"$KEY\",
      \"token\": \"$TOKEN\"
    }
  }"
}

### Azure IoT Central Configuration
function configure_azure {
  echo
  echo "Configuring to use Azure..."

  # Get the necessary information
  # TODO: Update the hints once the corresponding wiki entries are up
  get_input "Please enter the device Scope ID:" \
            "Hint: https://docs.microsoft.com/en-us/azure/iot-central/howto-generate-connection-string"
  local SCOPE_ID=$INPUT

  get_input "Please enter the Device ID:" \
            "Hint: https://docs.microsoft.com/en-us/azure/iot-central/howto-generate-connection-string"
  local DEVICE_ID=$INPUT

  get_input "Please enter the device SAS Primary Key:" \
            "Hint: https://docs.microsoft.com/en-us/azure/iot-central/howto-generate-connection-string"
  local DEVICE_KEY=$INPUT

  # Format the configuration file
  cloud_config="{
    \"cloud\": \"azure\",
    \"config\": {
      \"scope_id\": \"$SCOPE_ID\",
      \"device_id\": \"$DEVICE_ID\",
      \"device_key\": \"$DEVICE_KEY\"
    }
  }"
}

### ThingsBoard Configuration
function configure_thingsboard {
  echo
  echo "Configuring to use ThingsBoard..."

  # Get the server endpoint and device token
  get_input "Please enter the server IP:"
  local IP=$INPUT

  INPUT_DEFAULT="1883"
  get_input "Please enter the server port (default 1883):"
  local PORT=$INPUT

  get_input "Please enter the device token:"
  local TOKEN=$INPUT

  # Get the correct configuration JSON
  echo
  echo "Configure TLS?"
  read -p "[Y/N] " -n 1 -r REPLY
  echo
  local JSON=""
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Write the given ThingsBoard CA file
    local CA_PATH="${CLOUD_DIR}/thingsboard.pub.pem"
    get_file_input "Choose *.pub.pem file input method:"
    printf "%s" "$INPUT" > $CA_PATH
    # Use the TLS ThingsBoard template
    JSON=$(cat /usr/share/cloudadapter-agent/thingsboard/config_tls.json.template \
      | sed "s|{CA_PATH}|${CA_PATH}|g")
  else
    # Use the unencrypted ThingsBoard template
    JSON=$(cat /usr/share/cloudadapter-agent/thingsboard/config.json.template)
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
}

### Custom Configuration
function configure_custom {
  echo
  echo "Configuring to use a custom cloud service..."

  # Get a name
  get_input "Please enter a name for the cloud service:"
  local NAME=$INPUT

  # Get the data
  local JSON=""
  while [[ $JSON == "" ]]; do
    get_file_input "Choose JSON configuration input method:"
    JSON=$INPUT

    # Check against schema
    echo $JSON > TEMP.json
    if ! jsonschema -i TEMP.json /usr/share/cloudadapter-agent/config_schema.json; then
      echo
      echo "JSON is invalid!"
      JSON=""
    fi
    rm TEMP.json
  done

  # Format the configuration file
  cloud_config="{
    \"cloud\": \"custom: $NAME\",
    \"config\": $JSON
  }"
}

########## HELPER FUNCTIONS ##########

### Get a valid text input
# @param 1: The input request
# @param 2: The input hint
INPUT="x"
INPUT_DEFAULT="x"
function get_input {
  INPUT="x"
  while [[ $INPUT == "x" ]]; do
    echo
    echo "$1"
    read -e INPUT
    if [[ "x$INPUT" == "x" ]]; then
      if ! [[ "x$INPUT_DEFAULT" == "x" ]]; then
        INPUT=$INPUT_DEFAULT
        INPUT_DEFAULT=""
        return 0
      fi
      echo "Invalid input!"
      echo "$2"
      INPUT="x"
    fi
  done
}

### Get a multiline input
# @param 1: The input request
function get_multiline_input {
  INPUT=""
  local IN="x"
  echo
  echo $1
  while ! [[ "x$IN" == "x" ]]; do
    read -er IN
    INPUT=$INPUT$'\n'$IN
  done
}

### Get the contents of a "file"
# @param 1: The input request
function get_file_input {
  INPUT=""
  while [[ $INPUT == "" ]]; do
    echo
    echo $1
    select method in "Absolute file path" "Console input"
    do
      case $method in
        "Absolute file path")
          # Read data from file
          get_input "Please enter the file path:"
          local LOCATION=$INPUT
          if [[ -f $LOCATION && -r $LOCATION ]]; then
            INPUT=$(cat $LOCATION)
          else
            echo
            echo "Invalid file!"
          fi
          break;;
        "Console input")
          # Read directly from the stdin
          get_multiline_input "Please enter the data, followed by [ENTER] twice: "
          INPUT=$INPUT
          break;;
        *) echo "Invalid option!";;
      esac
    done
    if [[ $INPUT == "" ]]; then
      echo "No input given!"
    fi
  done
}

configure_cloud