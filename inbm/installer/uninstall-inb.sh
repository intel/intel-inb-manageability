#!/bin/bash

set -eo pipefail

function uninstall {
  # Ensure we're running as root
  if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
  fi

  if dpkg -l | grep dispatcher-agent; then
    uninstall_inb
  else
    uninstall_vision
  fi
}

function uninstall_inb {
  echo Stopping 'Intel(R)' In-Band Manageability services...
  systemctl stop inbm tpm2-abrmd tpm2-simulator mqtt inbm-vision >&/dev/null || true
  echo Disabling 'Intel(R)' In-Band Manageability services...
  systemctl disable inbm tpm2-abrmd inbm-vision mqtt >&/dev/null || true
  remove_xlink_modules_and_mqtt_keys
  echo Uninstalling 'Intel(R)' In-Band Manageability packages...
  dpkg --purge no-tpm-provision tpm-provision inbm-configuration-agent configuration-agent inbm-dispatcher-agent dispatcher-agent inbm-diagnostic-agent diagnostic-agent inbm-cloudadapter-agent cloudadapter-agent inbm-telemetry-agent telemetry-agent inbc-program inbm-vision-agent inbm-node-agent mqtt-agent trtl mqtt tpm2-abrmd tpm2-simulator tpm2-tools tpm2-tss inbc-program
  rm -rf /var/tpm2-simulator

  # Define array of user accounts = configuration, diagnostic, telemetry, cloudadapter
  declare -a arr=("configuration-agent" "diagnostic-agent" "telemetry-agent" "cloudadapter-agent" "vision-agent" "node-agent" "dispatcher-agent" "mqtt-ca" "inbc-program")
  # Loop through the user array and remove user
  for user in "${arr[@]}"
  do
     if getent group $user ; then
        groupdel -f $user
     fi
     if getent passwd $user ; then
        deluser $user
        echo "$user user removed"
     else
        echo "$user user not found"
     fi
  done

  echo "Uninstalling INB services complete."
  return 0
}

function uninstall_vision {
  echo Stopping 'Intel(R)' In-Band Manageability services...
  systemctl stop inbm-vision mqtt >&/dev/null || true
  systemctl stop inbm-node mqtt >&/dev/null || true
  echo Disabling 'Intel(R)' In-Band Manageability services...
  systemctl disable inbm-vision mqtt >&/dev/null || true
  systemctl disable inbm-node mqtt >&/dev/null || true
  remove_xlink_modules_and_mqtt_keys
  echo Uninstalling 'Intel(R)' In-Band Manageability packages...
  dpkg --purge no-tpm-provision tpm-provision inbm-node-agent inbm-vision-agent inbc-program mqtt-agent mqtt tpm2-abrmd tpm2-simulator tpm2-tools tpm2-tss

  if getent group node-agent ; then
     groupdel -f node-agent
  fi
  if getent passwd node-agent ; then
     deluser node-agent
     echo "node-agent user removed"
  else
     echo "node-agent user not found"
  fi

  if getent group vision-agent ; then
     groupdel -f vision-agent
  fi
  if getent passwd vision-agent ; then
     deluser vision-agent
     echo "vision-agent user removed"
  else
     echo "vision-agent user not found"
  fi

  echo "Uninstalling vision-agent and its dependency services complete."
  return 0
}

function remove_xlink_modules_and_mqtt_keys {
  echo Removing INB related modules...
  modprobe -r xlink || true
  modprobe -r mxlk || true
  #The following rm cmds are only for TBH platform
  rm /lib/firmware/xlink-driver/mxlk.ko || true
  rm /lib/firmware/xlink-driver/xlink.ko || true
  
  echo Removing secrets...
  /usr/bin/mqtt-remove-keys
  rm -rf /etc/intel-manageability 
}

uninstall
