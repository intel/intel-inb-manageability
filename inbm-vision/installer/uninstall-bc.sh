#!/bin/bash

set -eo pipefail

# Ensure we're running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi


#checking with user 
function vision_uninstall() {
    local agent="x"
    while [[ $agent == "x" ]]; do
        echo "please choose a agent service to uninstall:"
        echo " V - Vision Agent"
        echo " N - Node Agent"
        read -p "[H/N]" -n 1 -r agent
        echo 
    if [[ ! $agent =~ ^([Vv]|[Nn])$ ]]; then
      CLOUD="x"
    fi
    done

if [[ $agent =~ ^[Vv]$ ]]; then
    uninstall_vision
elif [[ $agent =~ ^[Nn]$ ]]; then
    uninstall_node
  fi

}

###uninstall node  
function uninstall_node {

    echo Stopping Node Agent services...
    systemctl stop inbm-node  >&/dev/null || true
    echo Disabling Node Agent services...
    systemctl disable inbm-node >&/dev/null || true
    echo Uninstalling Bit Creek Node packages...
    dpkg --purge inbm-node-agent
    echo Remove node-agent user/group
    if getent group node-agent ; then
      groupdel -f node-agent
    fi
    if getent passwd node-agent ; then
      deluser node-agent
      echo "node-agent user removed"
    else
      echo "node-agent user not found"
    fi
    echo Done.
}

#uninstall vision-agent
function uninstall_vision {
    echo Stopping vision-agent services...
    systemctl stop inbm-vision  >&/dev/null || true
    echo Disabling vision-agent services...
    systemctl disable inbm-vision >&/dev/null || true
    echo Uninstalling vision-agent packages...
    dpkg --purge inbm-vision-agent
    echo Remove vision-agent user/group
    if getent group vision-agent ; then
      groupdel -f vision-agent
    fi
    if getent passwd vision-agent ; then
      deluser vision-agent
      echo "vision-agent user removed"
    else
      echo "vision-agent user not found"
    fi
    echo Done.
}

vision_uninstall

exit 0

