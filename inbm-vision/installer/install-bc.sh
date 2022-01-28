#!/bin/bash
set -eo pipefail
# Shell script that installs Bit Creek framework after confirming dependencies are met.
# Usage:
#   Run with SSL Certificates (default): sudo ./install-bc.sh
#   Run without SSL Certificates (dev): sudo ./install-bc.sh dev

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Failed checks will terminate the script with a message to operator.
# Ensure we're running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Ensure we're running Ubuntu 18 or 20 or 21.10
if [ "$(lsb_release -rs)" == "18.04" ] || [ "$(lsb_release -rs)" == "20.04" ] || [ "$(lsb_release -rs)" == "21.10" ]; then
  echo "Confirmed Supported Platform"
else
  echo "Unsupported Platform. Hint: http://releases.ubuntu.com/18.04/ (or 20.04/21.10)"
  exit 1
fi

# Ensure TC is installed
INTEL_MANAGEABILITY_PUBLIC="/etc/intel-manageability/public/"

if  [ "$(ls -A $INTEL_MANAGEABILITY_PUBLIC)" ]; then
    echo "$INTEL_MANAGEABILITY_PUBLIC exist"
    echo "Confirmed TC is installed"
else 
    echo "$INTEL_MANAGEABILITY_PUBLIC not exist"
    echo "Confirmed TC not installed"
    echo "Aborting install"
    exit 1
fi 

# Update shell to force dpkg to use bash during installation.
echo "dash dash/sh boolean false" | debconf-set-selections
if ! dpkg-reconfigure dash -f noninteractive; then
  echo "Unable to configure environment (dash->bash)"
  exit 1
fi

#check with user to install agent
function BC_install() {
    local agent="x"
    while [[ $agent == "x" ]]; do
        echo "please choose a agent service to use:"
        echo " V - Vision Agent"
        echo " N - Node Agent"
        read -p "[V/N]" -n 1 -r agent
        echo 
    if [[ ! $agent =~ ^([Vv]|[Nn])$ ]]; then
      CLOUD="x"
    fi
    done

if [[ $agent =~ ^[Vv]$ ]]; then
	install_inbc
    install_vision
    systemctl start inbm-vision
elif [[ $agent =~ ^[Nn]$ ]]; then
    install_node
    systemctl start inbm-node
  fi
}

#install vision-agent
function install_vision {
    echo "installing vision-agent"
    mkdir -p /lib/firmware/intel-flashless # create folder to store flashless files
    mkdir -p /cache # to unify with Yocto
    dpkg -i inbm-vision*-agent-*.deb
    if ! dpkg -i inbm-vision*-agent-*.deb ; then
       echo "Issue with installation. Will force."
       apt-get install -f
    
    else
      echo "Agent Installation Complete"
    fi
}

#install node-agent
function install_node {
    echo "installing node agent"
    mkdir -p /cache # to unify with Yocto

    dpkg -i inbm-node*-agent-*.deb
    if ! dpkg -i inbm-node*-agent-*.deb ; then
       echo "Issue with installation. Will force."
       apt-get install -f

    else
      echo "Agent Installation Complete"
    fi
}

#install inbc
function install_inbc {
    echo "installing inbc-program"

    dpkg -i inbc*-program-*.deb
    if ! dpkg -i inbc-program-*.deb ; then
       echo "Issue with installation. Will force."
       apt-get install -f

    else
      echo "inbc-program Installation Complete"
    fi
}

INST_DIR="$DIR"
# Ensure installation packages are present
if [[ $(ls "$INST_DIR" | grep ".deb" | wc -l) -eq 0 ]]; then
    echo "$INST_DIR"
    echo "Installation packages not found. Exiting."
    exit 1
else 
   echo "Installation package found. Proceed"
   BC_install
fi

echo "HDDL Installation Complete"
exit 0


