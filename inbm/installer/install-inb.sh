#!/bin/bash
set -eo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
INSTALL_DIR="$DIR"

# Function will print an error and exit with code 1 if a user exists
# and has a password set.
# If the user exists and has a shell other than {/usr,}/sbin/nologin, set shell to
# /usr/sbin/nologin
check_no_insecure_user() {
  local user_to_check="$1"

  # user exists?
  if getent passwd "$user_to_check" >&/dev/null ; then

    # password set?
    case $(passwd --status "$user_to_check" | awk '{print $2}') in
      NP) true ;; # does not have password set, continue
      L)  true ;; # user is locked out, continue
      P)  echo "User $user_to_check already exists and has a password. Exiting." ; exit 1 ;;
    esac

    # shell other than /sbin/nologin or /usr/sbin/nologin?
    local user_shell
    user_shell=$(getent passwd "$user_to_check" | cut -d: -f7)
    if [[ "$user_shell" == "/sbin/nologin" ]] || [[ "$user_shell" == "/usr/sbin/nologin" ]] ; then
      true
    else
      echo "User $user_to_check already exists and has insecure shell $user_shell. Changing shell to /usr/sbin/nologin."
      chsh -s /usr/sbin/nologin "$user_to_check"
    fi
  fi
}

function start {
  # Ensure we're running as root
  if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
  fi

  check_no_insecure_user mqtt-broker

  if [ -z $1 ]; then
    echo  "Onboard device to Azure (Installing In-band Manageability Framework and HDDL manageability)"
    install_and_provision
    check_inb_installed
    install_vision_package
  elif [ $1 == "hddl" ]; then     
    echo "Installing HDDL manageability only..."
    install_vision_requirements
    PROVISION_TPM=auto /usr/bin/mqtt-detect-tpm 
    install_vision_package
    remove_unused_tc_folders
  else
    echo "Invalid argument. Please run the install-inb script with no argument to install both In-Band and HDDL Manageability or provide an argument 'hddl' to only install HDDL manageability"
    exit 1
  fi
  echo "Installation complete."
}

function install_and_provision {
  # install TC artifacts
  ACCEPT_INTEL_LICENSE=true bash -x ./install-tc.sh
  sed -i 's/level=ERROR/level=DEBUG/g' /etc/intel-manageability//public/*/logging.ini

  # provision no-cloud initially
  NO_CLOUD=1 PROVISION_TPM=auto bash -x /usr/bin/provision-tc

  # setup the Azure cloudadapter config file
  configure_default_azure

  return 0
}

##################################
### Configuring Azure cloud services ###
##################################

CLOUD_DIR="/etc/intel-manageability/secret/cloudadapter-agent/"
CLOUD_FILE="adapter.cfg" # The main config file
cloud_config="" # The main config data

### Choose the cloud service to configure
function configure_default_azure {
  conf_file=azure_conf_file
  default_file=/usr/share/azure_conf_file
  rm -rf $default_file
  cp "$INSTALL_DIR/$conf_file" "$default_file"
  echo "Installing Dependencies"
  apt-get install -y npm uuid-runtime
  if timeout 300 npm i -g dps-keygen; then
    echo "dps-keygen installed"
  else
    echo "Time-out while installing dps-keygen using npm. Cannot proceed with cloud provisioning."
    exit 1
  fi
  while read -r line; do declare "$line"; done </usr/share/azure_conf_file
  SCOPE_ID=$SCOPE_ID
  DEVICE_ID=$DEVICE_ID-$(uuidgen)
  echo "$DEVICE_ID"
  TEMPLATE_URN=$TEMPLATE_URN
  echo "$TEMPLATE_URN"
  sed -ir "s/^[#]*\s*DEVICE_ID=.*/DEVICE_ID=$DEVICE_ID/" $default_file
  PRIMARY_KEY=$PRIMARY_KEY
  DEVICE_SAS_KEY=`dps-keygen -mk:"$PRIMARY_KEY" -di:"$DEVICE_ID" | tail -2 | xargs`
  mkdir -p $CLOUD_DIR

  echo "Configuring to use Azure..."
  # Get the necessary information
  # TODO: Update the hints once the corresponding wiki entries are up
  while read -r line; do declare "$line"; done </usr/share/azure_conf_file
  local SCOPE_ID=$SCOPE_ID
  local DEVICE_ID=$DEVICE_ID
  local DEVICE_KEY=$DEVICE_KEY
  local TEMPLATE_URN=$TEMPLATE_URN
  local DEVICE_CERT=$DEVICE_CERT

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
  cat >$CLOUD_DIR$CLOUD_FILE <<EOF 
  $cloud_config
EOF
  
  echo
  echo "Successfully configured Azure cloud service!"
  echo
  systemctl restart inbm-cloudadapter
  echo "Successfully configured Azure cloud service!"
}

function install_vision_requirements {
  # Ensure we're running a supported OS
  verified_os_list=("Ubuntu 20.04" "Ubuntu 21.10" "Ubuntu 22.04")

  if [[ ${verified_os_list[@]} == *"$(lsb_release -rs)"* ]]; then
    OS_TYPE="Ubuntu-$(lsb_release -rs)"
    echo "Confirmed Supported Platform (Ubuntu $(lsb_release -rs))"
  else
    echo "WARNING: Unverified OS version detected. Recommend use of verified OS versions: ${verified_os_list[@]}"
  fi

  # Read proxy information from the environment

  if [[ "x$http_proxy" == "x" ]]; then
    http_proxy="$HTTP_PROXY"
  fi

  if [[ "x$https_proxy" == "x" ]]; then
    https_proxy="$HTTPS_PROXY"
  fi

  if [[ "x$no_proxy" == "x" ]]; then
    no_proxy="$NO_PROXY"
  fi
  apt-get purge -y mosquitto || true
  apt-get install -y lxc dkms
  apt-get update >&/dev/null
  apt-mark unhold mosquitto
  apt-get install -y mosquitto
  systemctl disable mosquitto
  systemctl stop mosquitto
  apt-get install -y -f cryptsetup less

  INST_DIR="$DIR"
  # Confirm expected packages exist.
  FOUND_INSTALL_PACKAGE="false"
  for file in "$INST_DIR"/*.preview.tar.gz; do
    if [ -e "$file" ]; then
      echo "Confirmed Installation Package: $file"
      FOUND_INSTALL_PACKAGE="true"
      INST_DIR=$(mktemp -d)
      cp -rv "$file" "$INST_DIR"
    fi
  done

  if [ "$FOUND_INSTALL_PACKAGE" == "false" ]; then
    echo "Intel Manageability installation package is missing."
    exit 1
  fi

  # Update shell to force dpkg to use bash during installation.
  echo "dash dash/sh boolean false" | debconf-set-selections
  if ! dpkg-reconfigure dash -f noninteractive; then
    echo "Unable to configure environment (dash->bash)"
    exit 1
  fi

  # From this point, failed checks will be remediated.


  # If all pre-requisites are met, install Intel Manageability framework
  # Extract installation packages
  # Convert to cpio function to preserve user permissions?
  for i in $(ls "$INST_DIR" | grep preview.tar.gz); do
      if ! tar -xzf "$INST_DIR/$i" -C "$INST_DIR/"; then
          echo "Issue with extracting packages. Exiting."
          exit 1
      fi
  done
  # Ensure installation packages are present
  if [[ $(ls "$INST_DIR" | grep ".deb" | wc -l) -eq 0 ]]; then
      echo "Installation packages not found. Exiting."
      exit 1
  fi

  pushd "$INST_DIR" > /dev/null


  # install tpm tools
  if [ "$(lsb_release -rs)" == "20.04" ]; then
    apt-get install -y tpm2-tools tpm2-abrmd libtss2-tcti-tabrmd0
    systemctl enable --now tpm2-abrmd
    ln -sf libtss2-tcti-tabrmd.so.0 /lib/x86_64-linux-gnu/libtss2-tcti-default.so
  elif [ "$(lsb_release -rs)" == "21.10" ]; then
    apt-get install -y tpm2-tools tpm2-abrmd
    systemctl enable --now tpm2-abrmd
  elif [ "$(lsb_release -rs)" == "22.04" ]; then
    apt-get install -y tpm2-tools tpm2-abrmd
    systemctl enable tpm2-abrmd
  else
    apt-get install -y tpm2-tools tpm2-abrmd
    systemctl enable tpm2-abrmd
  fi

  if [ $? -ne 0 ]; then
    echo "Issue with installation. Will force."
    apt-get install -f
  else
    echo "Provisioner Installation Complete"
  fi

  # install tpm-provision
  dpkg -i tpm-provision*.deb


  # Now the easy part!
  # install MQTT service
  echo ""
  echo "** Will install MQTT Service."
  if ! dpkg -i mqtt-*.deb ; then
    echo "Issue with installation. Will force."
    apt-get install -f
  else
    echo "MQTT Installation Complete"
  fi
  popd > /dev/null
  
  rm -rf "$INST_DIR"
}

#check with user to install agent
function install_vision_package() {
  DEB_FILES=( "VISION:inbm-vision*-agent*.deb"
        "INBC:inbc*.deb" )
  if [[ $(dpkg -l | grep kmb-xlink | wc -l) -gt 0 ]]; then
      if [[ $(lsmod | grep xlink | wc -l) -eq 0 ]]; then
        echo "XLINK drivers present on the device but aren't loaded. Loading modules mxlk and xlink..."
        modprobe mxlk
        modprobe xlink
      fi
      # Commenting the below check because we still have an issue with HDDL drivers. Will uncomment once the issue is fixed.
      # if [[ $(dpkg -l | grep kmb-hddl | wc -l) -eq 0 ]]; then
      #   echo "Missing HDDL driver on the device. Install the HDDL drivers available from the package and run the install-inb.sh script..."
      #   exit 1
      # fi
  elif [[ $(dpkg -l | grep thb-hddl-xlink | wc -l) -gt 0 ]]; then
      if [[ $(lsmod | grep xlink | wc -l) -eq 0 ]]; then
        echo "XLINK drivers present on the device but aren't loaded. Loading modules mxlk and xlink..."
        modprobe mxlk
        modprobe xlink
      fi
  else
      echo "Missing XLINK driver on the device. Install the XLINK drivers available from the package and run the install-inb.sh script..."
      exit 1
  fi

  for file in "${DEB_FILES[@]}" ; do
      KEY="${file%%:*}"
      VALUE="${file##*:}"
      if [[ $(ls "$INSTALL_DIR" | grep $VALUE | wc -l) -eq 0 ]]; then
          echo "$KEY installation package not found. Aborting installation..."
          exit 1
      fi
  done
  echo "All required installation packages found. Installing packages..."
  install_vision_and_inbc
  systemctl enable --now inbm-vision mqtt
  return 0
}

function remove_unused_tc_folders {
    INTEL_MANAGEABILITY_PUBLIC="/etc/intel-manageability/public/"
    INTEL_MANAGEABILITY_SECRET="/etc/intel-manageability/secret/"
    for i in $INTEL_MANAGEABILITY_PUBLIC $INTEL_MANAGEABILITY_SECRET; do \
      cd $i && \
      for j in dispatcher telemetry diagnostic configuration cloudadapter; do \
        rm -rf ${j}-agent ; \
      done ; \
    done
}

###install vision-agent
function install_vision_and_inbc {
    echo "Installing vision-agent and other dependencies..."
    mkdir -p /lib/firmware/intel-flashless # create folder to store flashless files
    mkdir -p /cache # to unify with Yocto
    dpkg -i ./inbc-program*.deb ./inbm-vision*-agent-*.deb
    if [ $? -ne 0 ]; then
       echo "Issue with installation. Forcing installation."
       apt-get install -f
    else
      echo "Vision-agent and INBC program installed."
    fi
}

function check_inb_installed {
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
}

start $1
