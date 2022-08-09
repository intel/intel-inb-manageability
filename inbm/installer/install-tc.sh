#!/bin/bash
set -eo pipefail
# Shell script that installs Intel Manageability framework after confirming dependencies are met.
# Usage:
#   Run with SSL Certificates (default): sudo ./install-tc.sh
#   Run without SSL Certificates (dev): sudo ./install-tc.sh dev

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

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

# Failed checks will terminate the script with a message to operator.
# Ensure we're running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Ensure we're running a supported OS
verified_os_list=("Ubuntu 20.04" "Ubuntu 21.10" "Ubuntu 22.04")

if [[ ${verified_os_list[@]} == *"$(lsb_release -rs)"* ]]; then
  OS_TYPE="Ubuntu-$(lsb_release -rs)"
  echo "Confirmed Supported Platform (Ubuntu $(lsb_release -rs))"
elif [ "$(lsb_release -sc)" == "buster" ] | [ "$(lsb_release -sc)" == "bullseye" ] ; then
  OS_TYPE="Debian"
  echo "Confirmed Supported Platform (Debian $(lsb_release -sc))"
else
  echo "WARNING: Unverified OS version detected. Recommend use of verified OS versions: ${verified_os_list[@]}"
fi


check_no_insecure_user mqtt-broker

if ! [[ "$ACCEPT_INTEL_LICENSE" == "true" ]]; then
  less LICENSE || ( echo "Cannot find license." && exit 1)
  read -p "Do you accept the license? [Y/N] " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "License accepted."
  else
    echo "Installer requires accepting the license."
    exit 1
  fi
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

# Confirm Docker is installed
if [ -x "$(command -v docker)" ]; then
  # Docker is installed
  echo "Confirmed Docker Engine"
else
  # Docker is not installed
  echo "Docker not found. Installing automatically."
  echo "Running apt-get update..."
  apt-get update >&/dev/null
  echo "Installing Docker..."
  apt-get -y install docker.io
  echo "Setting proxies for Docker..."
  DOCKER_SERVICE_D="/etc/systemd/system/docker.service.d"
  mkdir -p "$DOCKER_SERVICE_D"
  if ! [[ "x$http_proxy" == "x" ]]; then
    cat >"$DOCKER_SERVICE_D"/im-http-proxy.conf << EOF
    [Service]
    Environment="HTTP_PROXY=$http_proxy"
EOF
  fi
  if ! [[ "x$https_proxy" == "x" ]]; then
    cat >"$DOCKER_SERVICE_D"/im-https-proxy.conf << EOF
    [Service]
    Environment="HTTPS_PROXY=$https_proxy"
EOF
  fi
  if ! [[ "x$no_proxy" == "x" ]]; then
    cat >"$DOCKER_SERVICE_D"/im-no-proxy.conf << EOF
    [Service]
    Environment="NO_PROXY=$no_proxy"
EOF
  fi
  systemctl daemon-reload
  systemctl enable docker
  systemctl restart docker
  echo "Docker installed. Running self test."
  if docker run registry.hub.docker.com/library/hello-world ; then
    echo "Docker confirmed good."
  else
    echo "Problem running docker run registry.hub.docker.com/library/hello-world; exiting."
    exit 1
  fi
fi

echo "Stopping previous versions (if any) for upgrade..."
# Remove previous versions/stop previous services for upgrade.
for i in inbm-configuration inbm-dispatcher inbm-dispatcher inbm-telemetry inbm-diagnostic inbm-cloudadapter inbm configuration dispatcher telemetry diagnostic cloudadapter mqtt ; do
    systemctl disable --now $i >&/dev/null || true
done
dpkg --remove --force-all no-tpm-provision tpm-provision inbm-configuration-agent configuration-agent inbm-dispatcher-agent dispatcher-agent inbm-diagnostic-agent diagnostic-agent inbm-cloudadapter-agent cloudadapter-agent inbm-telemetry-agent telemetry-agent mqtt-agent trtl mqtt >&/dev/null || true

echo "Ensuring packages are installed: lxc mosquitto cryptsetup less docker-compose"
apt-get update >&/dev/null
if [ "$OS_TYPE" == "Debian" ]; then
  apt-get install -y lxc
else
  apt-get install -y lxc
  apt-get -y purge mosquitto || true
fi

apt-mark unhold mosquitto
apt-get install -y mosquitto
systemctl disable mosquitto
systemctl stop mosquitto
apt-get install -y -f cryptsetup less docker-compose python3-pip

if [ "$(findmnt -lo source,target,fstype,label,options,used -t btrfs)" ]; then
  echo "BTRFS filesystem detected. Ensuring snapper is installed to enable Rollback capability..."
  apt-get install -y -f snapper
else
  echo "WARNING: Rollback functionality is not supported on a non-btrfs filesystem."
fi

# workaround for docker-compose credential helper
# it is OK if it fails; only need to mv the file if it exists
mv /usr/bin/docker-credential-secretservice /usr/bin/docker-credential-secretservice.broken >&/dev/null || true

# Use script directory as installation directory
INST="$DIR"

# Confirm expected packages exist.
FOUND_INSTALL_PACKAGE="false"
for file in "$INST"/*.preview.tar.gz; do
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

# install TRTL
echo "Will install trtl executable"

if ! dpkg -i trtl-*.deb ; then
  echo "Issue with installation. Will force."
  apt-get install -f
else
  echo "TRTL Installation Complete"
fi

# install INB
echo "Will install inbc executable"

if ! dpkg -i inbc*.deb ; then
  echo "Issue with installation. Will force."
  apt-get install -f
else
  echo "INBC Installation Complete"
fi


# install Agent(s)
echo "Will install Manageability Agents"
mkdir -p /cache # to unify with Yocto
dpkg -i ./*-agent-*.deb
if ! dpkg -i ./*-agent-*.deb ; then
  echo "Issue with installation. Will force."
  apt-get install -f
else
  echo "Agent Installation Complete"
fi

popd > /dev/null

rm -rf "$INST_DIR"

echo "Intel(R) In-Band Manageability Installation Complete"
exit 0
