#!/bin/bash
set -eo pipefail
# Shell script that installs Intel Manageability framework after confirming dependencies are met.
# Usage:
#   Run with SSL Certificates (default): sudo ./install-tc.sh
#   Run without SSL Certificates (dev): sudo ./install-tc.sh dev

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

trap_error() {
  echo "Command '$BASH_COMMAND' failed on line $BASH_LINENO.  Status=$?" >&2
  exit $?
}

trap trap_error ERR

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
verified_os_list=("Ubuntu 22.04" "Ubuntu 24.04")

if [[ ${verified_os_list[@]} == *"$(lsb_release -rs)"* ]]; then
  OS_TYPE="Ubuntu-$(lsb_release -rs)"
  echo "Confirmed Supported Platform (Ubuntu $(lsb_release -rs))"
elif [ "$(lsb_release -sc)" == "buster" ] | [ "$(lsb_release -sc)" == "bullseye" ] ; then
  OS_TYPE="Debian"
  echo "Confirmed Supported Platform (Debian $(lsb_release -sc))"
else
  echo "WARNING: Unverified OS version detected. Recommend use of verified OS versions: ${verified_os_list[@]}"
fi

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

echo "Ensuring prerequisite packages are installed."
apt-get update >&/dev/null
if [ "$OS_TYPE" == "Debian" ]; then
  apt-get install -y lxc
fi

if [ "$(findmnt -lo source,target,fstype,label,options,used -t btrfs)" ]; then
echo "BTRFS filesystem detected. Ensuring snapper is installed to enable Rollback capability..."
apt-get install -y -f snapper
else
echo "WARNING: Rollback functionality is not supported on a non-btrfs filesystem."
fi

# Use script directory as installation directory
INST="$DIR"

# Update shell to force dpkg to use bash during installation.
echo "dash dash/sh boolean false" | debconf-set-selections
if ! dpkg-reconfigure dash -f noninteractive; then
  echo "Unable to configure environment (dash->bash)"
  exit 1
fi

# Use script directory as installation directory
INST="$DIR"

# Confirm expected packages exist.
FOUND_INSTALL_PACKAGE="false"
INST_DIR=$(mktemp -d)
for file in "$INST"/*.deb; do
  if [ -e "$file" ]; then
    echo "Confirmed Installation Package: $file"
    FOUND_INSTALL_PACKAGE="true"    
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

# Ensure installation packages are present
if [[ $(ls "$INST_DIR" | grep ".deb" | wc -l) -eq 0 ]]; then
    echo "Installation packages not found. Exiting."
    exit 1
fi

pushd "$INST_DIR" > /dev/null

if [ $? -ne 0 ]; then
  echo "Issue with installation. Will force."
  apt-get install -f
else
  echo "Provisioner Installation Complete"
fi

# install INBC
echo "Will install INBC executable"

if ! dpkg -i intel-inbm*.deb ; then
  echo "Issue with INBM installation. Will force."
  apt-get install -f
  if ! dpkg -i intel-inbm*.deb ; then
    echo "Failed to install INBM after resolving dependencies."
    exit 1
  fi
else
  echo "INBM Installation Complete"
fi

popd > /dev/null

rm -rf "$INST_DIR"

echo "Intel(R) In-Band Manageability Installation Complete"
exit 0
