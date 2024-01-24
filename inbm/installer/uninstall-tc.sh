#!/bin/bash

set -eo pipefail

trap_error() {
  echo "Command '$BASH_COMMAND' failed on line $BASH_LINENO.  Status=$?" >&2
  exit $?
}

trap trap_error ERR

# Ensure we're running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

if ! [[ "$ACCEPT_INTEL_LICENSE" == "true" ]]; then
  less LICENSE || ( echo "Cannot find license." && exit 1)
  read -p "Do you accept the license? [Y/N] " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "License accepted."
  else
    echo "Uninstaller requires accepting the license."
    exit 1
  fi
fi

echo Disabling and stopping 'Intel(R)' In-Band Manageability services...
systemctl disable --now inbm inbm-dispatcher inbm-diagnostic inbm-telemetry inbm-cloudadapter inbm-configuration tpm2-abrmd >&/dev/null || true
systemctl disable --now tpm2-simulator >&/dev/null || true
systemctl disable --now mqtt >&/dev/null || true
echo Removing secrets...
/usr/bin/mqtt-remove-keys
echo Uninstalling 'Intel(R)' In-Band Manageability packages...
dpkg --purge no-tpm-provision tpm-provision inbm-configuration-agent configuration-agent inbm-dispatcher-agent dispatcher-agent inbm-diagnostic-agent diagnostic-agent inbm-cloudadapter-agent cloudadapter-agent inbm-telemetry-agent telemetry-agent inbc-program mqtt-agent trtl mqtt tpm2-abrmd tpm2-simulator tpm2-tools tpm2-tss

# Define array of user accounts = configuration, diagnostic, telemetry, cloudadapter
declare -a arr=("configuration-agent" "diagnostic-agent" "telemetry-agent" "cloudadapter-agent" "mqtt-ca" "dispatcher-agent" "master-agent" "vision-agent" "node-agent" "inb_program" "inbc-program")
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

rm -rf /var/tpm2-simulator
rm -rf /etc/intel-manageability 
echo Done.

exit 0
