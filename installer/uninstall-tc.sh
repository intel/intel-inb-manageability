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
systemctl disable --now inbd >&/dev/null || true

echo Uninstalling 'Intel(R)' In-Band Manageability packages...
dpkg --purge inbc-program
dpkg --purge inbd

declare -a arr=("inbc-program")
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

echo Done.

exit 0
