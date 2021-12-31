#!/bin/bash
set -e
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"


echo Rebooting machine...
vagrant ssh -c "sudo reboot -f -f" || /bin/true 
sleep 3

"$DIR"/vagrant-wait-for-up.sh
