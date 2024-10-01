#!/bin/bash

set -euxo # DO NOT REMOVE -- used to fail test if intermediate command fails

source /scripts/test_util.sh

error_exit() {
  rm -f /etc/force_yocto
  rm -f /usr/bin/mender
  rm -f /mender-was-run
}
trap 'error_exit' ERR

TEST_FILE="BIOSUPDATE.tar"

mkdir -p /var/log/sota_test

echo "Triggering SOTA integration test: SOTA YOCTO UPDATE DOWNLOAD"
echo "<START> SOTA YOCTO UPDATE DOWNLOAD" | systemd-cat
! [ -f /var/intel-manageability/dispatcher_state ]
touch /etc/force_yocto
ls -l /etc/force_yocto
date

mkdir -p /etc/mender
date --date="today" +"artifact_name=Release-%Y%m%d%H%M%S" >/etc/mender/artifact_info
sleep 1 # ensure second counter changes
cat >/usr/bin/mender <<EOF
#!/bin/sh

echo "Do not use mender client to examine current artifact version."
touch /mender-was-run
date --date="today" +"artifact_name=Release-%Y%m%d%H%M%S" >/etc/mender/artifact_info
EOF
chmod +x /usr/bin/mender

mkdir -p /etc/mender/scripts/
cat >/etc/mender/scripts/ArtifactInstall_Leave_00_relabel_ext4 <<EOF
#!/bin/sh

touch /mender-ext4-was-run
EOF
chmod +x /etc/mender/scripts/ArtifactInstall_Leave_00_relabel_ext4

rm -f "/var/cache/manageability/repository-tool/sota/$TEST_FILE"
! [ -f /var/cache/manageability/repository-tool/sota/"$TEST_FILE" ]

(if listen_ota | grep 200 ; then
  echo "<PASS> SOTA YOCTO UPDATE DOWNLOAD" | systemd-cat
  true
else
  echo Test failed to detect rebooting message...
  cat /tmp/listen_ota_last_log
  echo "<FAILED> SOTA YOCTO UPDATE DOWNLOAD" | systemd-cat
  journalctl -a --no-pager -n 150 | egrep "( cat|dispatcher in system mode)"
  false
fi) &

inbc sota --uri https://ci_nginx/BIOSUPDATE.tar

#[ -f /var/cache/manageability/repository-tool/sota/"$TEST_FILE" ] # ensure test file was downloaded
echo "<REBOOT> SOTA YOCTO UPDATE DOWNLOAD" | systemd-cat

sleep 5

