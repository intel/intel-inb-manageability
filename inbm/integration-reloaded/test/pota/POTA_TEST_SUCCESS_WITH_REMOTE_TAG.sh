#!/bin/bash
set -e # DO NOT REMOVE -- used to fail test if intermediate command fails

source /scripts/test_util.sh

start_time=$(get_time)
print_all_error() {
   echo "TEST FAILED!!!"
    rm -f /etc/force_yocto
    rm -f /usr/bin/mender
    rm -f /mender-was-run
    rm -rf /var/lib/dispatcher/upload/*
    rm -rf /var/log/sota_test/*
    rm -rf /boot/efi/*
}
trap print_all_error ERR

TEST_FILE="BIOSUPDATE.tar"

test_echo "Copying new dmi Bios info"
cp /scripts/dmi_ami_bios_info/* /scripts/dmi_id_bios_info/

rm -rf /opt/afulnx
mkdir -p /opt/afulnx
cp /scripts/afulnx_64 /opt/afulnx/afulnx_64


mkdir -p /var/log/sota_test

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

POTA_GOOD_XML='<?xml version="1.0" encoding="UTF-8"?> <manifest>    <type>ota</type>    <ota>       <header>          <type>pota</type>          <repo>remote</repo>       </header>       <type>          <pota>             <fota name="sample">                <fetch>http://127.0.0.1:80/U1170000F60X043.bin</fetch>                <biosversion>5.12</biosversion>                <manufacturer>AMI Corporation</manufacturer>                <product>Aptio CRB</product>                <vendor>American Megatrends Inc.</vendor>                <releasedate>2018-02-08</releasedate>                <tooloptions>abc</tooloptions>             </fota>             <sota>                <cmd logtofile="N">update</cmd>                <fetch>https://ci_nginx/BIOSUPDATE.tar</fetch>                <release_date>2070-01-01</release_date>             </sota>          </pota>       </type>    </ota> </manifest>'

test_echo Triggering Good POTA REMOTE TAG Test

trigger_ota "${POTA_GOOD_XML}"

if (listen_ota | grep 'Reboot on hold after Firmware update'); then
  echo POTA REMOTE TEST FOTA good so far. Device not rebooting.
else
  print_all_error
  echo Error in POTA remote tag test for FOTA.  Showing recent journalctl.
  journalctl -a --no-pager -n 200
  exit 1
fi

if (listen_ota | grep 'SOTA command status: SUCCESSFUL'); then
  echo POTA REMOTE TEST SOTA good so far. Device rebooting.
  echo POTA REMOTE TAG TEST PASS
else
  print_all_error
  echo Error in POTA remote tag test for SOTA.  Showing recent journalctl.
  journalctl -a --no-pager -n 50
  exit 1
fi
