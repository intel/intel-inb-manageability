#!/bin/bash
set -euxo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd "$DIR"
rm -rf "$DIR"/dist
mkdir -p "$DIR"/dist

"$DIR"/inbm/build.sh
mkdir -p "$DIR"/dist/inbm
cp "$DIR"/inbm/output/install*.sh "$DIR"/dist/inbm
cp "$DIR"/inbm/output/uninstall*.sh "$DIR"/dist/inbm
cp "$DIR"/inbm/output/Intel*.tar.gz "$DIR"/dist/inbm

"$DIR"/inbm-vision/build.sh
mkdir -p "$DIR"/dist/inbm-vision
cp "$DIR"/inbm-vision/output/*.deb "$DIR"/dist/inbm-vision
cp "$DIR"/inbm-vision/output/*install*.sh "$DIR"/dist/inbm-vision

cd "$DIR"
rm -rf inb_manageability_host_package
mkdir -p inb_manageability_host_package
cp inbm/installer/install-inb.sh inb_manageability_host_package/
cp inbm/installer/install-tc.sh inb_manageability_host_package/
cp inbm/installer/uninstall-inb.sh inb_manageability_host_package/
cp inbm/installer/uninstall-tc.sh inb_manageability_host_package/
cp LICENSE inb_manageability_host_package
cp dist/inbm-vision/*.deb inb_manageability_host_package/
cp third-party-programs.txt inb_manageability_host_package/
cp dist/inbm/Intel-Manageability.preview.tar.gz inb_manageability_host_package/
cat >inb_manageability_host_package/Release-README << EOF
QUICK README
=============
1.  To install both TC and BC run the install-inb.sh script with root privileges. Before running the script update the following fields in azure_conf_file with the necessary information to have device connected to cloud.
        - SCOPE_ID <refer Azure user guide documentation on how to fetch SCOPE_ID>
        - DEVICE_ID <a pretag to the device. The device-id will be later generated with an appended uuid later>
        - PRIMARY_KEY <refer Azure user guide documentation on how to fetch PRIMARY_KEY>

    To install only BC, run the command 'sudo ./install-inb.sh hddl'

2.  When installed TC and BC by running install-inb.sh, the device will be automatically on-boarded to Azure cloud using SAS primary key. The device-id generated will be stored under /usr/share/azure_conf_file. 
        Use this device-id info to check the device on the Azure cloud (https://intel-inband-manageability.azureiotcentral.com/devices).
        NOTE: Azure Auto-onboarding is supported only via SAS token.

3.  To uninstall, run 'sudo ./uninstall-inb.sh'  
EOF
cp inbm/cloudadapter-agent/fpm-template/usr/share/cloudadapter-agent/azure_template_link.txt inb_manageability_host_package/
cp inbm/packaging/misc-files/azure_conf_file inb_manageability_host_package/
rm -f inb_manageability_host_package.zip
zip -r inb_manageability_host_package.zip inb_manageability_host_package
mv inb_manageability_host_package.zip dist
rm -rf inb_manageability_host_package


cat >dist/README.txt <<EOF
Build output files
==================

inbm/install-inb.sh                         Installs both inbm and inbm-vision for Ubuntu or Debian
inbm/install-tc.sh                          Installs inbm for Ubuntu or Debian
inbm/uninstall-inb.sh                       Uninstalls both inbm and inbm-vision for Ubuntu or Debian
inbm/uninstall-tc.sh                        Uninstalls inbm for Ubuntu or Debian
inbm/Intel-Manageability.preview.tar.gz     Holds binary files for inbm

inbm-vision/install-bc.sh                   Installs vision or node agent from inbm-vision
inbm-vision/uninstall-bc.sh                 Uninstalls vision or node agent from inbm-vision
inbm-vision/*.deb                           Hold binary files for inbm-vision
inb_manageability_host_package.zip          Host package for inbm-vision
EOF
