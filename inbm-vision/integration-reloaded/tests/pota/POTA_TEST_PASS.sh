# NOTE:  This test will never pass because the VM is on Ubuntu and installing with a manifest marked as 'local'.
# It will detect the OS as Ubuntu and try and do a debian update on the node.  This can not be done and it will send an error back.
# The only way to have a passing SOTA test for Bit Creek on the node, is to run the Node VM on Yocto and not Ubuntu.
# Since attempts to do this have been de-prioritized, we can not currently test Bit Creek SOTA in IT.

##!/bin/bash
#set -e # DO NOT REMOVE -- used to fail test if intermediate command fails
#
#DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
#source "$DIR"/../test_util.sh
#
#echo "Checking health of all services"
#check_health_vision_services
#echo "Health check passed"
#echo "Wait 10 seconds for all agent come up..."
#sleep 10
#
#systemctl start nginx
#
## Listen the channel first
#(if listen_vision_ota | grep pota; then
#  echo Target pota manifest is received by vision.
#else
#  echo printing errors...
#  echo Error in sending target pota manifest.  Showing recent journalctl.
#  echo VISION-AGENT JOURNAL LOG...
#  journalctl -u inbm-vision
#
#  echo NODE AGENT JOURNAL LOG...
#  journalctl -u inbm-node
#  exit 1
#fi) &
#
#echo Send FOTA INBC request
#inbc pota -fp ${VAGRANT_INPUT_PATH}/U1170000F60X043.tar -sp ${NGINX_DATA}/file.mender -m testmanufacturer -v "Intel Corp." -p "Broxton P"
#
#echo "Wait 20 seconds for node processing the manifest..."
#sleep 20
#
#if journalctl -u inbm-node | grep "revise_pota_manifest"; then
#  echo POTA test passed.
#  clean_up_subscribe
#else
#  #print_all_error
#  echo Node process POTA update request fail. Showing recent journalctl.
#
#  echo VISION, NODE, DISPATCHER AGENT JOURNAL LOG...
#  journalctl -u inbm-vision -u inbm-node -u dispatcher
#
#  exit 1
