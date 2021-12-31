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
#SOTA_MESSAGE='xlink_parser:revise_sota_manifest'
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
#(if listen_vision_ota | grep 389C0A; then
#  echo Target SOTA manifest received by vision from INBC
#else
#  echo printing errors...
#  #print_all_error
#  echo Error in sending target SOTA manifest.  Showing recent journalctl.
#  #journalctl -a --no-pager -n 50 | egrep "( cat|vision|dispatcher in system mode)"
#  echo VISION-AGENT JOURNAL LOG...
#  journalctl -u inbm-vision
#
#  echo NODE AGENT JOURNAL LOG...
#  journalctl -u inbm-node
#  exit 1
#fi) &
#
## Create dummy 20MB mender file
#fallocate -l 20M /var/cache/manageability/repository-tool/test.mender
#
#echo Send SOTA update via INBC
#inbc sota -p ${VAGRANT_INPUT_PATH}/U1170000F60X043.tar -t 389C0A
#
#echo "Wait 5 seconds..."
#sleep 5
#
#if journalctl -u inbm-dispatcher | grep 200 ; then
#  echo SOTA manifest publish good so far.
#else
#  journalctl -u inbm-dispatcher
#  echo Error in SOTA test.  Showing recent journalctl.
#  # journalctl -a --no-pager -n 50
#  exit 1
#fi
#
#echo "Wait 50 seconds for node processing the manifest..."
#sleep 50
#
#if journalctl -u inbm-node | grep $SOTA_MESSAGE; then
#  echo SOTA test passed.
#  echo wait 60 seconds for SOTA timer expired
#  sleep 60
#  clean_up_subscribe
#else
#  #print_all_error
#  echo Node process SOTA update request fail. Showing recent journalctl.
#  journalctl -a --no-pager -n 50 | egrep "( cat|vision|dispatcher in system mode)"
#
#  echo VISION-AGENT JOURNAL LOG...
#  journalctl -u inbm-vision
#
#  echo NODE AGENT JOURNAL LOG...
#  journalctl -u inbm-node
#  exit 1
#fi
