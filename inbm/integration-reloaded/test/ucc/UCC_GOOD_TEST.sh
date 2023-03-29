#!/bin/bash
set -euxo pipefail # DO NOT REMOVE -- used to fail test if intermediate command fails

source /scripts/test_util.sh

start_time=$(get_time)
print_all_error() {
   echo "TEST FAILED!!!"
}
trap print_all_error ERR



UCC_MSG=""MessageHeader": {"Version": 1, "Type": "telemetry"}, "MessageBody": {"OperatingSystem": {"Name": "Microsoft_Windows_10_Enterprise", "Version": "10.0.10240", "platform": "x86"}, "MemoryInfo": {"InstalledPhysicalMemory": 8192, "AvailablePhysicalMemory": 786},"CpuInfo": {"VendorId:": "Genuine_Intel", "ModelName": "Intel®_Core_i7-4790_CPU_@_3.60GHz"}, "DiskInfo": [{"Name": "\Device\Harddisk0", "TotalSize": 128}, {"Name": "\Device_Harddisk1", "TotalSize": 936}] "NetworkInfo": [{"Name": "Ethernet_adapter_Ethernet", "PhysicalAddress": "12-34-56-78-9A-BC", "Ipv4Address": "192.168.0.100", "Primary": true, "UccActive": false}, {"Name": "Ethernet_adapter_Ethernet_2", "PhysicalAddress": "12-34-56-78-9A-BD", "Ipv4Address": "192.168.1.100", "Primary": false, "UccActive": false}, {"Name": "USB_Ethernet_adapter_Ethernet_3", "PhysicalAddress": "12-34-56-78-9A-BE", "Ipv4Address": "192.168.2.100", "Primary": false, "UccActive": false}, {"Name": "Wireless_LAN_adapter_Wi-Fi", "PhysicalAddress": "12-34-56-78-9A-BF", "Ipv4Address": "10.0.0.10", "Primary": false, "UccActive": true}] "Resolution": [{"width": 800, "height": 600, "active": false}, {"width": 1024, "height": 768, "active": false}, {"width": 1920, "height": 1080, "active": true}] "UccStatusInfo": {"UccClientName": "client1", "UccUserName": "UccUserDemo", "UccStatus": "Running", "UccImageId": 1, "UccImageName": "Win10", "UccImageFormat": "qcow2",   "UccImageRunningMode": "idv", "UccRemovableStorageAccess": false}}}"


test_echo Triggering Good UCC Test
listen_ucc_telemetry

trigger_ucc_msg "${UCC_MSG}"
sleep 1
if [ -s /tmp/listen_telemetry ]; then 
  echo UCC Good test good so far 
else 
  echo UCC Good test good so far
  journalctl -a --no-pager -n 50
  exit 1
fi
