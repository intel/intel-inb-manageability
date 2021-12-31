#!/bin/bash
 
printf '\7\0\0\0\4\0\0\0\0\0\0\0' > /sys/firmware/efi/efivars/OsIndications-8be4df61-93ca-11d2-aa0d-00e098032b8c
 
rm -rf /boot/efi/EFI/UpdateCapsule/
mkdir -p /boot/efi/EFI/UpdateCapsule/
cp -f $1 /boot/efi/EFI/UpdateCapsule/
