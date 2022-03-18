# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

## NEXT - ?

## Fixed
 - RTC 509991 Updated docker stats dashboard to display units for readability.
 - HSD 15010649794 - INBC POTA/SOTA release date incorrect, SOTA schema change
 - HSD 15010868044 - Remove checking for isfile on destination before moving file
 - HSD 16016084283 - Change INBC to check for vision-agent process instead of waiting for MQTT message to determine the vision-agent service is running

## 3.0.9 - 2022-03-08
NOTE: This release has not yet been security tested.

### Fixed
- 509266 Vision agent post-install script fails
- HSD 1509485150, 47042 - Fix INBC fail to exit intermittently when using hddl_device_server
- (507873) Added support for Ubuntu 21.10
- HSD 15010686097, 509209 - Fix INBC query not printing correct time of fw-release-date
- HSD 15010749354 - Use XML schema to check for boundary conditions on integers in configuration files.  Validate set operations against schema.
- 505505 - Remove bootFlashlessDevice from vision configuration file
- HSD 15010640268 - Send only the SWID to Secure XLink API to avoid receiving the same GUID for each TBH.
- HSD 15010868050 - Fix manifest triggered POTA failed due to error "File does not exist or file path is not to a file"

## 3.0.8 - 2022-01-24

### Fixed
- 504494, HSD 15010332252 - Fix provision file not removed in /opt/xlink_provision when failed to reset device due to no matching device id
- 506035, HSD 15010309026 - Update node apparmor policy by adding /sys/kernel/xlink_secure/debug
- HSD 15010516458 - Fix storage checks failed during mender file transferring in SOTA/POTA
- 506874 - Fix node config schema error when upgrading from v2.16.0 to v2.17.2
- 507151 - Add lower bound, upper bound, and default values to node-agent configuration values.
- 507593 - Add lower bound, upper bound, and default values to vision-agent configuration values.
- 507150 - Rename Signature_version to hash_algorithm in manifest.  Add restricted values to manifest for hash_algorithm.

## 3.0.7 - 2022-01-04

## Fixed
 - Build from normal Internet connection fixed.

## 3.0.6 - 2021-12-31
This is the first open source release.

NOTE: Due to changing service names to include the inbm- prefix this release will require a new installation instead of an upgrade.

### Changed
 - Tweaked and updated documentation.

## 3.0.0-3.0.5 - 2021-12-16
These are the open source release candidates

### Fixed
 - Post-install script really fixed this time.
 - The post-install script for the vision agent has been fixed to enable the
   correct AppArmor profile.
 - Now using /usr/bin/vision as the binary name for the vision agent. (still inbm-vision for package and service)
 - Addressed some issues with the name of the vision agent in install scripts.

### Changed
 - 47548 - Rename node and vision agent services with inbm- prefix
