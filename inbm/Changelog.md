# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

## NEXT - ?

## Fixed
 - HSD 15010509095 - INBC fail to return correct Exit Code for difference scenario (-4/-6/-11)
 - HSD 15010982715 - inbm-vision failed to receive query request from cloud
 - HSD 15011009937 - Remove POTA Failure error on Success
 - HSD 15010766920 - Fix Telemetry apparmor issue on Yocto

### Added
- RTC 508495 Support INBC Config Append command
- RTC 508497 Support INBC Config Remove command
- RTC 500237 - Remove DBS messages from appearing in INBC

## 3.0.10 - 2022-03-28

## NEXT - 3.0.9 - 2022-03-08
 - RTC 509991 Updated docker stats dashboard to display units for readability.
 - HSD 15010649794 - INBC POTA/SOTA release date incorrect, SOTA schema change
 - HSD 15010868044 - Remove checking for isfile on destination before moving file
 - HSD 15010868047 - "Unsupported OS" when running POTA via INBC in CentOS container
 - RTC 511101 - Handle the null char in a URI
 - HSD 15010918893 INBM does not reject unsupported file type
 - Fixed new build error discovered by clearing docker cache and rebuilding
 - HSD 15010766920 - Apparmor issue querying swbom information

## Security
 - RTC 510928 - Upgrade 3rd party deps to address CVE-2022-24921, CVE-2022-23648.
 - Update docker/distribution dependency for trtl to address GitHub security warning
 - Updated golang runtime for trtl and inb-provision-{certs, cloud, ota-cert}. Previous runtime (1.17.8) had a number of CVEs associated with it. New runtime version is 1.18.0.

## 3.0.9 - 2022-03-08
NOTE: This release has not yet been security tested.

## Fixed
 - Fixed that x86_64 Yocto output files were missing inbm- prefix
 - RTC 508366 - Fix Issues affecting Docker Stats command for AOTA and Dynamic Telemetry
 - RTC 508708 - Improve usability of AOTA Docker List command
 - RTC 508698 - [BUG] Diagnostic returns inbm-telemetry not running and fails OTA checks blocking the OTA
 - RTC 508367 - Fix Thingsboard 3.3 files to support Batch updates
 - RTC 508935 - [BUG] Dispatcher can't handle missing sota cache directory
 - RTC 508936 - Upgrading networkmanager fails during SOTA in container
 - HSD 15010715189 - Telemetry service failed to start when unable to find mender file
 - RTC 509436 - [BUG] SOTA in docker container cannot take snapshot in btrfs
 - HSD 15010407028 - Remove <hash_algorithm> tag before sending provisionNode manifest to vision-agent
 - No longer upload custom tpm2 debs with 21.10 PPA deploy script
 - RTC 509442 - [BUG] docker-compose fails in container due to docker-compose not being installed in container
 - RTC 509493 - [BUG] docker service is running unnecessarily in container, in container mod
 - RTC 509440 - Remove testing entries from intel_manageability.conf in release builds
 - RTC 509438 - [BUG] When installing .deb file (driver update) in container, .deb should be installed in host
 - RTC 495463 - Fix existing driver get uninstalled if AOTA update failed using .deb file package
 - RTC 509509 - Fixes a bug on develop branch that prevents reboot.
 - RTC 508711 - [BUG] Fix Thingsboard Docker Stats widget to display data
 - RTC 509640 - [BUG] INBC Query(swbom) to exit successfully 

### Added
 - (507873) Added support for Ubuntu 21.10
 - (507914) Add script to deploy .debs to a PPA hosted on Artifactory
 - (508492, 508493) [INBM] Support INBC Config commands(Get,Set)
 - (508494) [INBM] Support INBC Config Load command
 
### Changed
 - (508706) - Change dynamic telemetry tag from ContainersCpuPercentage to ContainerStats

### Security
- RTC 510268: Updated golang runtime for trtl and inb-provision-{certs, cloud, ota-cert}. Previous runtime (1.17.6/1.17.6) had a number of CVEs associated with it. New runtime version is 1.17.8.

## 3.0.8 - 2022-01-24

### Fixed
 - 505595, HSD 15010407028 - Fix provisionNode command failed in Signature check
 - HSD 15010510035 - Fix node service fail to autostart after freshly flash
 - HSD 15010519087, 15010575546, 15010584480 - Fix SSL search path to work on Yocto, using /etc/ssl/ca-certificates.crt on all systems.

### Security
 - RTC 507867: Updated golang runtime for trtl and inb-provision-{certs, cloud, ota-cert}. Previous runtime (1.16.2/1.16.3) had a number of CVEs associated with it. New runtime version is 1.17.6.
 - RTC 507867: Updated trtl dependency to clear a third-party CVE result associated with containerd.

## 3.0.7 - 2022-01-04

### Fixed
 - Build from normal Internet connection fixed.

## 3.0.6 - 2021-12-31
This is the first open source release.

### Changed
 - (505457) Fix INBM Ubuntu Installation guide
 - (505458) Format Azure guide
 - Other documentation tweaks and updates

## 3.0.0-3.0.5 - 2021-12-16
These are the open source release candidates.

### Added
 - 47352, 47353 [TC] Support SWBOM Query command [Dispatcher-agent, Telemetry-agent]
 - 47354 - [INBC] Query command support for INBM.

### Fixed
 - Yocto-specific entries for AppArmor have been added to match
   new binary paths in the default arm64 Yocto build.
 - 47838, HSD-15010220936 - Temporary aota package not removed after AOTA success/fail

### Fixed
 - Yocto-specific AppArmor files are now generated correctly.
 - HSD 15010039534 - Fix telemetry not retry RAS notification registration after registration failure

### Changed
 - Documentation updated and improved

### Security
 - (505490) Upgraded trtl dependencies to address CVE-2021-41190 in specs-go 1.0.1
 - (RTC 503878) Ensure dispatcher agent always blanks username and password in logs

