# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

## NEXT - ?

### Fixed
 - RTC 530729 - Fix AOTA update log file show Reboot Failed although platform already rebooted and application updated
 - RTC 530881 - Fix JSON update log/access

## 4.1.0 - 2023-06-13

### Added
 - RTC 530033 - Add AOTA Applicaiton Update command to INBC
 - RTC 530032 - Add INBC SOTA update, download-only and no-download modes 
 - RTC 529914 - Implement OTA logger
 - RTC 529912 - Add a reboot option (optional) in OTA manifest for FOTA, SOTA and POTA
 - RTC 529913 - Update INBC to take in the optional reboot option in an OTA cmd

### Fixed
 - RTC 530482 - Remove 'force' option in OTA's
 - RTC 530846 - INBC AOTA Application update command to check package fetch from trusted repo

## 4.0.1 - 2023-05-26

### Security
 - RTC 529956 - [UCC Win] Bug: C:\intel-manageability\ directory can be written by non-admin user
 - RTC 529951 - Cloudadapter does not check if certain files are symlinks
 - Increased bit size when generating TLS keys
 - Updated pypi requests to fix dependabot security alert

### Changed
 - Added recommendation to use BitLocker when installing in Windows.


## 4.0.0 - 2023-05-16

### Added
 - Added Windows output (UCC only) from main build

### Fixed
 - RTC 528514 - [Defect] [UCC] Send telemetry value as-is rather than quoting
 - RTC 528654 - [Defect] Remove parameters from INBC for version, manufacturer, product, and vendor for both POTA and FOTA commands
 - RTC 529947 - Fix UCC bitsize 

### Security
 - RTC 528652 Mask Confidential data (Username & Password) of OTA is exposed in logs
 - RTC 529258 Adjust Windows build to address 3rd party vulnerabilities
 - Removed some unneeded libraries with vulnerabilities

## 3.0.15 - 2023-04-14

### Added
 - RTC 527671 Allow hostnames for Server IP in provision script
 - RTC 527023,527027 - Add docker notes to README.md and download link to Thingsboard docs
 - RTC 527025 - Add to INBC README on how to provision-tc with no cloud--"inbc only mode"
 - RTC 527028 - Add notes to INBC fota section to mention about URL configuration
 - RTC 527026 - Add notes to INBC docs
 - RTC 523847 - Support for Thingsboard 3.4.2
 - Added UCC mode for INBM installer and cloud adapter

### Fixed
 - RTC 498253 - Fix duplicate of DBS remove operation in docker-compose OTA
 - RTC 518125 - Fix Missing DBS log when docker image is removed
 - RTC 518127 - Fix DBS not removing failed container and failed image
 - RTC 517481 - Fix DBS image is removed when there is DBS container doesn't pass DBS check
 - HSD 15012036803 - Fix for few telemetry data of the OTA update is not published to Thingsboard cloud
 - RTC 517426 - Network check added after reboot for SOTA.
 - RTC 522583 - Added a command to fix for SOTA update fail due to apt-get -yq upgrade failed
 - JIRA NEXMGMT-16 - Added fix for configuration file not removed if config Load fail
 - RTC 527018 - Fixed miscellaneous build issues when building from repo root
 - RTC 527058 - Cloudadapter proxy error during startup (Azure)
 - RTC 527059 - Overall FOTA result is not publish to cloud (Azure)
 - RTC 527158, 527530: Installation fixes for UCC


### Removed
 - RTC 525534 - Remove Bit Creek from INBC code and documentation

### Security
 - RTC 527078 - Change golang-runtime 1.18 to 1.20
 - Harden tarfile extraction against path traversal attacks
 - Bump cryptography from 3.4.8 to 30.9.1 in /inbm/dispatcher-agent
 - RTC 526357 - security.md file for SDL CT256

## 3.0.14 - 2022-11-07

### Fixed
 - RTC 521500      - Fixed build error by updating PyInstaller to 5.6.2
 - RTC 520951      - Remove references to 'inbm-lib' from requirements.txt in intel-inb-manageability repository
 - HSD 15011727901 - Fix POTA/INBC POTA print "Firmware Update Aborted" message after firmware update is success
 - HSD 15011730318 - Fix INBC FOTA/POTA not supporting "guid" arguments

### Removed
 - RTC 517780 - Remove Ubuntu 18.04 support

## 3.0.13 - 2022-08-07

### Added
 - RTC 517782 - Add Ubuntu 22.04 support for INBM TC including integration test
 - RTC 517781 - Allow installation on Debian bullseye

### Fixed
 - RTC 517230 - Added fix for telemetry agent to receive latest values after performing config set OTA and restart of telemetry agent
 - RTC 517028 - Set schema boundary limits for telemetry configuration values
 - RTC 498253 - Fix duplicate of DBS remove operation in docker-compose OTA

## 3.0.12 - 2022-07-14

### Fixed
 - RTC 509640      - Shortened the SWBOM publish timer and added logic to cancel and update the timer
 - HSD 16016950467 - Missing AppArmor profile entries under /sys for diagnostic agent
 - HSD 15011298374 - Missing lxc-common dependencies for .debs/AppArmor
 - HSD 15011258925 - Kernel modules missing after AOTA update HDDL driver
 - HSD 15011243931 - Fix cloudadapter-agent disconnection issue
 - HSD 16016950467 - Add missing AppArmor entries for MTL-P Ubuntu
 - HSD 15011480329 - Fix INBC POTA fail while executing SOTA in ubuntu

### Added
 - HSD 15011298299, RTC 515263 - Support non-LTS versions of Ubuntu
 - RTC 516194 Add Query OTA cmd to ThingsBoard Batch dashboard
 - RTC 496923 - Changed return status during preinstall check fail from 302 to 400 and updated the error message 

### Security
 - Updated trtl dependencies

## 3.0.11 - 2022-05-17

### Fixed
 - HSD 15010509095 - INBC fail to return correct Exit Code for difference scenario (-4/-6/-11)
 - HSD 15010982715 - inbm-vision failed to receive query request from cloud
 - HSD 15011009937 - Remove POTA Failure error on Success
 - HSD 15010766920 - Fix Telemetry apparmor issue on Yocto
 - HSD 15011207622 - Fixed SOTA update failed due to mender command changed
 - RTC 513178 - apt-get failed to update from a different location for the main Ubuntu sources
 - RTC 497932 - Incorrect error message when OTA fetching fail
 - HSD 15011248619 - Support Signature argument in INBC Load command

### Added
- RTC 508495 Support INBC Config Append command
- RTC 508497 Support INBC Config Remove command
- RTC 497530 Add fields in Thingsboard and Azure to support Query command via button click.
- RTC 500237 - Remove DBS messages from appearing in INBC
- RTC 514101 - Remove support of remove and append command for apt source in configuration file
- RTC 515264 - [INBM] [SOTA] Execute 'apt-get -f install -y' after update and prior to upgrade commands

## 3.0.10 - 2022-03-28

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

