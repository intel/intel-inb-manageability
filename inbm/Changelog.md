# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

## NEXT - ?

## 4.2.3 - 2024-05-02

### Changed
 - Moved service files from /lib to /usr/lib for all Linux OSes

### Security
 - Bump golang.org/x/net from 0.17.0 to 0.23.0 in /inbm/trtl resolving detected 3rd party CVE: CVE-2023-45288

## 4.2.2 - 2024-03-26

### Changed
 - Removed remaining Bit Creek code including 'Target' references from the manifest schema.

### Fixed
 - RTC 539880 - Fix encountered disconnected with code 7 after successfully provision to Azure cloud

 - Bump cryptography to 42.0.4, resolving CVE-2024-26130
 - Bump github.com/docker/docker from 24.0.7+incompatible to 24.0.9+incompatible in /inbm/trtl, resolving CVE-2024-21626 and CVE-2024-24557 (NOTE: trtl does not use runc or Docker Engine, so these CVEs would not actually apply to this project)

## 4.2.1 - 2024-02-16

### Changed
 - Added --build-windows and --build-check flags to build scripts to allow optional skipping of Windows build and unit tests/mypy checks. One example scenario where this would be useful would be building an official version that has already been validated and unit tests already run, to reduce build time. Another scenario would be to skip the Windows build if the user only needs a Linux build.

### Fixed
 - RTC 538468 - paho-mqtt upgrade broke cloudadapter's mqtt connections. Fixed proxy setting code to not override all sockets with proxy as paho-mqtt 1.6.0 relies on listening/connecting to localhost to set up sockets, and this doesn't work with a global proxy on all sockets.
 - RTC 538549 - improved errors when unable to fetch from URLs. For example, if INBM receives a "404 Not Found" it will return this as part of its error instead of simply returning a generic error message about being unable to fetch the URL.
 - RTC 538524 - GUID missing when not provided by manifest when running fwupdate tool
 - RTC 530960 - Fix SOTA snapshot conditions to not reboot twice on EXT4 system  

### Security
 - RTC 537811 - Bump cryptography from 41.0.6 to 42.0.2 in /inbm/dispatcher-agent (addresses CVE-2023-5678, CVE-2023-6129)

## 4.2.0 - 2024-01-23

### Changed
 - RTC 536078 - Added package list option to inbc, cloud, and internal manifest. This allows SOTA to run an install/upgrade command on a set of individual packages rather than all installed packages.
 - (BREAKING CHANGE) RTC 536910 - [source] Remove ubuntuAptSource INBM configuration tag and underlying code; replaced with source command.

### Added
 - RTC 536601 - Added 'source' command to INBM. This command manages `/etc/apt/sources.list` and `/etc/apt/sources.list.d/*` and associated gpg keys on Ubuntu.
 - RTC 537769 -  Added verification of GPG key URIs against a list of trusted repositories for enhanced security

check if sourceApplication Gpg key URL is in trusted repo
### Fixed
 - RTC 534426 - Could not write to /var/log/inbm-update-status.log on Yocto due to /var/log being a symlink to /var/volatile/log.
 - RTC 523677 - Improve INBC error logging - invalid child tag not printed
 - RTC 522583 - Fix missing SOTA logs
 - RTC 534998 - Fix SOTA failure due to snapshot error 
 - Fixed some mismatched types in abstract classes vs subtypes in dispatcher agent
 - Fixed some container mode issues

### Security
 - RTC 533615 - Validate GUID format in manifest using XML schema.  
 -              Ensure the GUID in the manifest if provided matches one of the GUIDs on the system before performing a FOTA.
 - dependabot: update golang.org/x/net from 0.14.0 to 0.17.0 in /inbm/trtl (addresses CVE-2023-39325, CVE-2023-44487)
 - update pypi urllib3 from 1.26.17 to 1.26.18 (addresses CVE-2023-45803 in urllib3)
 - dependabot: bump github.com/docker/docker from 24.0.5+incompatible to 24.0.7+incompatible in /inbm/trtl (addresses GHSA-jq35-85cj-fj4p)
 - update included reference certifi source code from 2020.12.05 to 2023.7.22, which was not a security issue per se but was flagged in BDBA as it contains CVE-2022-23491 and CVE-2023-37920
 - dependabot: Bump pyinstaller from 5.13.0 to 5.13.1 in all agents/programs (addresses CVE-2023-49797)
 - RTC 536046 - Add a workflow to perform signature checks for AOTA packages if user enrolled a key during provisioning

## 4.1.4 - 2023-10-11

### Fixed
 - RTC 533936 - [INBM] Fix sota Kernel upgrade failure

### Added
 - Add firmware update database entry for NUC12WSHv5 using /usr/bin/iFlashVLnx64. This tool can be downloaded from https://www.intel.com/content/www/us/en/download/19504/intel-aptio-v-uefi-firmware-integrator-tools-for-intel-nuc.html

### Security
 - dependabot: update cryptography from 41.0.3 to 41.0.4
 - update urllib3 from 1.26.16 to 1.26.17 (addresses CVE-2023-43804 in urllib3)

## 4.1.3 - 2023-09-05

### Fixed
 - RTC 532663 - [INBM][UCC][Bug] During every Windows reboot there will be a temporary folder created
 - RTC 531795 - [Bug] inbc defaults to deviceReboot=yes even with download-only mode
 - RTC 531796 - [Bug] dispatcher reboots device after failed update even in download-only mode
 - RTC [533020] - Fix SOTA to  handle dpkg interactive prompt
 - RTC 532662 - [INBM][UCC][Bug] INBM fails to send telemetry when IP is changed manually
 - Changed golang builds to not depend on glibc.
 - Updated OpenSSL download path in Windows installer.

### Added
- RTC 532655 - Add AOTA docker-compose up,down and pull commands to INBC
- RTC 532848 - Add AOTA docker pull, import, load and remove commands to INBC

### Security
 - (dependabot) - Updated cryptography from 41.0.0 to 41.0.2
 - (dependabot) - Updated cryptography from 41.0.2 to 41.0.3
 - Updated golang runtime from 1.20.5 to 1.20.6
 - (533039) Added Intel standard compiler flags and settings to golang builds
 - (533037) CT72 - Secure Configuration Guidance: remove all remaining Telit references
 - Update to Python 3.11 to address some CVEs.
 - Update Windows Dockerfile to pull in Python 3.11.5 to address some CVEs.

## 4.1.2 - 2023-06-29

### Fixed
 - RTC 531066 - [TC Base] [Bug] Cloud Adapter disconnected upon provisioned
 - RTC 532217 - [TC Base] [Bug] Cloud Adapter cannot connect to Azure

### Security
 - Updated Windows Python version to pull in security updates

## 4.1.1 - 2023-06-23

NOTE: update log path has changed to /var/log/inbm-update-status.log

### Fixed
 - RTC 530729 - Fix AOTA update log file show Reboot Failed although platform already rebooted and application updated
 - RTC 530881 - Fix JSON update log/access
 - RTC 530960 - Fix INBC SOTA observe post-install check and rollback on EXT4
 - RTC 530992 - [TC Base] [Bug] Cloudadapter Agent failed to start - TypeError: object of type 'int' has no len()

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

