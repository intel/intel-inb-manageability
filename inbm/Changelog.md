# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

## NEXT - ?

## Fixed
 - Fixed that x86_64 Yocto output files were missing inbm- prefix

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
