# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

## NEXT - ?

### Fixed
- 504494, HSD 15010332252 - Fix provision file not removed in /opt/xlink_provision when failed to reset device due to no matching device id
- 506035, HSD 15010309026 - Update node apparmor policy by adding /sys/kernel/xlink_secure/debug
- HSD 15010516458 - Fix storage checks failed during mender file transferring in SOTA/POTA
- 506874 - Fix node config schema error when upgrading from v2.16.0 to v2.17.2

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
