## Intel Manageability Vision Installation Guide

See: https://wiki.ith.intel.com/pages/viewpage.action?pageId=1526327903

## BUILD INSTRUCTIONS

- Prepare a Linux machine with git and Docker installed.  Ensure the 'm4' and 'bash' packages are also installed (these are available in all major Linux distributions).
- (INTEL CAMPUS ONLY) Make sure the Linux machine has Intel intranet certificates installed. See https://intelpedia.intel.com/LinuxDesktop#Installing_Intel_SSL_Certificates for instructions.
- (INTEL CAMPUS ONLY) Clone the repository with git: git clone https://gitlab.devtools.intel.com/OWR/IoTG/SMIE/Manageability/bit-creek.git
- (INTEL CAMPUS ONLY) Note: you must have "OWR Viewer" access in AGS to do this. Git will prompt for your IDSID and password.
- cd bit-creek
- git checkout [name of tag or commit ID you wish to build]
- Run: ./build.sh
- When build is complete, build output will be in the output folder.

Tip: run ./build-check.sh to just run automated checks, lints, and coverage reports.

If you see something like 'unable to resolve' or a DNS error or 'unable to look up' near the start of the build, follow the instructions under https://docs.docker.com/install/linux/linux-postinstall/ --> "DISABLE DNSMASQ".  This can occur in some Linux distributions that put 127.0.0.1 in /etc/resolv.conf.
