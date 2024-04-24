# Installation Guide

## Table of Contents

1. [Introduction](#introduction)
    1. [Purpose](#purpose)
    2. [Audience](#audience)
2. [Installing INBM](#installing-INBM)
    1. [Supported OS](#supported-os)
    2. [Setting up checklist](#setting-up-checklist)
    3. [Run Install script](#run-install-script)

## Introduction
### Purpose

This Installation Guide serves to provide the reader an overview on how
to install INBM for Ubuntu on Edge IOT device:

-   Supported OS

-   Key checks before initiating installation

-   Run install script


### Audience

This guide is intended for

-   Independent Software Vendors (ISV) providing OS and Application
    update packages.

-   System Integrators administrating devices running In-Band
    Manageability framework.

## Installing INBM

### Supported OS

Intel In-band Manageability framework, a.k.a. INBM, is designed to provide certain level of OS abstraction to the administrator managing the IOT Device. The framework supported and validated on the below OS flavors:

-   Ubuntu 20.04 (Desktop and Server)

-   Ubuntu 22.04 (Desktop and Server)

-   Yocto OS

-   Debian 10

-   Debian 11

### Setting up checklist

Before starting the installation process the user should ensure that:

1.  Device time is correctly set: Ensures that the
    creation of certificates during the provisioning phase have the correct
    time stamps.

2.  Network proxies are set accordingly: Ensure that all the
    dependency packages for INBM are downloaded without any
    glitches, else the installation will get aborted.

### Run Install script

A typical installation package will consist of the below shell scripts.  It will also 
include a tar.gz file which consists of all the frameworks executable
packages (.deb files in the case of Ubuntu/Debian).

#### Build Output

The location of the installation scripts will be different depending on whether the source is being used from the GitHub location or if a build package is used from distribution.

| Description                          | From GitHub Clone File Location                  | From Distribution File Location           |
|:-------------------------------------|:-------------------------------------------------|:------------------------------------------|
| Installs INBM for Ubuntu or Debian   | `inbm/output/install-tc.sh`                      | `inbm/install-tc.sh`                      |
| Uninstalls INBM for Ubuntu or Debian | `inbm/output/uninstall-tc.sh`                    | `inbm/uninstall-tc.sh`                    |
| Binary files for INBM                | `inbm/output/Intel-Manageability.preview.tar.gz` | `inbm/Intel-Manageability.preview.tar.gz` |


Before running any of the above scripts, execute the below command:
```shell

chmod a+x *.sh

```

#### Install options

To install INBM:
```shell
sudo ./install-tc.sh
````
To install for UCC which only installs the cloudadapter-agent and not the other agents:
```shell
sudo UCC_MODE=x ./install-tc.sh
```

To install without the cloud option and to use INBC instead:
```shell
sudo NO_CLOUD=x ./install-tc.sh
```

❗ During Installation you will be prompted to accept the License. You can accept by typing ‘Y’, this will result in installation of the INBM Framework.

Any of the scripts can be run accordingly. Once the framework has been installed users would then need to provision INBM with Device Management Cloud related credentials, a phase referred to as “Provisioning”.

Details of provisioning steps are present in the **User Guide**, depending on the choice of cloud provider service; refer to 

-   [Azure User Guide](In-Band%20Manageability%20User%20Guide%20-%20Azure.md)

-   [INBS User Guide](In-Band%20Manageability%20User%20Guide%20-%20INBS.md)

-   [ThingsBoard User Guide](In-Band%20Manageability%20User%20Guide%20-%20ThingsBoard.md)

-   [UCC User Guide](In-Band%20Manageability%20User%20Guide%20-%20UCC.md)

Provisioning can also be performed without selecting a cloud, no cloud provisioning can be achieved by INBC, refer to
-   [INBC Only Mode](../inbc-program/README.md#prerequisites)

