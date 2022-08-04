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

-   Ubuntu 21.10 (Desktop and Server)

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

| Description                                               | From GitHub Clone File Location                  | From Distribution File Location           |
|:----------------------------------------------------------|:-------------------------------------------------|:------------------------------------------|
| Installs both inbm and inbm-vision for Ubuntu or Debian   | `inbm/output/install-inb.sh`                     | `inbm/install-inb.sh`                     |
| Installs inbm for Ubuntu or Debian                        | `inbm/output/install-tc.sh`                      | `inbm/install-tc.sh`                      |
| Uninstalls both inbm and inbm-vision for Ubuntu or Debian | `inbm/output/uninstall-inb.sh`                   | `inbm/uninstall-inb.sh`                   |
| Uninstalls inbm for Ubuntu or Debian                      | `inbm/output/uninstall-tc.sh`                    | `inbm/uninstall-tc.sh`                    |
| Binary files for inbm                                     | `inbm/output/Intel-Manageability.preview.tar.gz` | `inbm/Intel-Manageability.preview.tar.gz` |
| Installs vision or node agent from inbm-vision            | `inbm-vision/output/install-bc.sh`               | `inbm-vision/installer/install-bc.sh`     |
| Uninstalls vision or node agent from inbm-vision          | `inbm-vision/output/uninstall-bc.sh`             | `inbm-vision/installer/uninstall-bc.sh`   |
| Binary files for inbm-vision                              | `inbm-vision/outp/*.deb`                         | `inbm-vision/*.deb`                       | 


Before running any of the above scripts, execute the below command:
```shell

chmod a+x *.sh

```

To install INBM:
```shell
sudo ./install-tc.sh

```

To install INBM-VISION:
```shell
sudo ./install-bc.sh
```

❗ During Installation you will be prompted to accept the License. You can accept by typing ‘Y’, this will result in installation of the INBM Framework.

Any of the scripts can be run accordingly. Once the framework has been installed users would then need to provision INBM with Device Management Cloud related credentials, a phase referred to as “Provisioning”.

Details of provisioning steps are present in the **User Guide**, depending on the choice of cloud provider service; refer to 

-   [Azure User Guide](In-Band%20Manageability%20User%20Guide%20-%20Azure.md)

-   [ThingsBoard User Guide](In-Band%20Manageability%20User%20Guide%20-%20ThingsBoard.md)

