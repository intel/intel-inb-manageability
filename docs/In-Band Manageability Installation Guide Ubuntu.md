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

-   Ubuntu 18.04 (Desktop and Server)

-   Yocto OS

-   Debian 10

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


**Build Output files**

| Script name                               | Functionality                                             |
|-------------------------------------------|-----------------------------------------------------------|
| `inbm/install-inb.sh`                     | Installs both inbm and inbm-vision for Ubuntu or Debian   |
| `inbm/install-tc.sh`                      | Installs inbm for Ubuntu or Debian                        |
| `inbm/uninstall-inb.sh`                   | Uninstalls both inbm and inbm-vision for Ubuntu or Debian |
| `inbm/uninstall-tc.sh`                    | Uninstalls inbm for Ubuntu or Debian                      |
| `inbm/Intel-Manageability.preview.tar.gz` | Binary files for inbm                                     |
| `inbm-vision/install-bc.sh`               | Installs vision or node agent from inbm-vision            |
| `inbm-vision/uninstall-bc.sh`             | Uninstalls vision or node agent from inbm-vision          |
| `inbm-vision/*.deb`                       | Binary files for inbm-vision                              | 

Before running any of the above scripts, execute the below command:
```shell

chmod a+x *.sh

```

To install INBM:
```shell

sudo ./install-tc.sh

```

❗ During Installation you will be prompted to accept the License. You can accept by typing ‘Y’, this will result in installation of the INBM Framework.

Any of the scripts can be run accordingly. Once the framework has been installed users would then need to provision INBM with Device Management Cloud related credentials, a phase referred to as “Provisioning”.

Details of provisioning steps are present in the **User Guide**, depending on the choice of cloud provider service; refer to 

-   [Azure User Guide](In-Band%20Manageability%20User%20Guide%20-%20Azure.md)

-   [ThingsBoard User Guide](In-Band%20Manageability%20User%20Guide%20-%20ThingsBoard.md)

