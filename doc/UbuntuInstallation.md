# Installation Guide

## Table of Contents

1. [Introduction](#introduction)
    1. [Purpose](#purpose)
    2. [Audience](#audience)
2. [Installing INBM](#installing-inbm)
    1. [Supported OS](#supported-os)
    2. [Setup checklist](#setup-checklist)
    3. [Run Install script](#run-install-script)

## Introduction

### Purpose

This Installation Guide serves to provide the reader an overview on how
to install INBM for Ubuntu on Edge IOT device:

* Supported OS
* Setup Checklist
* Run install script

### Audience

This guide is intended for

* Independent Software Vendors (ISV) providing OS and Application
  update packages.

* System Integrators administrating devices running In-Band
  Manageability framework.

## Installing INBM

### Supported OS

Intel In-band Manageability framework, a.k.a. INBM, is designed to provide certain level of OS abstraction to the administrator managing the IOT Device. The framework supported and validated on the below OS flavors:

* Ubuntu 22.04 (Desktop and Server)
* Ubuntu 24.04 (Desktop and Server)
* Edge Microvisor Toolkit (Tiber OS)

### Setup checklist

Before starting the installation process the user should ensure that:

1. Network proxies are set accordingly: Ensure that all the
   dependency packages for INBM are downloaded without any
   glitches, else the installation will get aborted.

### Run Install script

A typical installation package will consist of the below shell scripts.  It also consists of all the frameworks executable
packages (.deb files in the case of Ubuntu/Debian).

#### Build Output

The location of the installation scripts will be different depending on whether the source is being used from the GitHub location or if a build package is used from distribution.

| Description                          | From GitHub Clone File Location                  | From Distribution File Location           |
|:-------------------------------------|:-------------------------------------------------|:------------------------------------------|
| Installs INBM for Ubuntu  | `inbm/output/install-tc.sh`                      | `inbm/install-tc.sh`                      |
| Uninstalls INBM for Ubuntu or Debian | `inbm/output/uninstall-tc.sh`                    | `inbm/uninstall-tc.sh`                    |

#### Install options

To install INBM:

```shell
sudo ./install-tc.sh
````

❗ During Installation you will be prompted to accept the License. You can accept by typing ‘Y’, this will result in installation of the INBM Framework.
