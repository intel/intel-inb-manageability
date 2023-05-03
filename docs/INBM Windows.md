# Directory Structure for INBM-Windows Port

The INBM (Intel In-Band Manageability) Windows port is designed to provide integration of INBM components into a Windows environment. This document outlines the directory structure used for the INBM-Windows port, which is designed to mimic the Unix filesystem structure for ease of use and compatibility with the Linux version.

## Directory Structure

The main directories for the INBM-Windows port are as follows:

1. C:\intel-manageability\broker
2. C:\intel-manageability\inbm

### 1. C:\intel-manageability\broker

This directory contains files directly related to the INBM broker, including certificates and keys for broker clients. The subdirectories in this folder are organized as follows:

```
broker
│   ├───etc
│   │   ├───public
│   │   │   ├───cloudadapter-agent
│   │   │   ├───cmd-program
│   │   │   ├───configuration-agent
│   │   │   ├───diagnostic-agent
│   │   │   ├───dispatcher-agent
│   │   │   ├───inbc-program
│   │   │   ├───mqtt-broker
│   │   │   ├───mqtt-ca
│   │   │   └───telemetry-agent
│   │   └───secret
│   │       ├───cloudadapter-agent
│   │       ├───cmd-program
│   │       ├───configuration-agent
│   │       ├───diagnostic-agent
│   │       ├───dispatcher-agent
│   │       ├───inbc-program
│   │       ├───mqtt-broker
│   │       ├───mqtt-ca
│   │       └───telemetry-agent
│   └───usr
│       └───bin
```

### 2. C:\intel-manageability\inbm

This directory contains files directly related to Turtle Creek, the main INBM component. The subdirectories in this folder are organized as follows:

```
inbm
│   ├───etc
│   │   ├───public
│   │   │   ├───cloudadapter-agent
│   │   │   ├───configuration-agent
│   │   │   ├───diagnostic-agent
│   │   │   ├───dispatcher-agent
│   │   │   └───telemetry-agent
│   │   ├───secret
│   │       └───cloudadapter-agent
│   ├───usr
│   │   ├───bin
│   │   └───share
│   │       ├───cloudadapter-agent
│   │       │   ├───thingsboard
│   │       │   └───ucc
│   │       └───intel-manageability
│   │           └───intel-manageability
│   │               └───mqtt
│   └───var
```
