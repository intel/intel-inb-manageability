# Installing and Provisioning INBM for Windows in UCC mode

This guide will walk you through the installation and provisioning of INBM for Windows in UCC mode, which installs the MQTT broker infrastructure and the Cloudadapter agent.

## Prerequisites

Before you begin, ensure that the following files contain the client and server IDs for UCC:

- `C:\ucc\client_id`
- `C:\ucc\server_id`

Also ensure you are installing on Windows 10, our supported Windows version.

Not required, but highly recommended for security of your device keys: enable BitLocker in Windows. Please see
Windows documentation for details.

## Installation

1. Download or build the INBM for Windows zip file and extract its contents to `C:\`. This will create a directory called `C:\inb-files`. To build, see instructions for building INBM. The build output in `dist` will contain a file `inbm-windows.zip`.

2. Open a Command Prompt with Administrator privileges. To do this, press `Win + X` and select "Command Prompt (Admin)" from the menu.

3. Navigate to the `C:\inb-files\intel-manageability` directory by running the following command:

   ```
   cd C:\inb-files\intel-manageability
   ```

4. Set the environment variable `UCC_MODE` to `true` by running the following command:

   ```
   set UCC_MODE=true
   ```

5. Run the `install.ps1` script by executing the following command:

   ```
   powershell -ExecutionPolicy Bypass -File install.ps1
   ```

6. If you want to provide your own `adapter.cfg` instead of providing UCC provisioning details interactively, set the environment variable `NO_CLOUD` to `true` before running the `provision.ps1` script:

   ```
   set NO_CLOUD=true
   ```

   Please see `In-Band Manageability User Guide - UCC.md` for documentation on the UCC configuration options. If you are providing your own `adapter.cfg`, you can put it in `C:\intel-manageability\inbm\etc\secret\cloudadapter-agent\adapter.cfg`.

7. Either way, run the `provision.ps1` script by executing the following command:

   ```
   powershell -ExecutionPolicy Bypass -File provision.ps1
   ```

At this point, all services should be running.


# Issues and Troubleshooting

* You can view logs in the Event Viewer (eventvwr.exe), or in `C:\intel-manageability\inbm\var\manageability.log`.
* You can edit logging settings for any agent in `C:\intel-manageability\inbm\etc\public\AGENT-NAME\logging.ini`. Be sure to restart the agent to make the change take effect. For example, you can restart cloudadapter by running;

  ```
  net stop inbm-cloudadapter
  net start inbm-cloudadapter
  ```


# Directory Structure for INBM-Windows Port

The INBM (Intel In-Band Manageability) Windows port is designed to provide integration of INBM components into a Windows environment. This section outlines the directory structure used for the INBM-Windows port, which is designed to mimic the Unix filesystem structure for ease of use and compatibility with the Linux version.

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
│   │   │   ├───ucc-native-service
│   │   │   └───telemetry-agent
│   │   └───secret
│   │       ├───cloudadapter-agent
│   │       ├───cmd-program
│   │       ├───configuration-agent
│   │       ├───diagnostic-agent
│   │       ├───dispatcher-agent
│   │       ├───inbc-program
│   │       ├───mqtt-broker
│   │       ├───ucc-native-service
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
