# Diagnostic Agent

<details>
<summary>Table of Contents</summary>

- [Overview](#overview)
- [Agent Communication](#agent-communication)
    - [Publish Channels](#publish-channels)
    - [Subscribe Channels](#subscribe-channels)
  - [Request - Response communication](#request---response-communication)
  - [Commands supported](#commands-supported)
- [Install from Source](#install-from-source)
- [Usage](#usage)
  - [Changing the logging level](#changing-the-logging-level)
  - [Run the agent](#run-the-agent)
  - [Test the agent](#test-the-agent)
- [Debian package (DEB)](#debian-package-deb)
</details>
    
## Overview

The Intel Manageability agent which monitors and reports the state of critical components of the  manageability framework.

## Agent Communication 

Uses MQTT for communication with other tools/agents

### Publish Channels
The agent publishes to the following topics:
  - Command response: `diagnostic/response/{id}`
  - Informs RemediationManager to remove a specific container: `remediation/container`
  - Informs RemediationManager to remove a specific image: `remediation/image`
  - Event channel: `manageability/event`
  - diagnostic-agent state: diagnostic/state` when dead/running


### Subscribe Channels
The agent subscribes to the following topics:
  - [Diagnostic commands](#commands-supported): `diagnostic/command/+`
  - [Diagnostic Configuration Settings](#../../docs/Configuration%20Parameters.md#diagnostic): `configuration/update/diagnostic/+`
  - [All Configuration Settings](#../../docs/Configuration%20Parameters.md#all): `configuration/update/all/+`
  - Agent states: `+/state`
 
❗`+` is a wild-card indicating single level thus matching `diagnostic/state` or `<another-agent>/state`

## Request - Response communication
- Agent incorporates req-resp style communication layer on top of MQTT
- Agents/Tools can send commands to Diagnostic via `diagnostic/command/<command-name>` with payload:
```json
  {
    "cmd": "<command name>",
    "id": "<any ID>"
  }
```
- Diagnostic sends JSON responses on `diagnostic/response/<ID>`
- Responses are of format: 
```json
  {
    "rc": "0 | 1", 
    "message": "<user friendly message>"
  }
```

## Commands supported

- `health_device_battery` - If system is battery powered, checks that battery charge is above expected minimum. (configurable)
- `check_memory` - Checks that memory is above expected minimum. (configurable)
- `check_storage` - Checks that available storage is above expected minimum. (configurable)
- `check_network` - Checks that an active network interface is up and connected to internet. This check can be turned off for systems without an internet connection.
- `container_health_check` - Lists out images on the system and 
- `swCheck` - Checks that listed software is installed on the system.  Ex. Docker, TRTL (configurable)
- `install_check` - Executes all the above commands and returns result

Ex: 
- Dispatcher can publish on `diagnostic/command/install_check` with payload:
```json
  {
    "cmd": "install_check", 
    "id": "12345"
  }
```
- Diagnostic receives the following response on `diagnostic/response/12345`:
```json
  {
    "rc":0, 
    "message": "Install check passed"
  }
```

## Install from Source
❗ Use a Python version greater than 3.12 is installed

1. [Build INBM](#../../README.md#build-instructions)
2. [Install INBM](#../../docs/In-Band%20Manageability%20Installation%20Guide%20Ubuntu.md)

## Usage

❗Ensure Mosquitto broker is installed and configured for Intel(R) In-Band Manageability.  
❗Some commands will require root privileges (sudo)  
❗Run commands in the `inbm/diagnostic-agent` directory

### Changing the logging level:
- Run: `make logging LEVEL=DEBUG`
- Valid values for `LEVEL`:
  - `DEBUG`
  - `ERROR`
  - `INFO`

### Run the agent:

- Run: `make run`

### Test the agent:

- Run: `make tests`

## Debian package (DEB)

### Install (For Ubuntu)
After building the above package, if you only want to install the diagnostic-agent, you can do so by following these steps:
- `cd dist/inbm`
- Unzip package: `sudo tar -xvf Intel-Manageability.preview.tar.gz`
- Install package: `dpkg -i diagnostic-agent<latest>.deb`

### Uninstall (For Ubuntu)
- `dpkg --purge diagnostic-agent`
