# Telemetry Agent

<details>
<summary>Table of Contents</summary>

- [Overview](#overview)
- [Agent Communication](#agent-communication)
    - [Publish Channels](#publish-channels)
    - [Subscribe Channels](#subscribe-channels)
- [Install from Source](#install-from-source)
- [Usage](#usage)
  - [Changing the logging level](#changing-the-logging-level)
  - [Running the agent](#running-the-agent)
  - [Testing the agent](#testing-the-agent)
- [Debian package (DEB)](#debian-package-deb)
</details>

## Overview

The Intel Manageability agent which is the central telemetry and logging service.

## Agent Communication 

Uses MQTT for communication with other tools/agents

### Publish Channels
The agent publishes to the following topics:
  - Telemetry events to the cloud or INBC: `manageability/telemetry`
  - Sends a command request to the diagnostic-agent: `diagnostic/command/{command}`
  - Telemetry-agent state: `telemetry/state` when dead/running

### Subscribe Channels
The agent subscribes to the following topics:
  - Dynamic telemetry updates: `telemetry/update`
  - [Telemetry Configuration Settings](#../../docs/Configuration%20Parameters.md#telemetry): `configuration/update/telemetry/+`
  - Response from diagnostic command request: `diagnostic/response/{id}`
  - Agent states: `+/state`
 
❗`+` is a wild-card indicating single level thus matching `telemetry/state` or `<another-agent>/state`

## Install from Source
❗ Use a Python version greater than 3.8 is installed

1. [Build INBM](#../../README.md#build-instructions)
2. [Install INBM](#../../docs/In-Band%20Manageability%20Installation%20Guide%20Ubuntu.md)

## Usage

❗Ensure Mosquitto broker is installed and configured for Intel(R) In-Band Manageability.  
❗Some commands will require root privileges (sudo)  
❗Run commands in the `inbm/telemetry-agent` directory

### Changing the logging level:

- Run: `make logging LEVEL=DEBUG`
- Valid values for `LEVEL`:
  - `DEBUG`
  - `ERROR`
  - `INFO`

### Running the agent:

- Run: `make run`

### Testing the agent:

- Run: `make tests`

## Debian package (DEB)

### Install (For Ubuntu)
After building the above package, if you only want to install the telemetry-agent, you can do so by following these steps:
- `cd dist/inbm`
- Unzip package: `sudo tar -xvf Intel-Manageability.preview.tar.gz`
- Install package: `dpkg -i telemetry-agent<latest>.deb`

### Uninstall (For Ubuntu)
- `dpkg --purge telemetry-agent`
