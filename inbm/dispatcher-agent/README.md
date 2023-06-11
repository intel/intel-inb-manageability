# Dispatcher Agent

<details>
<summary>Table of Contents</summary>

- [Overview](#overview)
- [Agent Communication](#agent-communication)
    - [Publish Channels](#publish-channels)
    - [Subscribe Channels](#subscribe-channels)
- [MQTT Client Module](#mqtt-client-module)
- [OTA/Config Manifest](#otaconfig-manifest)
  - [AOTA](#aota)
  - [SOTA](#sota)
  - [FOTA](#fota)
  - [POTA](#pota)
  - [Configuration](#configuration)
  - [Shutdown/Restart](#shutdownrestart)
  - [Query](#query)
- [Install from Source](#install-from-source)
- [Usage](#usage)
  - [Changing the logging level](#changing-the-logging-level)
  - [Run the agent](#run-the-agent)
  - [Test the agent](#test-the-agent)
- [Debian package (DEB)](#debian-package-deb)
</details>
    
## Overview

- The Intel Manageability agent which dispatches signals/commands to other tools/agents for performing OTA (over-the-air) and updates and configuration requests.
- Talks to the `diagnostic-agent` for pre/post install checks to confirm gateway/device health before performing OTA.  
  - Before install OTA check is done for all scenarios.  
  - After install OTA check is done only for successful installations.

## Agent Communication 

Uses MQTT for communication with other tools/agents

### Publish Channels
The agent publishes to the following topics:
  - Agent events: `manageability/event`
  - Request response: `manageability/response`
  - Perform pre and post diagnostic checks: `diagnostic/command/{command}`
  - Dynamic telemetry updates: `telemetry/update`
  - Informs diagnostic-agent remediation manager to remove a specific container: `remediation/container`
  - Informs diagnostic-agent remediation manager to remove a specific image:`remediation/image`
  - dispatcher-agent state: dispatcher/state` when dead/running


### Subscribe Channels
The agent subscribes to the following topics:
  - OTA requests from cloud or INBC: `manageability/request/+`
  - Response from diagnostic check request: `diagnostic/response/{id}`
  - Receive configuration changes: `configuration/update/dispatcher/+`
  - Receive DBS configuration setting changes: `configuration/update/all/+`
  - Receive SOTA configuration changes: `configuration/update/sota/+`
  - Agent states: `+/state`
 
❗`+` is a wild-card indicating single level thus matching `dispatcher/state` or `<another-agent>/state`


## MQTT Client Module

- Provides an abstraction to the Paho MQTT Client APIs
- Any other microservice/agent can set up an async broker communication through these. For example:
```
import mqttclient

# Create MQTT client instance by connecting to broker
client = MQTT(<id>, <host>, <port>, <keep-alive>)
client.start()

# Subscribe to topic
client.subscribe*('/topic')
# Publish to topic
client.publish('/topic', 'test')

# Close connection
client.stop()
```
## OTA/Config Manifest

- Dispatcher expects a `Manifest`.  [Manifest parameters and examples](#../../docs/Manifest%20Parameters.md)
- The manifest schema with the current format: `inbm/dispatcher-agent/fpm-template/usr/share/manifest_schema.xsd`
- The contents of this file (without the spaces, indent etc.) is sent through the `Trigger OTA` custom action
- If a file needs to be pulled from a remote repository it checks whether the repository is a secured/trusted.  The secured repositories list is stored in the config file in configuration manager.  If the remote repository is not in the trusted list, the request will be rejected. 

### AOTA
- Performs and Application over the Air request using either Docker or Docker-Compose.   

### SOTA
- Performs System Over the Air Updates using Ubuntu Apt-get Update or Mender (Yocto systems)

### FOTA
Performs a Firmware update:
 - Uses DMI path to gather current firmware info on the Edge device.
 - Compares gather data with information provided in the manifest file.
 - If the information matches, the update file will be downloaded from the remote repository pointed to in the <fetch> tag of the manifest.
 - Following the update the device will reboot.

### POTA
Performs both a SOTA and FOTA update at the same time.

### Configuration
The configuration agent is responsible for changes to the configuration files and to inform other
agents about changes
 - Dispatcher parses the manifest and calls set_element, get_element, append, or remove in configuration agent
 - Configuration agent sets or gets the value based on the functionality called
 - The returned value is displayed back to the cloud and dispatcher logs

### Shutdown/Restart
The shutdown or restart command can be sent using the manifest to trigger a system shutdown or reboot.

### Query
Query system information.

## Install from Source
❗ Use a Python version greater than 3.8 is installed

1. [Build INBM](#../../README.md#build-instructions)
2. [Install INBM](#../../docs/In-Band%20Manageability%20Installation%20Guide%20Ubuntu.md)

## Usage

❗Ensure Mosquitto broker is installed and configured for Intel(R) In-Band Manageability.  
❗Some commands will require root privileges (sudo)  
❗Run commands in the `inbm/dispatcher-agent` directory

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
- Install package: `dpkg -i disatpcher-agent<latest>.deb`

### Uninstall (For Ubuntu)
- `dpkg --purge dispatcher-agent`
