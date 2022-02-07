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
    - [Running the agent](#running-the-agent)
    - [Testing the agent](#testing-the-agent)
</details>
    
## Overview

The Intel Manageability agent which monitors and reports the state of critical components of the  manageability framework.

## Agent Communication 

Uses MQTT for communication with other tools/agents

### Publish Channels
The agent publishes to the following topics:
  - Command response: `diagnostic/response/{id}`
  - Container Remediation: `remediation/container`
  - Image Remediation: `remediation/image`
  - Event channel: `manageability/event`
  - diagnostic-agent state: diagnostic/state` when dead/running


### Subscribe Channels
The agent subscribes to the following topics:
  - [Diagnostic commands](#commands-supported): `diagnostic/command/+`
  - [Diagnostic Configuration Settings](#https://github.com/intel/intel-inb-manageability/blob/develop/docs/Configuration%20Parameters.md#diagnostic): `configuration/update/diagnostic/+`
  - [All Configuration Settings](#https://github.com/intel/intel-inb-manageability/blob/develop/docs/Configuration%20Parameters.md#all): `configuration/update/all/+`
  - Agent states: `+/state`
 
❗`+` is a wild-card indicating single level thus matching `diagnostic/state` or `<another-agent>/state`

## Request - Response communication

- Agent incorporates req-resp style communication layer on top of MQTT
- Agents/Tools can send commands to Diagnostic via `diagnostic/command/<command-name>` with payload:
```
{
	'cmd': <command name>,
	'id': <any ID>
}
```
- Diagnostic sends JSON responses on `diagnostic/response/<ID>`
- Responses are of format: `{'rc': 0/1, 'message': <user friendly message>}`

## Commands supported

- `health_device_battery` - If gateway battery powered, expects min of 20% battery charge
- `check_memory` - If min memory of 200MB present on gateway
- `check_storage` - If min storage of 100MB present on gateway
- `check_network` - If active network interface is up and connected to internet
- `install_check` - Executes all the above commands and returns result

Ex: 
- Dispatcher can publish on `diagnostic/command/install_check` with payload `{'cmd': 'install_check', 'id': 12345}`
- Diagnostic receives it, processes and sends result as `{'rc':0, 'message': 'Install check passed'}` on `diagnostic/response/12345`

## Install 
NOTE: Ensure any Python version greater than 3.8 is installed

- Run `git clone https://gitlab.devtools.intel.com/OWR/IoTG/SMIE/Manageability/iotg-inb.git` into local directory
- Run `cd iotg-inb/diagnostic-agent`
- Run `make init` to install necessary Python packages

## Usage (via Source)
NOTE:  
Ensure Mosquitto broker is installed and configured for Intel(R) In-Band Manageability.  
Some commands will require root privileges (sudo).  
Be sure to run the commands in the `diagnostic-agent` directory

Changing the logging level:

- Run: `make logging LEVEL=DEBUG`
- Valid values for LEVEL:
  - DEBUG
  - ERROR
  - INFO

Run the agent:

- Run: `make run`

Testing the agent:

- Run: `make tests`
