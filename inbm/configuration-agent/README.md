# Configuration Agent

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

The Intel Manageability agent which monitors and responds to key/value pair requests.

## Agent Communication

- Uses MQTT for communication with other tools/agents

### Publish Channels
The agent publishes to the following topics:
  - configuration-agent state: `configuration/state` when dead/running
  - updates made to configuration values in intel_manageability.conf file: `configuration/update/*`.  The * is replaced by the path of the value updated. e.g. updated value = maxCacheSize in telemetry on configuration/update/telemetry/mazCacheSize is published.
  - JSON formatted response to configuration requests: `configuration/response`

### Subscribe Channels
The agent subscribes to the following topics:
  - Agent states: `+/state`
  - Incoming commands: `configuration/command/+`

❗`+` is a wild-card indicating single level thus matching `diagnostic/state` or `<another-agent>/state`

## Request - Response communication

- Agent incorporates req-resp style communication layer on top of MQTT
- Agents/Tools can send commands to Configuration via `configuration/command/<command-name>` with payload:
```
{
	'cmd': <command name>,
	'id': <any ID>,
	'path': <any path>
}
```
- Configuration sends JSON responses on `configuration/response/<ID>`
- Responses are of format: `{'message': <result of the request>}`

## Commands Supported

- `get-element` - gets element from the given path.
- `set-element` - sets element at the given path with the given value.
- `append` - appends a new item to a list.  ex. TrustedRepository list
- `remove` - removes an item from a list.
- `load` - loads a new configuration file.

Ex:
- Another agent (ex. Diagnostic) can publish on `configuration/command/get-element` with payload `{'cmd': 'get-element', 'id': 12345, 'path': 'diagnostic/level'}`
- Configuration receives it, processes and sends result as `{'rc':0, 'message': '1'}` on `configuration/response/12345`

## Install from Source
NOTE: Ensure any Python version greater than 3.8 is installed

1. [Build INBM](#https://github.com/intel/intel-inb-manageability/blob/develop/README.md#build-instructions)
2. [Install INBM](#https://github.com/intel/intel-inb-manageability/blob/develop/docs/In-Band%20Manageability%20Installation%20Guide%20Ubuntu.md)

### Usage

❗Ensure Mosquitto broker is installed and configured for Intel(R) In-Band Manageability.  
❗Some commands will require root privileges (sudo)  
❗Run commands in the `inbm/configuration-agent` directory

#### Changing the logging level:

- Run: `make logging LEVEL=DEBUG`
- Valid values for `LEVEL`:
  - `DEBUG`
  - `ERROR`
  - `INFO`

#### Running the agent:

- Run: `make run`

#### Testing the agent:

- Run: `make tests`
