# CloudAdapter Agent

<details>
<summary>Table of Contents</summary>

- [Overview](#overview)
- [Agent Communication](#agent-communication)
  - [Cloud Services](#cloud-services)
  - [Intel Manageability](#intel-manageability)
    - [Publish channels](#publish-channels)
    - [Subscribe channels](#subscribe-channels)
- [Install from Source](#install-from-source)
  - [Usage](#usage)
    - [Setup](#setup)
    - [Changing the logging level](#changing-the-logging-level)
    - [Running the agent](#running-the-agent)
    - [Testing the agent](#testing-the-agent)
</details>

## Overview

- The Intel Manageability agent that publishes and subscribes to a chosen cloud service.
- The agent will pipeline remote procedure calls to corresponding agents.
- It will also pipeline telemetry and event data to the cloud service.

## Agent Communication

### Cloud Services

The agent supports MQTT for communication with cloud services.

There are two supported cloud services:
  - [Azure IoT Central](https://github.com/intel/intel-inb-manageability/blob/develop/docs/In-Band%20Manageability%20User%20Guide%20-%20Azure.md)
  - [ThingsBoard](https://github.com/intel/intel-inb-manageability/blob/develop/docs/In-Band%20Manageability%20User%20Guide%20-%20ThingsBoard.md)

### Intel Manageability

The agent uses MQTT for communication with other agents.

#### Publish channels
The agent publishes to the following topics:
  - cloudadapter-agent state: `cloudadapter/state` when dead/running
  - Manifest install requests: `manageability/request/`

#### Subscribe channels
The agent subscribes to the following topics:
  - Agent states: `+/state`
  - Agent events: `manageability/event`
  - Responses: `manageability/response`
  - Device telemetry: `manageability/telemetry`

❗`+` is a wild-card indicating single level thus matching `diagnostic/state` or `<another-agent>/state`

Events or responses sent to the agent are logged or published to the cloud as-is.

Device telemetry sent to the agent should have the following schema:
```json
{
    "type": "object",
    "required": ["type", "values"],
    "properties": {
        "type": {
            "description": "Type of telemetry",
            "type": "string",
            "enum": [
                "dynamic_telemetry",
                "static_telemetry"
            ]
        },
        "values": {
            "description": "Key value mapping of the telemetry",
            "type": "object",
            "patternProperties": {
                ".+": { "type": "string" }
            }
        }
    }
}
```
For example:
```json
{
    "type": "dynamic_telementry",
    "values": {
        "availableMemory": "2048",
        "systemCpuPercent": "25"
    }
}
```

## Install from Source
NOTE: Ensure any Python version greater than 3.8 is installed

1. [Build INBM](#https://github.com/intel/intel-inb-manageability/blob/develop/README.md#build-instructions)
2. [Install INBM](#https://github.com/intel/intel-inb-manageability/blob/develop/docs/In-Band%20Manageability%20Installation%20Guide%20Ubuntu.md)

### Usage

❗Ensure Mosquitto broker is installed and configured for Intel(R) In-Band Manageability.  
❗Some commands will require root privileges (sudo)  
❗Run commands in the `inbm/cloudadapter-agent` directory

#### Setup:
- Run: `make config`
- Refer to the following documents for cloud setup:
  - [Azure](#https://github.com/intel/intel-inb-manageability/blob/develop/docs/In-Band%20Manageability%20User%20Guide%20-%20Azure.md)
  - [Thingsboard](#https://github.com/intel/intel-inb-manageability/blob/develop/docs/In-Band%20Manageability%20User%20Guide%20-%20ThingsBoard.md)

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
