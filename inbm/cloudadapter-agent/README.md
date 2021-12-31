# cloudadapter-agent

## Contents

- [Overview](#overview)
- [Agent Communication](#agent-communication)
  - [Cloud Services](#cloud-services)
  - [Intel Manageability](#intel-manageability)
- [Source](#source)
  - [Install](#install)
  - [Usage](#usage)
- [Debian Package (DEB)](#debian-package-deb)
  - [Install](#install-1)
  - [Uninstall](#uninstall)
- [Generate PyDoc](#generate-pydoc)

## Overview

- The IoT Manageability agent that subscribes/messages to a chosen cloud service
- The agent will pipeline remote procedure calls to corresponding agents
- It will also pipeline telemetry and event data to the cloud service

## Agent Communication

### Cloud Services

The agent supports MQTT for communication with cloud services.

There are three supported cloud services:
  - [Telit deviceWise](https://soco.intel.com/docs/DOC-2654035)
  - [Azure IoT Central](https://soco.intel.com/docs/DOC-2643965)
  - [ThingsBoard](https://soco.intel.com/docs/DOC-2649874)

There is also a custom cloud configuration option, documented
[here](https://soco.intel.com/docs/DOC-2650245).

Information on triggering remote procedure calls can be found
[here](https://soco.intel.com/docs/DOC-2654034).

### Intel Manageability

The agent uses MQTT for communication with other agents.

The agent publishes to the following topics:
  - cloudadapter-agent state: `cloudadapter/state`
  - Manifest install requests: `manageability/request/`

The agent subscribes to the following topics:
  - Agent states: `+/state`
  - Agent events: `manageability/event`
  - Responses: `manageability/response`
  - Device telemetry: `manageability/telemetry`

Events  or responses sent to the agent are logged or published to the cloud as-is.

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
        "systemCpuPercent": "25",
    }
}
```

## Source

### Install

NOTE: Ensure any Python version greater than 3.8 is installed

- Run `git clone https://gitlab.devtools.intel.com/OWR/IoTG/SMIE/Manageability/iotg-inb.git` into local directory
- Run `cd cloudadapter-agent`
- Run `make init` to install necessary Python packages

### Usage

*Ensure Mosquitto broker is installed and configured for Intel(R) In-Band Manageability.*  
*Some commands will require root privileges (sudo)*  
*Run commands in the `cloudadapter-agent` directory*

Setting the cloud service:

- Run: `make config`

Changing the logging level:

- Run: `make logging LEVEL=DEBUG`
- Valid values for `LEVEL`:
  - `DEBUG`
  - `ERROR`
  - `INFO`

Running the agent:

- Run: `make run`

Testing the agent:

- Run: `make tests`

## Debian package (DEB)

### Install

- Download the DEB file from the artifacts tab of a successful TeamCity build
- For Ubuntu: `dpkg -i dist/cloudadapter-agent-<latest>.deb`
- Check cloudadapter agent is running correctly: `journalctl -fu cloudadapter`

### Uninstall

- For Ubuntu: `dpkg --purge cloudadapter-agent`

## Generate PyDoc

NOTE:  
TeamCity will generate API documentation for each commit

- To generate API documentation locally for CloudAdapter Agent:
  1. Run `cd doc`
  2. Run `make doc-init`
  3. Run `make html`
  4. Open `html/toc.html` in browser of choice
