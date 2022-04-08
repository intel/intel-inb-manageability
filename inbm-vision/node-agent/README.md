# Node agent

<details>
<summary>Table of Contents</summary>

- [Overview](#overview)
- [Agent Communication](#agent-communication)
    - [Publish Channels](#publish-channels)
    - [Subscribe Channels](#subscribe-channels)
- [Install from Source](#install-from-source)
- [Usage](#usage)
  - [Changing the logging level](#changing-the-logging-level)
  - [Run the agent](#run-the-agent)
  - [Test the agent](#test-the-agent)
</details>

## Overview

The Intel Manageability agent which registers with the Vision Agent and facilitates updates on the SOC.

## Agent Communication 

Uses MQTT for communication with the Dispatcher-agent residing on the SOC.

### Publish Channels
The agent publishes to the following topics:
  - Request from cloud or INBC for the node: `manageability/request/install`
  - node-agent state: node/state` when dead/running

### Subscribe Channels
The agent subscribes to the following topics:
 - Events to be sent back to the user: `manageability/event` 
 - Telemetry data: `manageability/telemetry`
 - Update response: `manageability/response`
 - Configuration response: `configuration/response`
 - Agent states: `+/state`

 P.S: `+` is a wild-card indicating single level thus matching `node/state` or `<another-agent>/state`

## Install from Source
The node-agent is installed on a Yocto image, which requires flashing a Mender image that contains the Node-agent.

## Usage

❗Ensure Mosquitto broker is installed and configured for Intel(R) In-Band Manageability.  
❗Some commands will require root privileges (sudo)  
❗Run commands in the `inbm/node-agent` directory

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

### Generate Pydoc Documentation:

- Run: `make documentation`
