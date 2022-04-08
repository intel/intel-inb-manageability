# Vision agent

<details>
<summary>Table of Contents</summary>

- [Overview](#overview)
- [Agent Communication](#agent-communication)
    - [Publish Channels](#publish-channels)
    - [Subscribe Channels](#subscribe-channels)
  - [Commands supported](#commands-supported)
- [Install from Source](#install-from-source)
- [Usage](#usage)
  - [Changing the logging level](#changing-the-logging-level)
  - [Run the agent](#run-the-agent)
  - [Test the agent](#test-the-agent)
- [Debian package (DEB)](#debian-package-deb)
</details>
    
## Overview

The Intel Manageability agent which manages SOC registration and facilitates OTA updates on HDDL devices.

## Agent Communication 

Uses MQTT for communication with INBC and Dispatcher-agent.

### Publish Channels
The agent publishes to the following topics:
  - Telemetry events: `manageability/event`
  - Telemetry data: `manageability/telemetry`
  - Command results: `manageability/response`
  - vision-agent state: vision/state` when dead/running

### Subscribe Channels
The agent subscribes to the following topics:
  - Incoming requests from the cloud or INBC: `ma/request/+`
  - Updates to configuration values in either vision-agent, node-agent, or INB residing on the SOC: `ma/configuration/update/+`
  - Agent states: `+/state`

 P.S: `+` is a wild-card indicating single level thus matching `node/state` or `<another-agent>/state`

## Commands supported

### Channel `ma/request/+`
- `install` - FOTA/SOTA/POTA update requests

### Channel `ma/configuration/update/+`
- `get-element` - gets element at the given path.
- `set_element` - sets element at the given path with the given value.
- `load` - load a new configuration file
- `append` - append to a value at the given path with the given value.file
- `remove` - remove the given value at the given path.


## Install from Source
❗ Use a Python version greater than 3.8 is installed

1. [Build INBM](#https://github.com/intel/intel-inb-manageability/blob/develop/README.md#build-instructions)
2. [Install INBM](#https://github.com/intel/intel-inb-manageability/blob/develop/docs/In-Band%20Manageability%20Installation%20Guide%20Ubuntu.md)

## Usage

❗Ensure Mosquitto broker is installed and configured for Intel(R) In-Band Manageability.  
❗Some commands will require root privileges (sudo)  
❗Run commands in the `inbm/vision-agent` directory

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

## Debian package (DEB)

### Install (For Ubuntu)
After building the above package, if you only want to install the vision-agent, you can do so by following these steps:
```
cd dist/inbm-vision
dpkg -i vision-agent<latest>.deb
```

### Uninstall (For Ubuntu)
```shell
dpkg --purge vision-agent
```

## Update flashless tool
- Build flashless tool after modification on flashless files.
```shell
  cd ..
  ./build.sh
```

- Move flashless tool from output folder to Vision Agent flashless folder.
```
mv output/flashless vision-agent/fpm-template/usr/bin/vision-flashless/
```

- Run `./build.sh` again to update the tool in Debian package.
