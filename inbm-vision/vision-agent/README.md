# vision-agent
IoT Vision Agent for IA host

Agent which manages SOC registration and facilitates updates

## Agent Communication
- Uses MQTT for communication with OTA client (i.e. INB)
- Vision-agent subscribes to the following topics:
- `ma/request/+` channel for any incoming requests from OTA client
- `ma/configuration/update/+` channel for any updates to configuration values in either the vision-agent, node-agent, or OTA client residing on the SOC
- `+/state` channel for knowing state of OTA Client (e.g. `running`, `dead` etc.)
- Publishes state to `vision/state` when running/dead
- Publishes events to `manageability/event`
- Publishes telemetry to `manageability/telemetry`
- Publishes response to `manageability/response`

 P.S: `+` is a wild-card indicating single level thus matching `node/state` or `<another-agent>/state`

## Commands supported

`ma/request/+``
- `install` - FOTA/SOTA update requests​

`ma/configuration/update/+`
- `get-element` - gets element at the given path.
- `set_element` - sets element at the given path with the given value.
- 'load' - load a new configuration file
- `append` - append to a value at the given path with the given value.file
- `remove` - remove the given value at the given path.


## Install
NOTE: Ensure any Python version greater than 3.8 is installed

- Clone repository into local directory
- Run `cd vision-agent`
- Run `make init` to install necessary Python packages

## Usage (via Source)
NOTE:
Ensure Mosquitto broker is installed and configured for INB.
Some commands will require root privileges (sudo).
Be sure to run the commands in the `vision-agent` directory

Changing the logging level:

- Run: `make logging LEVEL=DEBUG`
- Valid values for LEVEL:
  - DEBUG
  - ERROR
  - INFO

Running the agent:
- Run: `make run`

Testing the agent:
- Run: `make tests`

## Install (via DEB)
- Download the DEB file from the artifacts tab of a successful TeamCity build
- For Ubuntu: `dpkg -i dist/vision-agent-<latest>.deb`
- Check vision agent is running correctly: `journalctl -fu vision`


## Uninstall (via DEB)
- For Ubuntu: `dpkg --purge inbm-vision-agent`


## Generate PyDoc for vision-agent
NOTE: TeamCity will generate API documentation for each commit

- To generate API documentation locally for Vision Agent:
  1. Run `cd doc`
  2. Run `make doc-init`
  3. Run `make html`
  4. Open `html/toc.html` in browser of choice


## Update flashless tool
- Build flashless tool after modification on flashless files.
  1. cd ..
  2. run ./build.sh to build flashless tool
- Move flashless tool from output folder to Vision Agent flashless folder.
  1. mv output/flashless vision-agent/fpm-template/usr/bin/vision-flashless/
- Run ./build.sh again to update the tool in Debian package.
