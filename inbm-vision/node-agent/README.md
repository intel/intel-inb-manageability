# node-agent
IoT Node Agent on SOC

Agent which registers with Node Agent and facilitates update on the SOC

## Agent Communication
- Uses MQTT for communication with OTA client (i.e. INB)
- Subscribes to events on `manageability/event`
- Subscribes to telemetry on `manageability/telemetry`
- Subscribes to response on `manageability/response`
- Publishes install request on `manageability/request/install`
- Publishes state to `node/state` when running/dead

 P.S: `+` is a wild-card indicating single level thus matching `node/state` or `<another-agent>/state`

## Install
NOTE: Ensure any Python version greater than 3.8 is installed

- Clone repository into local directory
- Run `cd node-agent`
- Run `make init` to install necessary Python packages

## Usage (via Source)
NOTE:
Ensure Mosquitto broker is installed and configured for INB.
Some commands will require root privileges (sudo).
Be sure to run the commands in the `node-agent` directory

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
- For Ubuntu: `dpkg -i dist/node-agent-<latest>.deb`
- Check node agent is running correctly: `journalctl -fu inbm-node`


## Uninstall (via DEB)
- For Ubuntu: `dpkg --purge inbm-node-agent`


## Generate PyDoc for configuration agent
NOTE: TeamCity will generate API documentation for each commit

- To generate API documentation locally for Node Agent:
  1. Run `cd doc`
  2. Run `make doc-init`
  3. Run `make html`
  4. Open `html/toc.html` in browser of choice