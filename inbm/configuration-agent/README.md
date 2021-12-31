# configuration-agent

IoT Configuration Agent

Agent which monitors and responds to key/value pair requests.

## Agent Communication

- Uses MQTT for communication with other tools/agents
- Currently, once Configuration agent is up and running, subscribes to the following topics:
 - `configuration/command/#` channel for any incoming commands
 - `+/state` channel for knowing states of other agents (e.g. `running`, `dead` etc.)
 - `+/broadcast` channel for general message exchange with everyone who is subscribed to this channel
 - `configuration/update/*` channel for any updates made to values in the intel_manageability.conf file.
    the * is replaced by the path of the value updated e.g. updated value = maxCacheSize in telemetry
    on configuration/update/telemetry/maxCacheSize the updated value is published'
- Publishes state to `configuration/state` when running/dead

P.S: `+` is a wild-card indicating single level thus matching `configuration/state` or `<another-agent>/state`

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

## Commands supported

- `get-element` - gets element from the given path.
- `set-element` - sets element at the given path with the given value.

Ex:
- Another agent (ex. Diagnostic) can publish on `configuration/command/get-element` with payload `{'cmd': 'get-element', 'id': 12345, 'path': 'diagnostic/level'}`
- Configuration receives it, processes and sends result as `{'rc':0, 'message': '1'}` on `configuration/response/12345`

## Install
NOTE: Ensure any Python version greater than 3.8 is installed

- Run `git clone https://gitlab.devtools.intel.com/OWR/IoTG/SMIE/Manageability/iotg-inb.git` into local directory
- Run `cd iotg-inb/configuration-agent`
- Run `make init` to install necessary Python packages

## Usage (via Source)
NOTE:  
Ensure Mosquitto broker is installed and configured for Intel(R) In-Band Manageability.  
Some commands will require root privileges (sudo).  
Be sure to run the commands in the `configuration-agent` directory

Changing the logging level:

- Run: `make logging LEVEL=DEBUG`
- Valid values for LEVEL:
  - DEBUG
  - ERROR
  - INFO

Runnning the agent:

- Run: `make run`

Testing the agent:

- Run: `make tests`

## Install (via DEB)

- Download the DEB file from the artifacts tab of a successful TeamCity build
- For Ubuntu: `dpkg -i dist/configuration-agent-<latest>.deb`
- Check configuration agent is running correctly: `journalctl -fu configuration`

## Uninstall (via DEB)

- For Ubuntu: `dpkg --purge configuration-agent`

## Generate PyDoc for configuration agent
NOTE: TeamCity will generate API documentation for each commit

- To generate API documentation locally for Configuration Agent:
  1. Run `cd doc`
  2. Run `make doc-init`
  3. Run `make html`
  4. Open `html/toc.html` in browser of choice
