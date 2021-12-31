# diagnostic-agent

IoT Diagnostic Agent

Agent which monitors and reports the state of critical components of the  manageability framework

## Agent Communication 

- Uses MQTT for communication with other tools/agents
- Currently, once Diagnostic agent is up and running, subscribes to the following topics:
 - `diagnostic/command/#` channel for any incoming commands 
 - `+/state` channel for knowing states of other agents (e.g. `running`, `dead` etc.)
 - `+/broadcast` channel for general message exchange with everyone who is subscribed to this channel
- Publishes state to `diagnostic/state` when running/dead
 
P.S: `+` is a wild-card indicating single level thus matching `diagnostic/state` or `<another-agent>/state`

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
- `install_check` - Executes all of the above commands and returns result

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

Runnning the agent:

- Run: `make run`

Testing the agent:

- Run: `make tests`

## Install via DEB

- Download RPM from Artifacts directory in diagnostic-agent/ repo build in TeamCity
- For Ubuntu: `dpkg -i dist/diagnostic-agent-<latest>.deb`
- Check diagnostic agent is running correctly: `journalctl -fu diagnostic`

## Remove `diagnostic-agent` (via DEB)

- For Ubuntu: `dpkg --purge diagnostic-agent`

## Generate PyDoc for diagnostic agent
NOTE: TeamCity will generate API documentation for each commit

- To generate API documentation locally for Diagnostic agent:
  1. Run `cd doc`
  2. Run `make doc-init`
  3. Run `make html`
  4. Open `html/toc.html` in browser of choice
