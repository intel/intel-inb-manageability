# dispatcher-agent

## Overview

- IoT Manageability agent/Dispatcher which dispatches signals/commands to other tools/agents for performing OTA (over-the-air) updates
- Talks to `diagnostic-agent` for pre/post install checks to confirm gateway/device health before performing OTA

## Agent Communication 

- Uses MQTT for communication with other tools/agents
- Currently, once Dispatcher is up and running, subscribes to the following topics:
 - `dispatcher/command` channel for any incoming commands (commands that Dispatcher supports is TBD)
 - `+/state` channel for knowing states of other agents (e.g. `running`, `dead` etc.)
 - `+/broadcast` channel for general message exchange with everyone who is subscribed to this channel
- Publishes state to `dispatcher/state` when running/dead

- Talks to `diagnostic-agent` to confirm device health before and after OTA install
- After install OTA check is done only for successful installations
- Before install OTA check is done for all scenarios
 
P.S: `+` is a wild-card indicating single level thus matching `dispatcher/state` or `<another-agent>/state`

## MQTT Client Module

- Provides an abstraction to the Paho MQTT Client APIs
- Any other microservice/agent can setup async broker communication through these. For example:
- Refer PyDocs for more API details
```
import mqttclient

# Create MQTT client instance by connecting to broker
client = MQTT(<id>, <host>, <port>, <keep-alive>)
client.start()

# Subscribe to topic
client.subscribe*('/topic')
# Publish to topic
client.publish('/topic', 'test')

# Close connection
client.stop()
```
## OTA/CONFIG Manifest

- Dispatcher expects a `Manifest` which is XML containing metadata for the OTA install
- The currently supported format is located at `packaging/config/ota_manifest_sample.xml`
- The contents of this file (without the spaces, indent etc.) is sent through the `Trigger OTA` custom action

## Custom Actions/Commands registered with cloud Adapter HDC

`HDC Adapter` can register commands with the HDC cloud. Current registered commands:

1. `Trigger OTA`
 - Parameter Name: `Manifest`
 - Parameter Value: Contents of `packaging/config/ota_manifest_sample.xml`
 - Please change the values of the file as per the deployment need

P.S: Remove the spaces, indent, comments etc. while pasting into `Manifest` parameter. It should be a continuous string

It is possible to trigger to two types of OTA's so far through this trigger or to trigger an update/fetch to config agent
1. AOTA - Application Over the Air
2. FOTA - Firmware Over the Air
3. CONFIG FETCH/UPDATE

###AOTA
Is responsible for installing the update requested by sending the manifest down.
- It does a source check. If we need to pull a file from a repository it checks whether the repository is a secured/trusted one or not.
The secured repositories list is stored in the config file in configuration manager. The list is extracted from there when an update comes
and the source is checked against that list. If it is present the update is triggered otherwise it is rejected.



### FOTA
The Firmware update tool currently does the below:
 - Use DMI path to gather current firmware info on the gateway
 - Compares it to the firmware info pointed to the manifest file
 - Then if there is a good match, it downloads the file and places it in location pointed by <path> in manifest file
 - It reboots the gateway allowing the driver to kick in during boot for firmware installation

### CONFIG FETCH/UPDATE
The configuration agent is responsible for changes to the configuration files and to inform other
agents about changes
 - Dispatcher parses the manifest and calls set_element or get_element in configuration agent
 - Configuration agent sets or gets the value based on the functionality called
 - The returned value is displayed on HDC and dispatcher logs


### SHUTDOWN/RESTART COMMAND TRIGGER
The shutdown or restart command can also be sent down using the manifest to trigger a system shutdown or reboot.


If the anything goes wrong, the file is not downloaded from the repository. The code only works for Apollo Lake capable CRB.

## Install
NOTE: Ensure any Python version greater than 3.8 is installed

- Run `git clone https://gitlab.devtools.intel.com/OWR/IoTG/SMIE/Manageability/iotg-inb.git` into local directory
- Run `cd dispatcher-agent`
- Run `make init` to install necessary Python packages

## Usage (via Source)

NOTE:  
Ensure Mosquitto broker is installed and configured for Intel(R) In-Band Manageability.  
Some commands will require root privileges (sudo).  
Be sure to run the commands in the `dispatcher-agent` directory

Changing the logging level:

- Run: `make logging LEVEL=DEBUG`
- Valid values for LEVEL:
  - DEBUG
  - ERROR
  - INFO

Run the agent:

- For production, run: `make run`
- For non-production, set GENERIC_LISTEN_PORT, e.g: `GENERIC_LISTEN_PORT=8888 make run`

Test the agent:

- Run: `make tests`

## Install via DEB

P.S: The below step assumes you already have `trtl` binary installed.

- For Ubuntu, Debian, or Deby: `dpkg -i dist/inbm-dispatcher-agent-<latest>.deb`
- Check Dispatcher is running correctly: `journalctl -fu dispatcher`
- This starts Dispatcher by using the default HDC adapter

## Remove `dispatcher-agent` (via DEB)
- For Ubuntu, Debian, or Deby: `dpkg --purge inbm-dispatcher-agent`

P.S: If user wants to run the Dispatcher service via Test Adapter:
 1. Open `/lib/systemd/system/inbm-dispatcher.service`
 2. Edit `ExecStart` to use `--adapter=test`
 3. Add a new environment variable `Environment='GENERIC_LISTEN_PORT=8888` before `ExecStart`
 4. Save and close
 5. `systemctl daemon-reload`
 6. `systemctl start inbm-dispatcher`

## How to enable Runtime Configs for Containers
1. Attach USB stick to gateway for testing purposes (can be any device)
2. Change manifest - sample XML
3. Pass the string and trigger update. Once it is successful you should be able to see the contents of usb listed in dispatcher logs.

## Generate PyDoc API documentation for Dispatcher locally (for dev/testing puposes)
NOTE: TeamCity will generate API documentation for each commit

- To generate API documentation locally for Dispatcher Agent:
  1. Run `cd doc`
  2. Run `make doc-init`
  3. Run `make html`
  4. Open `html/toc.html` in browser of choice
