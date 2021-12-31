# telemetry-agent

IoT Telemetry Agent

Central telemetry/logging service for the manageability framework
TODO: expand this description

## Install (via Source)
NOTE: Ensure any Python version greater than 3.8 is installed

- Run `git clone https://gitlab.devtools.intel.com/OWR/IoTG/SMIE/Manageability/iotg-inb.git` into local directory
- Run `cd iotg-inb/telemetry-agent`
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

Runnning the agent:

- Run: `make run`

Testing the agent:

- Run: `make tests`

## Install (via DEB)

- Download DEB from Artifacts directory in telemetry-agent/ repo build in TeamCity
- For Ubuntu: `dpkg -i dist/telemetry-agent-<latest>.deb`
- Check telemetry agent is running correctly: `journalctl -fu telemetry`

## Remove `telemetry-agent` (via DEB)
- For Ubuntu: `dpkg --purge telemetry-agent`

## Generate PyDoc for telemetry agent
NOTE: TeamCity will generate API documentation for each commit

- To generate API documentation locally for Telemetry agent:
  1. Run `cd doc`
  2. Run `make doc-init`
  3. Run `make html`
  4. Open `html/toc.html` in browser of choice
