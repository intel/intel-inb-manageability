# Developer Guide

## Table of Contents

1. [Introduction](#introduction)
    1. [Purpose](#purpose)
    2. [Audience](#audience)
    3. [Terminology](#terminology)
2. [Source Overview](#source-overview)
   1. [Agents Overview](#agents-overview)
      1. [CloudAdapter Agent](#cloudadapter-agent)
      2. [Configuration Agent](#configuration-agent)
      3. [Diagnostic Agent](#diagnostic-agent)
      4. [Dispatcher Agent](#dispatcher-agent)
      5. [Telemetry Agent](#telemetry-agent)
      6. [Vision Agent](#vision-agent)
      7. [Node Agent](#node-agent)
   2. [Run Agents via Source Code](#run-agents-via-source-code)
3. [Build instructions](#build-instructions)
4. [Configuring Framework](#configuring-framework)
5. [Security](#security)
   1. [OS Hardening](#os-hardening)
   2. [INBM Hardening](#inbm-hardening)
      1. [AppArmor Profiles](#apparmor-profiles)
      2. [Access Control List](#access-control-list)
      3. [MQTT over TLS Support](#mqtt-over-tls-support)
      4. [Trusted Repo List](#trusted-repo-list)
      5. [Signature Verification on OTA Packages](#signature-verification-on-ota-packages)
      6. [Manifest Schema Checks](#manifest-schema-checks)
      7. [Docker Bench Security](#docker-bench-security)
      8. [Platform TPM usage](#platform-tpm-usage)
6. [Enable Debug Logging](#enable-debug-logging)
7. [OTA updates via Manifest](#ota-updates-via-manifest)
   1. [Manifest Rules](#manifest-rules)
   2. [AOTA Updates](#aota-updates)
      1. [AOTA Manifest Parameters](#aota-manifest-parameters)
      2. [Docker manifest examples](#docker-manifest-examples)
      3. [Docker-Compose Manifest Examples](#docker-compose-manifest-examples)
   3. [FOTA Updates](#fota-updates)
      1. [FOTA Manifest Parameters](#fota-manifest-parameters)
      2. [Sample FOTA Manifest](#sample-fota-manifest)
   4. [SOTA Updates](#sota-updates)
      1. [SOTA Manifest Parameters](#sota-manifest-parameters)
      2. [Sample SOTA Manifest](#sample-sota-manifest)
   5. [Configuration Operations](#configuration-operations)
      1. [Configuration Manifest](#configuration-manifest)
      2. [Manual Configuration Update](#manual-configuration-update)
   6. [Power Management](#power-management)
      1. [Restart via Manifest](#restart-via-manifest)
      2. [Shutdown via Manifest](#shutdown-via-manifest)
8. [Extending FOTA support](#extending-fota-support)
   1. [Understanding FOTA Configuration File](#understanding-fota-configuration-file)
   2. [Query command Manifest](#query-command-manifest)
   3. [Configuration Parameter Values](#configuration-parameter-values)
   4. [AppArmor Permissions](#apparmor-permissions)
9. [Creating a New Agent](#creating-a-new-agent)
10. [Issues and Troubleshooting](#issues-and-troubleshooting)
    1. [OTA Error Status](#ota-error-status)
    2. [Dispatcher-Agent Not Receiving Messages](#dispatcher-agent-not-receiving-messages)

Appendix
1. [Vision-agent Xlink Connectivity Class Diagram](#vision-agent-xlink-connectivity-class-diagram)

## Introduction
### Purpose

This Developer Guide provides the reader instructions on how to navigate
and build the INBM source code. It also provides information that Manageability solution developers will find useful, for
example:

-   Configuration file composition
-   How to enable logging
-   Adding new Platform support for FW update capability
-   Adding support to a new Cloud Backend and Communicating with the INBM framework

### Audience

This guide is intended for:
-   Manageability Solution developers to extend/modify the INBM Framework.
-   System Integrators administrating devices running the INBM Framework.

### Terminology

| Term   | Description                                                                                                                                                                                                     |                                                                                                                                                                                                            
|:-------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| AOTA   | Application Over-the-Air (Docker)                                                                                                                                                                               | 
| BIOS   | Basic Input Output System                                                                                                                                                                                       |                                                                                                                                                                        
| Device | A device is any equipment that is installed to be monitored or controlled in a building. Examples of devices include light switches, thermostats, cameras, other mechanical loads, chillers, cooler, and so on. |
| FOTA   | Firmware Over-the-Air                                                                                                                                                                                           |          
| FW     | Firmware                                                                                                                                                                                                        |   
| INBM   | Intel In-Band Manageability                                                                                                                                                                                     |
| IoT    | Internet of Things                                                                                                                                                                                              |                                                                                                                                                                              
| OS     | Operating System                                                                                                                                                                                                |                                                                                                                                                                             
| OTA    | Over-the-air                                                                                                                                                                                                    |
| POTA   | Platform Over-the-Air (SOTA and FOTA combined)                                                                                                                                                                  |
| SMBIOS | System Management BIOS                                                                                                                                                                                          |                                                                                                                                                                                 
| SOTA   | Software Over the Air (OS update)                                                                                                                                                                               |   
| YAML   | Yet Another Markup Language                                                                                                                                                                                     |

## Source Overview

INBM has seven different agents each with its own unique responsibility.

- Cloudadapter-agent
- Configuration-agent
- Diagnostic-agent
- Dispatcher-agent
- Telemetry-agent
- Vision (used with Intel Vision cards)
- Node (used with Intel Vision cards)

### Agents Overview

The Vision and Node agents communicate with each other via Xlink.  All other agents
communicate with the other agents using MQTT.

#### ⚙️CloudAdapter Agent
The cloudadapter-agent relays the messages between the cloud and the dispatcher-agent via MQTT.  

#### ⚙️Configuration Agent
Configuration-agent publishes the config parameter values to all other agents. The parameters are stored at ``/etc/intel_manageability.conf``` file. The descriptions of the parameters are available in the USER guide. To
configure and use a new parameter, refer [Section 4](#configuring-framework).

The *broker.py* handles all config updates to be performed on the system.  
The *configuration.py* starts the configuration agent.  
The *xml_handler.py* contains the necessary functions required to
modify the XML conf file.  
The *constants.py* contains all MQTT subscription and publishing
channels used by configuration-agent.

#### ⚙️Diagnostic Agent
Monitors and reports the state of critical components of the framework. This agent is responsible for performing all 
diagnostic checks like system health checks. It requires software checks before installation, network checks, docker stats, docker-bench-security checks as such. These checks will be performed at timed intervals. These timed intervals can be altered by changing the interval seconds within the ```/etc/intel_manageability.conf``` file using configuration updates from cloud via button click or manifest update. Once the checks are completed, the result message is published to the cloud as telemetry.

The *command_pattern.py* consists of all the commands/checks that are being handled by the diagnostic agent.  
The *dispatch_command.py* dispatches correct command/checks based on the request.  
The *docker_bench_security\_runner.py* runs the DockerBenchSecurity checks on the docker containers and images, while the *event\_watcher.py* watches for events from Docker.  
The *repeating_timer.py* creates a timer that repeats for a given interval specified by the time-based checks.  
The file *constants.py* contains all the MQTT subscription and publishing channels used by diagnostic-agent to communicate with other agents.

#### ⚙️Dispatcher Agent

Dispatches and performs the received commands/operations from the cloud on the device.  It is responsible for determining what kind of request is received from the cloud and invokes the respective commands/threads that would perform the desired operation. Once the operation is complete, the status of the operation will be published to the cloud by this agent.

##### OTA update Class Diagram
When there is an OTA update, the Dispatcher class will call into an Abstract Factory pattern to create the correct concrete classes to perform the update.  The update
can be for either a FOTA, SOTA, AOTA, or POTA.  It will create the classes based on that.  

<img src="media/In-Band Manageability Developer Guide/media/image19.png" alt="P1189#yIS1" style="width:5.39583in;height:3.97917in" />

#### ⚙️Telemetry Agent
Publishes the system’s static and dynamic telemetry to the cloud.

The broker.py initializes the agents publish/subscribe channels.

The *container_usage.py* has code that gets the container stats on a
device.

The *dynamic_attributes.py* contains functions that retrieve dynamic
telemetry information such as disk_usage, cpu percentage, network
telemetry, and available memory,

The *static_attributes.py* have function that gets the device’s static
telemetry information such as cpu_id, disk information, and total
physical memory,

The *telemetry_handling.py* is responsible for calling the necessary
telemetry events upon time-intervals and then publishing the information
on to the cloud and other agents when needed.

The file *constants.py* contains all the MQTT subscription and
publishing channels used by telemetry-agent to communicate with other
agents.

#### ⚙️Vision Agent
The Vision-agent resides on the Host side of a system utilizing Intel Vision cards.  It manages all communication with the individual vision cards.  It is responsible for the following:
- Keep a registry of all individual Vision card.  (hardware, operating system, firmware, and security information)
- Manage the communication status of each Vision card.  Try and reconnect if communication is lost.
- Determine what Vision cards should receive the update if no targets are requested in the manifest.
- Verify that a requested target is eligible for the requested OTA update.
- Publish Telemetry events and results received from Vision cards

The Xlink code used by the Vision-agent uses several classes and two Abstract Factory design patterns.  The class diagram of how these classes interact
can be found in the [Appendix](#vision-agent-xlink-connectivity-class-diagram).

#### ⚙️Node Agent
The Node-agent resides on each of the individual Intel Vision cards.  It manages the communication of each vision card via Xlink.  It is responsible for the following:
- Registering with the Vision-agent on startup with its hardware, firmware, operating system, and security information 
- Sending a heartbeat to the Vision-agent at the set interval (received as a registration response message from the Vision-agent)
- Try and reconnect with Vision-agent if communication is lost.
- Download OTA update file via Xlink from Vision-agent
- Download Configuration load file via Xlink from Vision-agent
- Receive updated manifest from Vision-agent via Xlink and publish it to the Dispatcher-agent via MQTT for OTA updates and configuration requests.
- Relay Telemetry events and results to the Vision-agent via Xlink 

### Run Agents via Source Code

To run and test the agents after modifying the source code, the developer is required to run the script *dev-mode.sh* located
under the **applications.manageability.inband-manageability.iotg-manageability/inbm** directory.

For a developer to run and test the modified code, the following
requirements are required on the device the developer is working on:

-   Prior to developer running the code from source, INBM should
    be installed, running in binary mode, and provisioned to the cloud.

The *dev-mode.sh* script checks the environment, installs all the
required dependencies, disables, and stops the active INBM 
agents.

If the network needs proxy, the developer may need to add the respective
proxy information for pip within the *dev-mode.sh* to
install the dependencies. If no proxy is required, the proxy parameter
needs to be removed from the script.

Once the necessary changes are made to the code, the developer is
required to open one terminal for each associated agent. On each
terminal, run the following command:

```shell
cd ~/applications.manageability.inband-manageability.iotg-manageability/inbm/<agent>
```
<!-- -->

1.  execute tests

Additionally, the user can enable logging from the agent terminal using
the command

```shell
make logging LEVEL=DEBUG
```

or refer to [Section 5](#security) to enable logging prior to running
the INBM via source code.


## Build instructions 

Developers can build INBM executables if source is provided as
part of the release package.

To successfully build the INBM source code, the user would need to execute
the following commands, to make sure the scripts have the executable
access:
```shell
cd applications.manageability.inband-manageability.iotg-manageability/inbm

find . -type f -iname configure -exec chmod +x {} \\;

find . -type f -iname "\*.sh" -exec chmod +x {} \\;

chmod -R 755 trtl/scripts/
```
The user should be able to build the source from the directory
**applications.manageability.inband-manageability.iotg-manageability/inbm** using the command.

Docker needs to be installed on the system to build the code.

```shell
./build.sh
```

or the following command can also be used for better build performance:

```shell
DOCKER_BUILDKIT=1 ./build.sh
```

When the build is complete, the build output can be found in the
**turtlecreek/source/output** folder.

## INBC

INBC is a command-line tool that allows the user to perform OTA and configuration commands from the Edge or 
Host (Intel Vision card solution) system instead of from the cloud.

### INBC Class Diagram
INBC uses the Python 'argparse' library to parse the command-line arguments.  Based on those arguments it will use
the Factory Design Pattern to create the correct concrete 'Command' class.

<img src="media/In-Band Manageability Developer Guide/media/image17.png" alt="P1189#yIS1" style="width:5.39583in;height:3.97917in" />

## Adding a New Configuration Parameter

There may be scenarios where new configurations are required to be added
to extend the functionality of the INBM framework. For example,
if a developer plans to add a new health check telemetry code within the
framework.  They would configure the ```/etc/intel_manageability.conf``` file
to accommodate this health check tag with a certain value by following these steps:

1.  Edit the configuration base file at
```shell
~/inbm/configuration-agent/fpm-template/etc/intel_manageability.conf
```

2.  Edit the XSD schema file that validates the above file:
```shell
~/inbm/configuration-agent/fpm-template/usr/share/configuration-agent/iotg_inb_schema.xsd
```

3. (a) Test the changes by creating a new build using the build instructions mentioned in [Section
    3](#build-instructions). Uninstall and reinstall INBM from the output folder after the build is complete.

(Or)

3. (b) Copy the conf file in step 1 to ```/etc/intel_manageability.conf``` and the
*xsd_schema* file in step 2 to ```/usr/share/configuration-agent/iotg_inb_schema.xsd```.  Then run the agents via 
source code using the steps in [Section 2.2](#run-agents-via-source-code).

## Security 
Security is a key aspect for any software solution to consider,
especially for IoT devices that would be deployed in the field. The
below section details out the various techniques, measures, assumptions,
and recommendations we made when designing Intel In-Band Manageability.

### OS Hardening 
INBM is a user space application that relies on the underlying OS to
have inbuilt security capabilities. Below is a list of solution that is
recommended to help harden the security of any OS.

**Secure Boot:** An industry standard now, where the Platform Firmware
(BIOS) checks signature of the boot chain software, for example, UEFI
drivers, EFI applications, and OS Kernel. If the signature is valid, the
BIOS proceed with the boot chain. This mechanism ensures that boot chain
components were not altered at rest and hence can guarantee to certain
extent the integrity and authenticity of the boot components.

**AppArmor:** AppArmor is an access control mechanism in Linux kernel,
which confines a program to resources that are set in its profile.
AppArmor binds access control attributes to Program and not to Users.
AppArmor profiles are loaded during boot by the kernel and consist of
policies that the Program would be subjected to while accessing the
resources listed in it.

### INBM Hardening 
In addition to the OS hardening recommendations, INBM also
ensures a Secure solution by following the below mechanisms.

#### AppArmor Profiles
INBM framework services/tools have an associated
AppArmor profile, which gets enforced when the framework is installed on
a platform. These profiles define the access that INBM
executables have on the underlying platform resources (file system),
ensuring only certain directories are readable/writeable, thereby
reducing the risk of corrupting the platform by accessing an
unauthorized resource via INBM.

These profiles can be found at: 
```
/etc/apparmor.d/usr.bin.\<service\>
```

#### Access Control List
INBM services communicate with each other over MQTT in
localhost. MQTT being a pub/sub protocol client publish and receive
information on predefined “topics”. Controlled access to these topics is
critical to ensure that an unauthorized MQTT client is not able to
eavesdrop or publish incorrect/garbage data to legitimate clients.
Access control is achieved by setting up ACL list in the MQTT Broker
configuration. Access control specifies which topic each of the MQTT
clients is authorized to read and write to.

ACL list is defined at:
```
/etc/intel-manageability/public/mqtt-broker/acl.file
```

#### MQTT over TLS Support 
To further protect the confidentiality of data being transmitted between
INBM services, the session between the MQTT Broker and the
services is established over mutual TLS. During the provisioning phase
of INBM on a platform, the provisioning script sets up the MQTT
broker and the INBM services with X509 cert and key pairs to
facilitate TLS sessions. The certs and keys are located under:

Certificate: ```/etc/intel-manageability/public/```

Key: ```/etc/intel-manageability/secret/```

#### Trusted Repo List
The OTA command consists of a URL from where INBM fetches the
update (FW, OS, Application) package. To ensure that a package is only
fetched from a trusted location, INBM maintains a list of URLs
tagged as *– \<trustedRepositories\>* in the configuration file.

The trustedRepositories URL’s can be found in: 
```
/etc/intel_manageability.conf
```

#### Signature Verification on OTA Packages
To ensure that the OTA packages are not modified or corrupted, INBM also employs signature verification of the downloaded OTA package
against an OTA cert that the users can enroll during the provisioning  step. INBM verifies the signature of the OTA package being sent
in the Manifest against the signature generated using the enrolled OTA cert.

When the signature matches, INBM proceeds with the update, else it deletes or removes the OTA package from the platform.

#### Manifest Schema Checks
INBM accepts OTA commands in XML format.  It enforces strict Manifest Schema checks to ensure that the OTA commands
meet a predefined requirement of tags, fields, data lengths etc. This ensures that no unwanted data or tags are injected in the OTA commands.

#### Docker Bench Security 
Users can also deploy Containers, INBM uses the Docker Bench Security (DBS) to enhance the security of the platform. The
Docker Bench Security is a script that checks for common best practices around deploying Docker containers in production.

Configuration that enforces DBS can be found in ```/etc/intel_manageability.conf``` under *\<dbs\>* tag.

In production, it is recommended that the DBS be set to **ON**.

#### Platform TPM usage

INBM services communicate with each other over TLS secured MQTT
sessions. The certificates used for this communication are created
during the provisioning phase of the framework where the private/public
certs and keys are generated using OpenSSL API’s. While provisioning,
INBM creates a small file system that writes all the generated
private keys.

The certs and keys are considered secrets, therefore they are kept encrypted
on the disk. The encryption is done using a randomly generated
passphrase which INBM stores in TPM.

INBM uses slot **0x81001231** on the platform TPM as it is
unlikely to conflict with any other programs TPM usage. If this slot is
used by any other program, then we would need to assign a new slot for
INBM.

This can be done by modifying the file: ```/usr/bin/tc-get-tpm-passphrase```

STORE_SLOT="0x81001231"



## Enable Debug Logging

### Description
To enable debug messages, the user can configure *logging.ini* files
for each agent by changing **ERROR** to **DEBUG** with a text editor.  These *logging.ini* files are located at
    ```/etc/intel-manageability/public/\<agent-name\>-agent/logging.ini```

### Steps

#### Option 1 (single agent):
1. Open the logging file: 
```shell
vi  /etc/intel-manageability/public/\<agent-name\>-agent/logging.ini
```

2. Change the value **ERROR** to **DEBUG**

3. Restart the agent: 
```shell
systemctl restart <agent-name>
```

#### Option 2 (multiple agents):
 If logging needs to be enabled on all the agents, the following command can be used: 
```shell
sed -i 's/level=ERROR/level=DEBUG/g' /etc/intel-manageability/public/\*/logging.ini
```

### View Logs
To view logs of a particular agent, run the following command:  
```shell
journalctl -fu <agent-name>
```

## OTA Commands via Manifest

A manifest is an XML string that contains important information about the
update to be executed.  Any OTA update can be done via the Manifest
Update by entering the XML text to update the Endpoint.

To trigger manifest updates:

1. Click the **Dashboard** tab to select Edge Device. Then, click the device name.  
<img src="media/In-Band Manageability Developer Guide/media/image10.png" style="width:6in;height:1.15417in" />

2. Select the **Commands** tab.

<img src="media/In-Band Manageability Developer Guide/media/image11.png" style="width:6in;height:1.47639in" />

3. Scroll down to **Manifest Update** 

<img src="media/In-Band Manageability Developer Guide/media/image12.png" style="width:5.61213in;height:2.12598in" />

### Manifest Rules 

-   All tags marked as **required (R)** in the manifest examples below
    must be in the manifest. Any tags marked as **optional (O)** can be
    omitted.

-   The start of a section is indicated as follows **\<manifest\>**.

-   The end of a section is indicated by **\</manifest\>**. All sections
    must have the start and the matching end tag.

-   Remove spaces, tabs, comments and so on. Make it a single continuous
    long string.  
    Example: **\<xml
    ...\>\<manifest\>\<ota\>\<header\>...\</ota\>\<manifest\>**

-   Parameter within a tag cannot be empty.  
    Example: **\<description\>\</description\>** is not allowed.

### AOTA Updates

Supported AOTA commands and their functionality:

Supported ***docker*** commands:

| *docker* Command                | Definition                                                              |
|:--------------------------------|:------------------------------------------------------------------------|
| [Import](#_Example_of_docker)   | Importing an image to the device and starting a container               |
| [Load](#_Example_of_docker_1)   | Loading an image from the device and starting a container               |
| [Pull](#_Example_of_docker_2)   | Pulls an image or a repository from a registry and starting a container |
| [Remove](#_Example_of_docker_3) | Removes docker images from the system                                   |
| [Stats](#_Example_of_docker_4)  | Returns a live data stream for all the running containers               |

Supported ***docker-compose*** commands:

| *docker-compose* Command          | Definition                                                                    |
|:----------------------------------|:------------------------------------------------------------------------------|
| [Up](#_Example_of_docker-compose) | Deploying a service stack on the device                                       |
| [Down](#_Example_of_docker_5)     | Stopping a service stack on the device                                        |
| [Pull](#_Example_of_docker_6)     | Pulls an image or a repository from a registry and starting the service stack |
| [List](#_Example_of_docker_7)     | Lists containers                                                              |
| [Remove](#_Example_of_docker_8)   | Removes docker images from the system                                         |

Supported **‘Application’** commands:

| *application* Command | Definition                      |
|:----------------------|:--------------------------------|
| Update                | Updating an application package |

Fields in the AOTA form:

| Field                                             | Description                                                                                                                                                                                                                                                  |
|:--------------------------------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| App                                               | Docker or Docker-compose or Application                                                                                                                                                                                                                      |
| Command                                           | **Docker-Compose:** Up, Down, Pull, List and Remove.  <p>**Docker operation**s: Load, Import, Pull, Remove and Stats</p>                                                                                                                                     |
| Container Tag                                     | Name tag for image/container.                                                                                                                                                                                                                                |
| Docker Compose File                               | Specify custom yaml file for docker-compose command. Example: *custom.yml*                                                                                                                                                                                   |
| Fetch                                             | Server URL to download the AOTA container *tar.gz* <p>❗ If the server requires username/password to download the file then provide this information in server username server password                                                                       |
| Server username/<p>Server Password</p>            | If server needs credentials; specify the username and password                                                                                                                                                                                               |
| Version                                           | Each container will have a version number tag. You are recommended to use this version number under version in the AOTA trigger. ```docker images```. See image below for result.                                                                            |
| Docker Registry Docker Registry Username/Password | Specify Docker Registry if accessing any registry other than the default <em>index.docker.io.  <p>Optional fields Docker Registry Username/Password can be used to access docker private images in AOTA through docker and docker-compose up, pull commands. |

#### AOTA Manifest Parameters
[AOTA Manifest Parameters and Examples](Manifest-parameters.md#AOTA)

### FOTA Updates

To perform FOTA updates, IBVs must supply the SMBIOS or Device Tree info
that is unique to each platform SKU. The info must fulfill the vendor,
version, release date, manufacturer, and product name that matches the
endpoint as shown below.

Prior to sending the manifest the user needs to make sure that the
platform information is present within the
```/etc/firmwarm_tool_info.conf``` file. Refer to [Section
7](#ota-updates-via-manifest) on how to modify the file and extend the
FOTA support to a new platform.

1.  The following information must match the data sent in the FOTA
    update command for In-Band Manageability Framework to initiate a
    firmware update process.

| Information | Field        | Checks                                        |
|:------------|:-------------|:----------------------------------------------|
| Firmware    | Vendor       | Exact string match                            |
|             | Version      | Checks if its “unknown”                       |
|             | Release Date | Checks if the FOTA date is newer than current |
| System      | Manufacturer | Exact string match                            |
|             | Product Name | Exact string match                            |

To find the firmware and system fields at the endpoint, run the commands
below:

**Intel x86 UEFI-based products**

For UEFI based platforms, the firmware and system information can be
found running the following command:

```shell
dmidecode –t bios –t system
```

### FOTA Manifest Parameters
[FOTA Manifest Parameters and Examples](Manifest-parameters.md#FOTA)

### FOTA Class Diagram

The FOTA module within the dispatcher-agent uses a combination of an Abstract Factory and Factory Method design pattern. 
The Abstract Factory is used to determine which OS Concrete classes should be created (Linux or Windows-not currently supported).
Then when it creates the installer it will create that Concrete class based on the platform type by using the Factory Method design pattern.

<img src="media/In-Band Manageability Developer Guide/media/image18.png" alt="P1189#yIS1" style="width:5.39583in;height:3.97917in" />

### SOTA Updates 

SOTA flow can be broken into two parts:

1.  Pre-reboot - SOTA update is triggered.
2.  Post-reboot - Checks the health of critical manageability services and takes corrective action.

### SOTA Manifest Parameters
[SOTA Manifest Parameters and Examples](Manifest-parameters.md#SOTA)

### POTA Manifest Parameters

A platform update is the equivalent of performing both a SOTA and FOTA with the same command. This is useful when there is a hard dependency between the software and firmware updates. Please review the information above regarding SOTA and FOTA for determining the correct values to supply.

### POTA Manifest Parameters
[POTA Manifest Parameters and Examples](Manifest-parameters.md#POTA)

### Configuration Operations 

Configuration update is used to change/retrieve/append/remove configuration parameter values from the Configuration file located at
*/etc/intel_manageability.conf*. Refer to tables below to understand the configuration key value pairs

The below tables represent the different sections of the configuration file.

##### All
| Key | Default Value | Description                                                                                    |
|:----|:-------------:|:-----------------------------------------------------------------------------------------------|
| dbs |     WARN      | How the system should be respond if there is a Docker Bench Security alert. [ON, OFF, or WARN] |

##### Telemetry
| Key                            | Default Value | Description                                                                                                                              |
|:-------------------------------|:-------------:|:-----------------------------------------------------------------------------------------------------------------------------------------|
| collectionIntervalSeconds      |  60 seconds   | Time interval after which telemetry is collected from the system.                                                                        |
| publishIntervalSeconds         |  300 seconds  | Time interval after which collected telemetry is published to dispatcher and the cloud                                                   |
| maxCacheSize                   |      100      | Maximum cache set to store the telemetry data. This is the count of messages that telemetry agent caches before sending out to the cloud |
| containerHealthIntervalSeconds |  600 seconds  | Interval after which container health check is run and results are returned.                                                             |
| enableSwBom                    |     true      | Specifies if Software BOM needs to be published in the initial telemetry.                                                                |
| swBomIntervalHours             |      24       | Number of hours between swBom publish.                                                                                                   |

##### Diagnostic
| Key                                |        Default Value         | Description                                                                     |
|:-----------------------------------|:----------------------------:|:--------------------------------------------------------------------------------|
| minStorageMB                       |             100              | Minimum storage that the system should have before or after an update           |
| minMemoryMB                        |              10              | Minimum memory that the system should have before or after an update            |
| minPowerPercent                    |              20              | Value of minimum battery percent that system should have before or after update |
| sotaSW                             | docker, trtl, inbm-telemetry | Mandatory software list.                                                        |
| dockerBenchSecurityIntervalSeconds |             900              | Time interval after which DBS will run and report back to the cloud.            |
| networkCheck                       |             true             | True if network connection is mandatory; otherwise, False.                      |

##### Dispatcher
| Key                             | Default Value | Description                                                                        |
|:--------------------------------|:-------------:|:-----------------------------------------------------------------------------------|
| dbsRemoveImageOnFailedContainer |     false     | True if image should be removed on BSD flagged failed container; otherwise, False. |
| trustedRepositories             |               | List of trusted repositories for fetching packages                                 | 

##### Orchestrator
| Key                  |             Default Value              | Description        |
|:---------------------|:--------------------------------------:|:-------------------|
| orchestratorResponse |                  true                  |                    |
| ip                   |   /etc/opt/csl/csl-node/csl-manager    | path to IP         |
| token                | /etc/opt/csl/csl-node/long-lived-token | path to token      |
| certFile             |     /etc/ssl/certs/csl-ca-cert.pem     | path the cert file |

##### SOTA
| Key                    |     Default Value      | Description                                                                              |
|:-----------------------|:----------------------:|:-----------------------------------------------------------------------------------------|
| ubuntuAptSource        | http://yoururl/ubuntu/ | Location used to update Ubuntu                                                           |
| proceedWithoutRollback |          true          | Whether SOTA update should go through even when rollback is not supported on the system. |

#### Configuration Manifest

[Configuration Command Manifests and Examples](Manifest-parameters.md)

To send the whole manifest with edited parameters at once,

-   Go to **Manifest Update** widget by clicking the **eye** icon next
    to the device of interest under **Methods**.

-   Enter the parameters to be updated along with the path of the
    element in the system.

-   To see the values of parameters, use **Get Element Manifest**.

-   To modify the parameters of interest, use the **Set Element
    Manifest** and edit the values. Use the tag to identify the category
    of the configuration you are updating. Example *diagnostic* or
    *telemetry*.

-   To overwrite the existing configuration file with a new one then use
    the **Load Element Manifest**.

The following commands are useful to append, remove values for
parameters that have multiple values. Parameters that have multiple
values are **trustedRepositories**, **sotaSW** and **ubuntuAptSource**.

-   To append to existing value, use **Append Element** manifest.

-   To remove part of a value, use **Remove Element** manifest

[Configuration GET Manifest and Examples](Manifest-parameters.md#Get)

[Configuration SET Manifest and Examples](Manifest-parameters.md#Set)

[Configuration APPEND Manifest and Examples](Manifest-parameters.md#Append)

[Configuration REMOVE Manifest and Examples](Manifest-parameters.md#Remove)

[Configuration LOAD Manifest and Examples](Manifest-parameters.md#Load)

### Manual Configuration Update:
User can also manually update the parameters of the configuration file
within ```/etc/intel_manageability.conf``` instead of triggering a config
update from the cloud.

To manually edit the parameter values. The user needs to open the
```/etc/intel_manageability.conf``` file in a text editor and edit the
parameter values. Then restart the configuration agent using the
following command:

```shell
systemctl restart configuration
```

### Power Management
Power Management such as restart, or shutdown of an end device can be triggered using a Manifest as well as Button Click.

#### Restart via Manifest
```xml
<?xml version='1.0' encoding='utf-8'?>
<manifest>
    <type>cmd</type>
    <cmd>restart</cmd>
</manifest>
```

#### Shutdown via Manifest
```xml
<?xml version='1.0' encoding='utf-8'?>
<manifest>
    <type>cmd</type>
    <cmd>shutdown</cmd>
</manifest>
```

## Extending FOTA support
INBM supports a scalable FOTA solution where triggering FOTA on any new platform is made easy by adding the platform
related information to a config file that the framework uses while installing the new firmware.

### Understanding FOTA Configuration File 
The FOTA config file is located at ```/etc/firmware_tool_info.conf```.
This file consists of all the platform information of the products that
supports the INBM FOTA.

If a new platform needs to be supported by the framework, the user needs
to add the platform related information in the XML format within this
conf file.

The XML format of the conf file looks similar as the following snippet:
```xml
<?xml version="1.0" encoding="utf-8"?>
<firmware_component>
    <firmware_product name='NUC6CAYS'>
        <bios_vendor>Intel Corp.</bios_vendor>
        <operating_system>linux</operating_system>
        <firmware_tool>UpdateBIOS.sh</firmware_tool>
        <firmware_file_type>bio</firmware_file_type>
    </firmware_product>
</firmware_component>
```
Once the platform information is added, there are no code changes required. This information from the configuration file will be used by the code
to perform a FOTA update.

### Firmware Configuration Parameter Values

The following table helps in understanding what each tag in the firmware configuration file refers to. The **Required(R)/Optional(O)** field
associated with each tag represents whether the tag is mandatory or not while adding a new platform information.

| Tag                                                     | Attributes                   | Example                                                            | Required/Optional | Notes                                                                                                                                                                                              |
|:--------------------------------------------------------|:-----------------------------|:-------------------------------------------------------------------|:-----------------:|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `<?xml version='1.0' encoding='utf-8'?>`                |                              |                                                                    |         R         |
| `<firmware_component>`                                  |                              | `<firmware_component>`                                             |         R         ||
| `<firmware_product>`                                    |                              | See examples below with attributes                                 |         R         | Use the latter when tool_options is required by the firmware bootloader to install the FW.  This is the platform name. Run the command ‘***dmidecode –t bios –t system***’ to view the information |
|                                                         | name=PLATFORM_NAME           | `<firmware_product name='NUC6CAYS'>  `                             |         R         |                                                                                                                                                                                                    |
|                                                         | tool_options=[true or false] | `<firmware_product name='EMBC5000' tool_options='true'> `          |         O         |                                                                                                                                                                                                    |
|                                                         | guid=[true or false]         | `<firmware_product name='Alder Lake Client Platform' guid='true'>` |         O         |                                                                                                                                                                                                    |
| `<operating_system></operating_system>`                 |                              | `<operating_system>linux</operating_system>`                       |         R         | OS name – [linux or windows]  Currently only linux is supported.                                                                                                                                   |
| `<firmware_file_type></firmware_file_type>`             |                              | `<firmware_file_type>bio</firmware_file_type>`                     |         R         | FW file type – bio, fv, cap etc.                                                                                                                                                                   |
| `<bios_vendor></bios_vendor>`                           |                              | `<bios_vendor>Intel Corp.</bios_vendor>`                           |         O         | Run the command '***dmidecode –t bios –t system***’ to view the information                                                                                                                        |
| `<firmware_tool></firmware_tool>`                       |                              | `<firmware_tool>UpdateBIOS.sh</firmware_tool>`                     |         O         | FW tool used for update.  Can be obtained from the vendor                                                                                                                                          |
| `<manufacturer></manufacturer>`                         |                              | `<manufacturer>Intel Corp.</manufacturer>`                         |         O         | Run the command ‘***dmidecode –t bios –t system***’ to view the information                                                                                                                        |
| `<firmware_dest_path><firmware_dest_path>`              |                              | `<firmware_dest_path>/boot/efi/</firmware_dest_path>`              |         O         | Location to store new FW file.  Only used on the platforms where the FW update is just to replace the existing firmware file in a path.                                                            |
| `<firmware_tool_args></firmware_tool_args>`             |                              | `<firmware_tool_args>--apply</firmware_tool_args>`                 |         O         | Additional arguments that follow the firmware tool command to apply firmware                                                                                                                       |
| `<firmware_tool_check_args></firmware_tool_check_args>` |                              | `<firmware_tool_check_args>-s</firmware_tool_check_args>`          |         O         | Additional arguments to check if a FW tool exists on system.                                                                                                                                       |
| `</firmware_product>`                                   |                              | `</firmware_product>`                                              |         R         |                                                                                                                                                                                                    |                                                                                                                                                       |
| `</firmware_component>`                                 |                              | `</firmware_component>`                                            |         R         |                                                                                                                                                                                                    |

### Query command Manifest
INBM supports Query based requests where
triggering query commands via manifest returns query results through dynamic telemetry.

### Supported Query command options and their functionality:

| *query* command options | Description                          |
|:------------------------|:-------------------------------------|
| [all]                   | Publish all the  details together    |
| [fw]                    | Publish firmware details             |
| [guid]                  | Publish GUID of Vision card          |
| [hw]                    | Publish hardware details             |
| [os]                    | Publish operating system details     |
| [security]              | Publish security details             |
| [swbom]                 | Publish software BOM package details |
| [version]               | Publish INBM version details         |

### Query Manifest Parameters 
[Query Manifest and Examples](Manifest-parameters.md#Query)

AppArmor Permissions:
---------------------

Make sure the tool or script path used in [Section 7.2](#aota-updates) has AppArmor permissions granted to execute 
the firmware update.  

For example, the tool or script used to update an Intel NUC  is located at */usr/bin/UpdateBIOS.sh*. 
In this case, the user needs to make sure that the dispatcher’s AppArmor profile has an entry with rix
access rights to the script path. If the entry does not exist, the entry is required to be added to the AppArmor profile.

To edit the AppArmor profile:

Step 1: Open the AppArmor profile for the service.
```shell
vi /etc/apparmor.d/usr.bin.dispatcher
```

Step 2: Add the entry with a comma at the end and save the file.
```shell
/usr/bin/UpdateBIOS.sh rix,
```

<img src="media/In-Band Manageability Developer Guide/media/image13.png" alt="P1167L11#yIS1" style="width:2.30208in;height:0.21875in" />

Step 3: After updating the file, restart the AppArmor service:
```shell
systemctl restart apparmor
```

## Creating a New Agent
The framework code base can be extended when there is a requirement to add a new Agent to perform a designated task.

The following steps provide a clear overview on how to create a new agent.

1.  A new folder with name **\<agent\_name\>-agent** should be created under the *\~/inbm* directory.
2.  Once the source code is added to the folder, mqtt keys need to be generated for the new agent. To generate mqtt-keys,

> <img src="media/In-Band Manageability Developer Guide/media/image14.png" style="width:6.15139in;height:1.24514in" />Go
> to
> *\~/inbm/fpm/mqtt/template/usr/bin/mqtt-ensure-keys-generated*
> file, and add the new agent name in the for-loop(line 50) shown in the
> below image.

3.  These certificates are stored in

```
/etc/intel-manageability/secret/\<agent\_name\>-agent/\<agent\_name\>-agent.crt
```

And the respective keys are stored in

```
/etc/intel-manageability/secret/\<agent\_name\>-agent/\<agent\_name\>-agent.key
```

4.  The above-mentioned paths must be used within the agent code to make
    sure keys and certs are being pulled in from the right location.

5.  Once the code is ready to be built, a service file created for the
    agent should include the correct group name.
```shell
~ /turtle-creek/<agent_name>-agent/fpm-template/etc/systemd/system/<agent_name>.service
```
An example of the *dispatcher.service* file located at
```shell
~/inbm/dispatcher-agent/fpm-template/lib/systemd/system/inbm-dispatcher.service
```
is shown below highlighting its respective group name.

<img src="media/In-Band Manageability Developer Guide/media/image15.png" alt="P1189#yIS1" style="width:5.39583in;height:3.97917in" />


## Issues and Troubleshooting

### OTA Error Status
| Error Message                     | Description                                                                                                           | Result                                                                   |
|:----------------------------------|:----------------------------------------------------------------------------------------------------------------------|:-------------------------------------------------------------------------|
| COMMAND_FAILURE                   | Diagnostic-agent check fails to run properly or diagnostic agent config agent is not up when contacted.               | {'status': 301, 'message': 'COMMAND FAILURE'}                            |
| COMMAND_SUCCESS                   | Post and pre-install check go through.                                                                                | {'status': 200, 'message': 'COMMAND SUCCESS'}                            |
| FILE_NOT_FOUND                    | File to be fetched is not found.                                                                                      | {'status': 404, 'message': 'FILE NOT FOUND'}                             |
| IMAGE_IMPORT_FAILURE              | Image is already present when Image Import is triggered.                                                              | {'status': 401, 'message': 'FAILED IMAGE IMPORT, IMAGE ALREADY PRESENT'} |
| INSTALL_FAILURE                   | Installation was not successful due to invalid package or one of the source file, signature or version checks failed. | {'status': 400, 'message': 'FAILED TO INSTALL'}                          |
| OTA_FAILURE                       | Another OTA is in progress when OTA is triggered.                                                                     | {'status': 302, 'message': 'OTA IN PROGRESS, TRY LATER'}                | 
| UNABLE_TO_START_DOCKER_COMPOSE    | Docker-compose container is not able to be started or spawned etc.                                                    | {'status': 400, 'message': "Unable to start docker-compose container."}  |
| UNABLE_TO_STOP_DOCKER_COMPOSE     | Docker-compose down command was not successful.                                                                       | {'status': 400, 'message': "Unable to stop dockercompose container."}    |
| UNABLE_TO_DOWNLOAD_DOCKER_COMPOSE | Docker-compose download command failed.                                                                               | {'status': 300, 'message': 'FAILED TO PARSE/VALIDATE MANIFEST'}          |

### Dispatcher-Agent Not Receiving Messages 
If the dispatcher-agent does not receive the manifest message from the *cloudadapteragent* after triggering SOTA/FOTA, 
the current workaround is to remove *mosquitto.db*. This will remove the messages in the MQTT queue:

Step 1: 
```shell
systemctl stop mqtt  
```

Step 2:
```sehell
rm /var/lib/mosquitto/mosquitto.db  
```

Step 3:
```shell
systemctl start mqtt
```

## Appendix

### Vision-agent Xlink Connectivity Class Diagram

Below is the class diagram showing how the different classes in the Vision-agent work together to send and receive communication with the individual node-agents.  The xlink classes can be found in the source under both the *inbm-vision/vision-agent/vision/node_communicator* and  */inbm-lib/inbm_vision_lib/xlink* directories.  The classes under the inbm-lib are also used by the node-agent for xlink communication.  Those classes are in green in the diagram below.

<img src="media/In-Band Manageability Developer Guide/media/image16.png" alt="P1189#yIS1" style="width:5.39583in;height:3.97917in" />
