# Developer Guide

<details>
<summary>Table of Contents</summary>

1. [Introduction](#introduction)
    1. [Purpose](#purpose)
    2. [Audience](#audience)
2. [Architecture](#architecture)
   1. [INB](#inbm)
         1. [CloudAdapter Agent](#%EF%B8%8Fcloudadapter-agent)
         2. [Configuration Agent](#%EF%B8%8Fconfiguration-agent)
         3. [Diagnostic Agent](#%EF%B8%8Fdiagnostic-agent)
         4. [Dispatcher Agent](#%EF%B8%8Fdispatcher-agent-dms)
            1. [OTA Update Class Diagram](#ota-update-class-diagram)
         5. [Telemetry Agent](#%EF%B8%8Ftelemetry-agent)
         6. [TRTL](#%EF%B8%8Ftrtl)
   2. [INBC](#inbc)
3. [Run Agents via Source Code](#run-agents-via-source-code)
6. [Add New Configuration Parameter](#add-new-configuration-parameter)
7. [Security](#security)
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
8. [Enable Debug Logging](#enable-debug-logging)
9. [OTA Commands via Manifest](#ota-commands-via-manifest)
   1. [AOTA Updates](#aota-updates)
      1. [AOTA Manifest Parameters](#aota-manifest-parameters)
   2. [FOTA Updates](#fota-updates)
      1. [FOTA Manifest Parameters](#fota-manifest-parameters)
      2. [FOTA Class Diagram](#fota-class-diagram)
   3. [SOTA Updates](#sota-updates)
      1. [SOTA Manifest Parameters](#sota-manifest-parameters)
   4. [POTA Updates](#pota-updates)
      1. [POTA Manifest Parameters](#pota-manifest-parameters)
   5. [Configuration Operations](#configuration-operations)
      1. [Configuration Manifest](#configuration-manifest)
      2. [Manual Configuration Update](#manual-configuration-update)
   6. [Power Management](#power-management)
      1. [Restart via Manifest](#restart-via-manifest)
      2. [Shutdown via Manifest](#shutdown-via-manifest)
10. [Extending FOTA support](#extending-fota-support)
    1. [Understanding FOTA Configuration File](#understanding-fota-configuration-file)
    2. [Firmware Configuration Parameter Values](#firmware-configuration-parameter-values)
    3. [Query command Manifest](#query-command-manifest)
    4. [AppArmor Permissions](#apparmor-permissions)
11. [Creating a New Agent](#creating-a-new-agent)
12. [Issues and Troubleshooting](#issues-and-troubleshooting)
    1. [OTA Error Status](#ota-error-status)
    2. [Dispatcher-Agent Not Receiving Messages](#dispatcher-agent-not-receiving-messages)
</details>

## Introduction
### Purpose

It provides information that Manageability solution developers will find useful, for
example:

- Overall architecture
- Configuration file composition
- How to enable logging
- Adding new Platform support for FW update capability
- Adding support to a new Cloud Backend and Communicating with the INBM framework

### Audience

This guide is intended for:
-   Manageability Solution developers to extend/modify the INBM Framework.
-   System Integrators administrating devices running the INBM Framework.
                                                                                                                                                                           |

## Architecture

The diagram below depicts the entire Intel Manageability Framework.  There are three projects to the Framework.  They can
either be used together or separately.  The following are the 3 projects:
1. INBM
2. INBC (Optional command-line tool)

<img src="media/In-Band Manageability Developer Guide/media/image1.png" alt="P1189#yIS1" style="width:5.39583in;height:3.97917in" />

### INBM
The diagram below depicts the overall architecture of INBM.  INBM is one of the three projects within the INBM Framework.  
It's responsibilities include:
  - Communication with the Cloud
  - Perform OTA updates (FOTA, SOTA, POTA, and AOTA)
  - Diagnostic checks
  - Telemetry (Static and Dynamic)

There are 5 Agents and 1 Binary associated with INBM which all reside on the same system and communicate with one another via MQTT.
- Cloudadapter-agent
- Configuration-agent
- Diagnostic-agent
- Dispatcher-agent
- Telemetry-agent
- TRTL (Binary Executable)

<img src="media/In-Band Manageability Developer Guide/media/image3.png" alt="P1189#yIS1" style="width:5.39583in;height:3.97917in" />

#### ⚙️CloudAdapter Agent

**Service name:** inbm-cloudadapter

Relays MQTT messages between the cloud API and dispatcher-agent.  

#### ⚙️Configuration Agent

**Service name:** inbm-configuration

Publishes the configuration parameter values to all other agents. The parameters are stored in the ``/etc/intel_manageability.conf`` file. 
The parameters and their descriptions can be found in the [Configuration Parameters](Configuration%20Parameters.md) reference.

#### ⚙️Diagnostic Agent

**Service name:** inbm-diagnostic

The Diagnostic-agent is responsible for the following:
- Perform diagnostic system health checks prior to an OTA install.
- Perform diagnostic check at timed intervals which can be altered by changing the interval seconds with the ```/etc/intel_manageability.conf``` file using configuration 
updates.
- Publishing diagnostic results as Telemetry.

The following checks may be performed:
- Network available
- Docker stats
- Docker-bench-security for container health
- Available memory
- Available storage
- Battery power (mobile systems)
- Required software installed

#### ⚙️Dispatcher Agent (DMS)

**Service name:** inbm-dispatcher

The Dispatcher-agent is the central agent.  It is responsible for the following:
- Dispatching and executing the received commands/operations from the cloud or INBC. Determines the type of request and invokes the respective commands/threads to perform the operation.
- Publishes the resulting status of the operation.

    ##### OTA Update Class Diagram
    When there is an OTA update, the Dispatcher class will call into an [Abstract Factory pattern](https://en.wikipedia.org/wiki/Abstract_factory_pattern) to create the correct concrete classes to perform the update.  The update
    can be for either a FOTA, SOTA, AOTA, or POTA.  It will create the classes based on that.  
    
    <img src="media/In-Band Manageability Developer Guide/media/image19.png" alt="P1189#yIS1" style="width:5.39583in;height:3.97917in" />

#### ⚙️Telemetry Agent

**Service name:** inbm-telemetry

The Telemetry-agent is responsible for the following:
- Collect and publish the system’s static telemetry information.
- Collect and publish dynamic telemetry information at configured intervals.

#### ⚙️TRTL
TRTL is a binary executable developed in Golang.  It is a command-line tool which is also called internally in INB. It provides a wrapper around the API calls to Docker, Docker-Compose, and Snapper in order to provide the following:
 - Uniform interface to install/rollback for back ends such as Docker, Docker-Compose, and Snapper.
 - Ability to open a container to perform Docker-bench-security checks
   - Container management
     - Create
     - Remove
     - Snapshot
     - Rollback
     - List
 - [List of Commands](https://github.com/intel/intel-inb-manageability/blob/develop/inbm/trtl/README.md)

   #### TRTL High Level Class Diagram
   TRTL parses the incoming command and then creates the concrete class based on the type of command (docker, compose, btrfs).  It will then activate the designated command.  
   <img src="media/In-Band Manageability Developer Guide/media/image8.png" alt="P1189#yIS1" style="width:5.39583in;height:3.97917in" />

### INBC

INBC is a command-line based tool that can be used instead of the cloud to perform the following:
- OTA update
- View/Change Configuration settings
- Query system data
- Restart SOC

INBC uses the Python 'argparse' library to parse the command-line arguments.  Based on those arguments it will use
the Factory Design Pattern to create the correct concrete 'Command' class.

<img src="media/In-Band Manageability Developer Guide/media/image17.png" alt="P1189#yIS1" style="width:5.39583in;height:3.97917in" />


## Run Agents via Source Code

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

or refer to [Security](#security) to enable logging prior to running
the INBM via source code.

## Add New Configuration Parameter

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

3. (a) Test the changes by creating a new build using the [build instructions](https://github.com/intel/intel-inb-manageability/blob/develop/README.md). Uninstall and reinstall INBM from the output folder after the build is complete.

(Or)

3. (b) Copy the conf file in step 1 to ```/etc/intel_manageability.conf``` and the
*xsd_schema* file in step 2 to ```/usr/share/configuration-agent/iotg_inb_schema.xsd```.  Then run the agents via 
source code using these [steps](#run-agents-via-source-code).

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
/etc/apparmor.d/usr.bin.<service>
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
sudo vi  /etc/intel-manageability/public/<agent-name>-agent/logging.ini
```

2. Change the value **ERROR** to **DEBUG**


#### Option 2 (multiple agents):
 If logging needs to be enabled on all the agents, the following command can be used: 
```shell
sed -i 's/level=ERROR/level=DEBUG/g' /etc/intel-manageability/public/*/logging.ini
```

### Restart the agents after changing the log level: 
```shell
sudo systemctl restart <agent-name>
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


### AOTA Updates

#### Supported AOTA commands and AOTA form descriptions
[AOTA Updates](AOTA.md)

#### AOTA Manifest Parameters
[AOTA Manifest Parameters and Examples](Manifest%20Parameters.md#AOTA)

### FOTA Updates

To perform FOTA updates, IBVs must supply the SMBIOS or Device Tree info
that is unique to each platform SKU. The info must fulfill the vendor,
version, release date, manufacturer, and product name that matches the
endpoint as shown below.

Prior to sending the manifest the user needs to make sure that the
platform information is present within the
```/etc/firmwarm_tool_info.conf``` file. Refer to [Extending FOTA Support](#extending-fota-support) on how to modify the file and extend FOTA support to a new platform.

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
[FOTA Manifest Parameters and Examples](Manifest%20Parameters.md#FOTA)

### FOTA Class Diagram

The FOTA module within the dispatcher-agent uses a combination of an Abstract Factory and Factory Method design pattern. 
The Abstract Factory is used to determine which OS Concrete classes should be created (Linux or Windows-not currently supported).
Then when it creates the installer it will create that Concrete class based on the platform type by using the Factory Method design pattern.

<img src="media/In-Band Manageability Developer Guide/media/image18.png" alt="P1189#yIS1" style="width:5.39583in;height:3.97917in" />

### SOTA Updates 

SOTA flow can be broken into two parts:

1.  Pre-reboot - SOTA update is triggered.
2.  Post-reboot - Checks the health of critical manageability services and takes corrective action.

#### SOTA Manifest Parameters
[SOTA Manifest Parameters and Examples](Manifest%20Parameters.md#SOTA)

### POTA Updates

A platform update is the equivalent of performing both a SOTA and FOTA with the same command. This is useful when there is a hard dependency between the software and firmware updates. Please review the information above regarding SOTA and FOTA for determining the correct values to supply.

#### POTA Manifest Parameters
[POTA Manifest Parameters and Examples](Manifest%20Parameters.md#POTA)

### Configuration Operations 

Each of the agents has its own set of configuration key/value pairs which can be dynamically set either via the cloud, INBC, or directly in the file.  Note, that if the changes 
are made via the cloud or using INBC that the changes will be dynamic.  If they are made to the file directly, then the service will need to be restarted to pick up the changes.

[Configuration Parameters](Configuration%20Parameters.md)

#### Configuration Manifest

[Configuration Command Manifests and Examples](Manifest%20Parameters.md)

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

[Configuration GET Manifest and Examples](Manifest%20Parameters.md#Get)

[Configuration SET Manifest and Examples](Manifest%20Parameters.md#Set)

[Configuration APPEND Manifest and Examples](Manifest%20Parameters.md#Append)

[Configuration REMOVE Manifest and Examples](Manifest%20Parameters.md#Remove)

[Configuration LOAD Manifest and Examples](Manifest%20Parameters.md#Load)

### Manual Configuration Update:
User can also manually update the parameters of the configuration file
within ```/etc/intel_manageability.conf``` instead of triggering a config
update from the cloud.

To manually edit the parameter values. The user needs to open the
```/etc/intel_manageability.conf``` file in a text editor and edit the
parameter values. Then restart the configuration agent using the
following command:

```shell
sudo systemctl restart configuration
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
| [hw]                    | Publish hardware details             |
| [os]                    | Publish operating system details     |
| [swbom]                 | Publish software BOM package details |
| [version]               | Publish INBM version details         |

### Query Manifest Parameters 
[Query Manifest and Examples](Manifest%20Parameters.md#Query)

AppArmor Permissions:
---------------------

Make sure the tool or script path used in [FOTA Manifest Parameter Values](Manifest%20Parameters.md#FOTA) has AppArmor permissions granted to execute 
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

Step 3: After updating the file, restart the AppArmor service:
```shell
sudo systemctl restart apparmor
```

## Creating a New Agent
The framework code base can be extended when there is a requirement to add a new Agent to perform a designated task.

The following steps provide a clear overview on how to create a new agent.

1. A new folder with name `<agent_name>-agent` should be created under the `inbm` directory.
2. Once the source code is added to the folder, mqtt keys need to be generated for the new agent at provision time. To update the provisioning utility to do this, edit `inbm/fpm/inb-provision-certs/main.go` to add the new agent name to the for loop in the `main` function of this `main.go` file.

3.  These certificates are stored in

```
/etc/intel-manageability/secret/<agent_name>-agent/<agent_name>-agent.crt
```

And the respective keys are stored in

```
/etc/intel-manageability/secret/<agent_name>-agent/<agent_name>-agent.key
```

4.  The above-mentioned paths must be used within the agent code to make
    sure keys and certs are being pulled in from the right location.

5.  Once the code is ready to be built, a service file created for the
    agent should include the correct group name.
```shell
inbm/<agent_name>-agent/fpm-template/etc/systemd/system/<agent_name>.service
```
An example of the `dispatcher.service` file located at
```shell
inbm/dispatcher-agent/fpm-template/lib/systemd/system/inbm-dispatcher.service
```
is shown below.

```
 # Copyright 2021-2023 Intel Corporation All Rights Reserved.
 # SPDX-License-Identifier: Apache-2.0

[Unit]
Description=Dispatcher Agent Service
Requires=network.target mqtt.service
After=mqtt.service
PartOf=inbm.service
After=inbm.service

[Service]
# ExecStart command is only run when everything else has loaded
Type=idle
User=root
EnvironmentFile=-/etc/environment
EnvironmentFile=-/etc/dispatcher.environment
EnvironmentFile=-/etc/intel-manageability/public/mqtt.environment
ExecStart=/usr/bin/inbm-dispatcher
RestartSec=5s
Restart=on-failure
WorkingDirectory=/etc/systemd/system/
Group=dispatcher-agent

[Install]
WantedBy=inbm.service
```

## Issues and Troubleshooting

### OTA Error Status

[Error Messages](Error%20Messages.md)

### Dispatcher-Agent Not Receiving Messages 
If the dispatcher-agent does not receive the manifest message from the *cloudadapteragent* after triggering SOTA/FOTA, 
the current workaround is to remove *mosquitto.db*. This will remove the messages in the MQTT queue:

Step 1: 
```shell
sudo systemctl stop mqtt  
```

Step 2:
```shell
sudo rm /var/lib/mosquitto/mosquitto.db  
```

Step 3:
```shell
sudo systemctl start mqtt
```
