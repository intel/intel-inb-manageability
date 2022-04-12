# Intel® In-band Manageability Command-line Utility (INBC) 

<details>
<summary>Table of Contents</summary>

1. [Introduction](#introduction)
2. [Prerequisites](#prerequisites)
3. [Notes](#-notes)
4. [MQTT Communication](#mqtt-communication)
   1. [Publish Channels](#publish-channels)
   2. [Subscribe Channels](#subscribe-channels)
5. [Commands](#commands)
   1. [FOTA](#fota)
   2. [SOTA](#sota)
   3. [POTA](#pota)
   4. [Configuration Load](#load)
   5. [Configuration Get](#get)
   6. [Configuration Set](#set)
   7. [Restart](#restart)
   8. [Query](#query)
6. [Status Codes](#status-codes)
7. [Return and Exit Codes](#return-and-exit-codes)
8. [FAQ](#-faq)
   1. [How do I find what values to use for a specific HDDL plug-in card FOTA update?](#-how-do-i-find-what-values-to-use-for-a-specific-hddl-plug-in-card-fota-update)
      

</details>

# Introduction

Intel® In-Band Manageability command-line utility, INBC, is a software utility running either on a host managing HDDL plugin cards via PCIe or an Edge IoT Device.  It allows the user to perform Device Management operations like firmware update or system update from the command-line. This may be used in lieu of using the cloud update mechanism.

# Prerequisites
Intel® In-Band Manageability needs to be installed and running.

# 📝 Notes
1. INBC supports FOTA, SOTA, POTA and Config Updates(Get, Set) on an Edge device. Use the **'--nohddl'** flag to target an Edge device.  This requires downloading from a remote source.
2. If targets=NONE for HDDL; the vision-agent determines the eligible targets based on their attributes.
3. Use the query command to find system information needed to fill in FOTA and SOTA update parameters.
4. If placing files local on the system for update, they need to be placed in a folder with read/write access in the apparmor profile.  The recommended path would be ```/var/cache/manageability```.  If another directory is used, the apparmor profile would need to
be modified to allow read/write access to that directory.

# MQTT Communication 

Uses MQTT for communication with INBM agents

### Publish Channels
The agent publishes to the following topics:
- INBM command request: `manageability/request/install`
- Vision-agent command requests: `ma/request/{command}`  command=status, restart, query
- Vision-agent configuration requests: `ma/configuration/update/{command}`  command=get_element, set-element, load


### Subscribe Channels
The agent subscribes to the following topics:
- Telemetry Response to check if update successful: `manageability/response`
- Searches for keywords in the telemetry events.  Keywords are dependent on command: `manageabilty/event`
- Determines if Vision-agent is present by looking for xlink driver message: `ma/xlink/status`

# Commands

## FOTA
### Description
Performs a Firmware Over The Air (FOTA) update on either an Edge Device or HDDL Plug-in Card.

❗ See [Note #4](#-notes) if placing files local on the system.

### Usage
```
inbc fota [--nohddl] {--path,  -p=PATH | --uri, -u=URI}  
   [--releasedate, -r RELEASE_DATE; default="2024-12-31"] 
   [--vendor, -v VENDOR; default="Intel"] 
   [--biosversion, -b BIOS_VERSION; default="5.12"] 
   [--manufacturer, -m MANUFACTURER; default="intel"] 
   [--product, -pr PRODUCT; default="kmb-hddl2"] 
   [--signature, -s SIGNATURE_STRING; default=None] 
   [--tooloptions, -to TOOL_OPTIONS]
   [--username, -un USERNAME] 
   [--target, -t TARGETS...; default=None]
```

### Examples

 #### Edge device requiring a username/password
```
inbc --nohddl fota 
     --uri <URI to TAR package>/BIOSUPDATE.tar
     --releasedate 2022-11-3
     --username <username>
```
#### Edge device requiring a signature
```
inbc --nohddl fota 
     --uri <URI to TAR package>/BIOSUPDATE.tar
     --releasedate 2022-11-3
     --signature <hash string of signature>
```
#### HDDL Plug-in cards - update all eligible cards with FIP image
```
inbc fota -p <local path to FIP>/fip-hddl2.bin --releasedate 2022-11-3
 ```
#### HDDL Plug-in cards - update specific cards with FIP image
```
inbc fota -p <local path to FIP>/fip-hddl2.bin 
   --releasedate 2022-11-3
   --target 123ABC 345DEF
 ```

## SOTA
### Description
Performs a Software Over The Air (SOTA) update on either an Edge Device or HDDL Plug-in Card.

❗ See [Note #4](#-notes) if placing files local on the system.

#### Edge Device
There are two possible software updates on an edge device depending on the Operating System on the device. If the OS is Yocto, then a Mender file will be required. If the OS is Ubuntu, then the update will be performed using the Ubuntu update mechanism.

#### HDDL Plug-in Card
To perform software updates on HDDL plug-in cards, a newer Mender image file will be required. The Query command can be used to determine the current version on HDDL plug-in cards.

System update flow can be broken into two parts:
1.  Pre-reboot: The pre-boot part is when a system update is triggered.
2.  Post-reboot: The post-boot checks the health of critical manageability services and takes corrective action.

### Usage
```
inbc sota [--nohddl] 
   {--path,  -p=PATH | --uri, -u=URI} 
   [--releasedata, -r RELEASE_DATE; default="2024-12-31"] 
   [--username, -un USERNAME] 
   [--target, -t TARGETS...; default=None]
```
### Examples
#### Edge Device on Yocto OS requiring username/password
```
inbc sota --nohddl 
     --uri <URI to mender file>/update_file.mender 
     --releasedate 2022-02-22 
     --username <username>
```
#### Edge Device on Ubuntu
```
inbc sota --nohddl
```

#### HDDL Plug-in cards - update all eligible cards with FIP image
```
inbc sota 
     --path <path to mender file>/core_kmb_hddl2.mender 
     --releasedate 2022-09-30 
```
#### HDDL Plug-in cards - update specific cards with FIP image
```
inbc sota 
     --path <path to mender file>/core_kmb_hddl2.mender 
     --releasedate 2022-09-30 
     --target 000732767ffb-16781312 000732767ffb-16780544
```

## POTA
### Description
Performs a Platform Over The Air update (POTA)

A platform update is the equivalent of performing both a SOTA and FOTA with the same command. This is useful when there is a hard dependency between the software and firmware updates. Please review the information above regarding SOTA and FOTA for determining the correct values to supply.

❗ See [Note #4](#-notes) if placing files local on the system.
### Usage
```
inbc pota [--nohddl] 
   {--fotapath, -fp=FOTA_PATH | --fotauri, -fu=FOTA_URI}
   [--sotapath, -sp FILE_PATH | --sotauri, -su=SOTA_URI] - N/A for Ubuntu based 
   [--releasedate, -r FOTA_RELEASE_DATE; default="2024-12-31"] 
   [--vendor, -v VENDOR; default="Intel"] 
   [--biosversion, -b BIOS_VERSION; default="5.12"] 
   [--manufacturer, -m MANUFACTURER; default="intel"] 
   [--product, -pr PRODUCT; default="kmb-hddl2"] 
   [--release_date, -sr SOTA_RELEASE_DATE; default="2024-12-31"] 
   [--fotasignature, -fs SIGNATURE_STRING] 
   [--username, -u USERNAME] 
   [--target, -t TARGETS...; default=None]
```
### Examples
#### Edge Device on Yocto OS
```
inbc pota --nohddl 
     --fotauri <remote URI to FOTA file>/bios.bin 
     -r 2021-02-22 
     --sotauri <remote URI to mender file>/update.mender
     -sr 2021-11-12
```
 #### Edge Device on Ubuntu
```
inbc pota --nohddl 
     --fotauri <remote URI to FOTA file>/bios.bin 
     -r 2021-02-22 
 ```
#### HDDL Plug-in cards - update all eligible cards with FIP image
```
inbc pota 
     -fp /var/cache/manageability/repository-tool/fip-hddl2.bin 
     -r 2022-09-30
     -sp /var/cache/manageability/core_kmb_hddl2.mender 
     -sr 2021-11-12
```
#### HDDL Plug-in cards - update specific cards with FIP image
```
inbc pota 
     -fp /var/cache/manageability/repository-tool/fip-hddl2.bin 
     -r 2022-09-30
     -sp /var/cache/manageability/core_kmb_hddl2.mender 
     -sr 2021-11-12
     --target 000732767ffb-16781312 000732767ffb-16780544
```


## LOAD
### Description
Load a new configuration file.   This will replace the existing configuration file with the new file.

❗ See [Note #4](#-notes) if placing files local on the system.
### Usage
``` 
inbc load [--nohddl] 
   {--path, -p FILE_PATH}
   [--uri, -u URI]
   [--targettype, -tt NODE | VISION | NODE_CLIENT; default="node"] 
   [--target, -t TARGETS...; default=None]
```
### Examples
#### Edge Device on Yocto OS
```
inbc load --nohddl --uri  <URI to config file>/config.file
```
#### Edge Device on Ubuntu
```
inbc load --nohddl --uri  <URI to config file>/config.file
```
#### HDDL Plug-in cards - load new configuration on vision-agent
```
inbc load --path /var/cache/manageability/intel_manageabilty_vision.conf -tt vision
```
#### HDDL Plug-in cards - load new configuration on all node-agents
```
inbc load --path /var/cache/manageability/intel_manageabilty_node.conf -tt node
```
#### HDDL Plug-in cards - load new configuration on specific node-agents
```
inbc load --path /var/cache/manageability/intel_manageabilty_node.conf 
   -tt node -t 
   --target 000732767ffb-16781312 000732767ffb-16780544
```

#### HDDL Plug-in cards - load new configuration on all node-clients
```
inbc load --path /var/cache/manageability/intel_manageabilty.conf -tt node_client
```
#### HDDL Plug-in cards - load new configuration on specific node-clients
```
inbc load --path /var/cache/manageability/intel_manageabilty.conf 
   -tt node_client -t 
   --target 000732767ffb-16781312 000732767ffb-16780544
```


## GET
### Description
Get key/value pairs from configuration file

### Usage
```
inbc get [--nohddl]
   {--path, -p KEY_PATH;...} 
   [--targettype, -tt NODE | VISION | NODE_CLIENT; default="node"]
   [--target, -t TARGETS...; default=None]
```   
### Examples
#### Edge Device on Yocto OS
```
inbc get --nohddl --path  publishIntervalSeconds
```
#### Edge Device on Ubuntu
```
inbc get --nohddl --path  publishIntervalSeconds
```
#### HDDL Plug-in cards - get values from vision-agent
```
inbc get -p isAliveTimerSecs;heartbeatRetryLimit -tt vision
```
#### HDDL Plug-in cards - get values from all node-agents
```
inbc get -p heartbeatResponseTimerSecs;registrationRetryLimit -tt node
```
#### HDDL Plug-in cards - get values from specific node-agents
```
inbc get -p heartbeatResponseTimerSecs;registrationRetryLimit 
   -tt node 
   --target 000732767ffb-16781312 000732767ffb-16780544
```

#### HDDL Plug-in cards - get values from all node-clients
```
inbc get -p maxCacheSize;trustedRepositories -tt node_client
```
#### HDDL Plug-in cards -get values from specific node-clients
```
inbc get -p maxCacheSize;trustedRepositories 
   -tt node_client 
   --target 000732767ffb-16781312 000732767ffb-16780544
```


## SET
### Description
Set key/value pairs in configuration file

### Usage
```
inbc set [--nohddl]
   {--path, -p KEY_PATH;...} 
   [--targettype, -tt NODE | VISION | NODE_CLIENT; default="node"] 
   [--target, -t TARGETS...; default=None]
```
### Examples
#### Edge Device on Yocto OS
```
inbc set --nohddl --path  maxCacheSize:100
```
#### Edge Device on Ubuntu
```
inbc set --nohddl --path  maxCacheSize:100
```
#### HDDL Plug-in cards - set values on vision-agent
```
inbc set -p isAliveTimerSecs:50;heartbeatRetryLimit:2 -tt vision
```
#### HDDL Plug-in cards - set values on all node-agents
```
inbc set -p heartbeatResponseTimerSecs:350;registrationRetryLimit:7 -tt node
```
#### HDDL Plug-in cards - set values on specific node-agents
```
inbc set -p heartbeatResponseTimerSecs:350;registrationRetryLimit:7 
   -tt node 
   --target 000732767ffb-16781312 000732767ffb-16780544
```

#### HDDL Plug-in cards - set values on all node-clients
```
inbc set -p maxCacheSize:120;publishIntervalSeconds:310 -tt node_client
```
#### HDDL Plug-in cards - set values on specific node-clients
```
inbc set -p maxCacheSize:120;publishIntervalSeconds:310 
   -tt node_client 
   --target 000732767ffb-16781312 000732767ffb-16780544
```


## RESTART
### Description
Restart nodes

❗  This command is only supported on HDDL Plug-in cards 
### Usage
```
inbc restart [--target, -t TARGETS...; default=None]
```
### Examples
#### HDDL Plug-in cards - restart all nodes
```
inbc restart
```
#### HDDL Plug-in cards - restart specific nodes
```
inbc restart --target 000732767ffb-16781312 000732767ffb-16780544
```

## QUERY
### Description
Query device(s) for attributes

### Usage
```
inbc query 
   [--option, -o=[all | hw | fw | guid (HDDL only) | os | security (HDDL only) | status (HDDL only) | swbom (Edge only) | version ]; default='all']  
   [--targettype, -tt=[vision | node ]; default=None] 
   [--target, -t TARGETS...; default=None]
```

### Option Results
[Allowed Options and Results](https://github.com/intel/intel-inb-manageability/blob/develop/docs/Query.md)

### Examples
#### HDDL Plug-in cards - return all attributes
```
inbc query
```
#### HDDL Plug-in cards - return only 'hw' attributes for all nodes
```
inbc query --option hw
```
#### HDDL Plug-in cards - return only 'sw' attributes for  specific nodes
```
inbc query --option sw --target 000732767ffb-16781312 000732767ffb-16780544
```

# Status Codes

 | Message         | Description                           | Result                                        |
|:----------------|:--------------------------------------|:----------------------------------------------|
| COMMAND_SUCCESS | Post and pre-install check go through | {'status': 200, 'message': 'COMMAND SUCCESS'} |
| FILE_NOT_FOUND  | File to be fetched is not found       | {'status': 404, 'message': 'FILE NOT FOUND'}  |
 | COMMAND_FAILURE | Update did not go through             | {'status': 400, 'message': 'COMMAND FAILURE'} |

# Return and Exit Codes

| Return Code | Exit Code | Description                  |
|:-----------:|:---------:|:-----------------------------|
|      0      |     0     | SUCCESS                      |
|     -1      |     1     | FAIL                         |
|     -2      |     2     | COMMAND TIMED OUT            |
|     -3      |     3     | HOST UNAVAILABLE             |
|     -4      |     4     | NODE NOT FOUND               |
|     -5      |     5     | NODE UNRESPONSIVE            |
|     -6      |     6     | HOST BUSY                    |
|     -11     |    11     | XLINK DEVICE NOT FOUND (OFF) |
|     -12     |    12     | XLINK DEVICE BUSY            |
|     -13     |    13     | XLINK DRIVER UNAVAILABLE     |
|     -14     |    14     | XLINK DRIVER ERROR           |

# ❔ FAQ

<details><summary>[See answers to frequently asked questions]</summary>

### ❓ How do I find what values to use for a specific HDDL plug-in card FOTA update?

> Use the query command with the '--option hw' flag.  This will return the attributes for the card(s) that can be used for the update.


</details>
