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
   

</details>

# Introduction

Intel® In-Band Manageability command-line utility, INBC, is a software utility running on a host managing an Edge IoT Device.  It allows the user to perform Device Management operations like firmware update or system update from the command-line. This may be used in lieu of using the cloud update mechanism.

# Prerequisites
Intel® In-Band Manageability needs to be installed and running. INBC can be working even without provisioning to the cloud by running the following command:

```
sudo NO_CLOUD=x provision-tc
```

# 📝 Notes
1. INBC has to be run as root or with sudo.
2. INBC supports FOTA, SOTA, POTA and Config Updates(Get, Set) on an Edge device. This requires downloading from a remote source.
3. Use the query command to find system information needed to fill in FOTA and SOTA update parameters.

# MQTT Communication 

Uses MQTT for communication with INBM agents

### Publish Channels
The agent publishes to the following topics:
- INBM command request: `manageability/request/install`

### Subscribe Channels
The agent subscribes to the following topics:
- Telemetry Response to check if update successful: `manageability/response`
- Searches for keywords in the telemetry events.  Keywords are dependent on command: `manageabilty/event`

# Commands

## FOTA
### Description
Performs a Firmware Over The Air (FOTA) update.

# 📝 Notes
Ensure trusted repository in intel_manageability.conf is to be configured with the URL for inbc fota to download from that specified URL.

### Usage
```
inbc fota {--uri, -u=URI}  
   [--releasedate, -r RELEASE_DATE; default="2026-12-31"]   
   [--signature, -s SIGNATURE_STRING; default=None] 
   [--tooloptions, -to TOOL_OPTIONS]
   [--username, -un USERNAME] 
```

### Examples

 #### Edge device requiring a username/password
```
inbc fota 
     --uri <URI to TAR package>/BIOSUPDATE.tar
     --releasedate 2022-11-3
     --username <username>
```
#### Edge device requiring a signature
```
inbc fota 
     --uri <URI to TAR package>/BIOSUPDATE.tar
     --releasedate 2022-11-3
     --signature <hash string of signature>
```

## SOTA
### Description
Performs a Software Over The Air (SOTA) update.

#### Edge Device
There are two possible software updates on an edge device depending on the Operating System on the device. If the OS is Yocto, then a Mender file will be required. If the OS is Ubuntu, then the update will be performed using the Ubuntu update mechanism.

System update flow can be broken into two parts:
1.  Pre-reboot: The pre-boot part is when a system update is triggered.
2.  Post-reboot: The post-boot checks the health of critical manageability services and takes corrective action.

### Usage
```
inbc sota {--uri, -u=URI} 
   [--releasedata, -r RELEASE_DATE; default="2026-12-31"] 
   [--username, -un USERNAME] 
```
### Examples
#### Edge Device on Yocto OS requiring username/password
```
inbc sota
     --uri <URI to mender file>/update_file.mender 
     --releasedate 2022-02-22 
     --username <username>
```
#### Edge Device on Ubuntu
```
inbc sota
```

## POTA
### Description
Performs a Platform Over The Air update (POTA)

A platform update is the equivalent of performing both a SOTA and FOTA with the same command. This is useful when there is a hard dependency between the software and firmware updates. Please review the information above regarding SOTA and FOTA for determining the correct values to supply.

### Usage
```
inbc pota {--fotauri, -fu=FOTA_URI}
   [--sotauri, -su=SOTA_URI] - N/A for Ubuntu based 
   [--releasedate, -r FOTA_RELEASE_DATE; default="2026-12-31"] 
   [--release_date, -sr SOTA_RELEASE_DATE; default="2026-12-31"] 
   [--fotasignature, -fs SIGNATURE_STRING] 
   [--username, -u USERNAME] 
```
### Examples
#### Edge Device on Yocto OS
```
inbc pota
     --fotauri <remote URI to FOTA file>/bios.bin 
     -r 2021-02-22 
     --sotauri <remote URI to mender file>/update.mender
     -sr 2021-11-12
```
 #### Edge Device on Ubuntu
```
inbc pota
     --fotauri <remote URI to FOTA file>/bios.bin 
     -r 2021-02-22 
 ```

## LOAD
### Description
Load a new configuration file.   This will replace the existing configuration file with the new file.

### Usage
``` 
inbc load
   {--path, -p FILE_PATH}
   [--uri, -u URI]
```
### Examples
#### Load new Configuration File
```
inbc load --uri  <URI to config file>/config.file
```


## GET
### Description
Get key/value pairs from configuration file

### Usage
```
inbc get
   {--path, -p KEY_PATH;...} 
```   
### Examples
#### Get Configuration Value
```
inbc get --path  publishIntervalSeconds
```


## SET
### Description
Set key/value pairs in configuration file

### Usage
```
inbc set
   {--path, -p KEY_PATH;...} 
```
### Examples
#### Set Configuration Value
```
inbc set --path  maxCacheSize:100
```


## Append
### Description
Append is only applicable to three config tags, which are trustedRepositories, sotaSW and ubuntuAptSource

### Usage
```
inbc append
   {--path, -p KEY_PATH;...} 
```
### Examples
#### Append a key/value pair
```
inbc append --path  trustedRepositories:https://abc.com/
```


## Remove
### Description
Remove is only applicable to three config tags, which are trustedRepositories, sotaSW and ubuntuAptSource

### Usage
```
inbc remove
   {--path, -p KEY_PATH;...} 
```


### Examples
#### Remove a key/value pair
```
inbc remove --path  trustedRepositories:https://abc.com/
```

## RESTART
### Description
Restart nodes

### Usage
```
inbc restart
```
### Examples
#### restart
```
inbc restart
```

## QUERY
### Description
Query device(s) for attributes

### Usage
```
inbc query 
   [--option, -o=[all | hw | fw |  os | swbom | version ]; default='all']  
```

### Option Results
[Allowed Options and Results](https://github.com/intel/intel-inb-manageability/blob/develop/docs/Query.md)

### Examples
#### Return all attributes
```
inbc query
```
#### Return only 'hw' attributes
```
inbc query --option hw
```
#### Return only 'sw' attributes
```
inbc query --option sw
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
|     -6      |     6     | HOST BUSY                    |

