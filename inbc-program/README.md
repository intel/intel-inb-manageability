# Intel® In-band Manageability Command-line Utility (INBC) 

<details>
<summary>Table of Contents</summary>

1. [Introduction](#introduction)
2. [Prerequisites](#prerequisites)
3. [Notes](#-notes)
4. [MQTT Communication](#mqtt-communication-)
   1. [Publish Channels](#publish-channels)
   2. [Subscribe Channels](#subscribe-channels)
5. [Commands](#commands)
   1. [FOTA](#fota)
   2. [SOTA](#sota)
   3. [POTA](#pota)
   4. [AOTA](#aota)
   5. [Configuration Load](#load)
   6. [Configuration Get](#get)
   7. [Configuration Set](#set)
   8. [Restart](#restart)
   9. [Query](#query)
   10. [Source Application Add](#source-application-add)
   11. [Source Application Remove](#source-application-remove)
   12. [Source Application Update](#source-application-update)
   13. [Source Application List](#source-application-list)
   14. [Source OS Add](#source-os-add)
   15. [Source OS Remove](#source-os-remove)
   16. [Source OS Update](#source-os-update)
   15. [Source OS List](#source-os-list)
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
   [--reboot, -rb; default=yes] 
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

SOTA on Ubuntu is supported in 3 modes:
1. Update/Full - Performs the software update.
2. No download - Retrieves and installs packages.
3. Download only - Retrieve packages (will not unpack or install).

By default when SOTA is performaing an install, it will upgrade all eligible packages. The user can optionally specify a list of packages to upgrade (or install if not present) via the [--package-list, -p=PACKAGES] option.


### Usage
```
inbc sota {--uri, -u=URI} 
   [--releasedate, -r RELEASE_DATE; default="2026-12-31"] 
   [--username, -un USERNAME]
   [--mode, -m MODE; default="full", choices=["full","no-download", "download-only"] ]
   [--reboot, -rb; default=yes]
   [--package-list, -p=PACKAGES]
```
### Examples
#### Edge Device on Yocto OS requiring username/password
```
inbc sota
     --uri <URI to mender file>/update_file.mender 
     --releasedate 2022-02-22 
     --username <username>
```
#### Edge Device on Ubuntu in Update/Full mode
```
inbc sota
```

#### Edge Device on Ubuntu in Update/Full mode with package list
```
inbc sota --package-list less,git
```

This will install (or upgrade) the less and git packages and any necessary
dependencies.

#### Edge Device on Ubuntu in download-only mode
```
inbc sota --mode download-only
```

#### Edge Device on Ubuntu in download-only mode with package list
```
inbc sota --mode download-only --package-list less,git
```

This will download the latest versions of less and git and any necessary
dependencies.

#### Edge Device on Ubuntu in no-download mode
```
inbc sota --mode no-download
```

#### Edge Device on Ubuntu in no-download mode with package list
```
inbc sota --mode no-download --package-list less,git
```

This will upgrade or install the packages less and git and any necessary
dependencies, as long as all packages needed to do this have already been
downloaded. (see download-only mode)

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
   [--reboot, -rb; default=yes] 
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

## AOTA
### Description
Performs an Application Over The Air update (AOTA)

INBC is only supporting the application update portion of AOTA.

### Usage
```
inbc aota {--app, -a APP_TYPE} {--command, -c COMMAND}
   [--uri, -u URI]
   [--version, -v VERSION]
   [--containertag, -ct CONTAINERTAG]
   [--file, -f FILE]
   [--reboot, -rb REBOOT; default="no"]
   [--username, -un USERNAME]
   [--dockerusername, -du DOCKERUSERNAME]
   [--dockerregistry, -dr DOCKERREGISTRY]
```

Note: when the arguments --username/--dockerusername are used, passwords need to be entered after the prompt "Enter Password".

### Examples
#### Application Update
```
inbc aota
     --uri <remote URI to AOTA file>/update.deb
```

#### Docker pull

```
inbc aota --app docker --command pull --version 1.0 --containertag name
```

#### Docker load

```
inbc aota --app docker --command load --uri <remote URI to AOTA file>/name.tgz --version 1.0 --containertag name
```

#### Docker import

```
inbc aota --app docker --command import --uri <remote URI to AOTA file>/name.tgz --version 1.0 --containertag name
```

#### Docker remove

```
inbc aota --app docker --command remove --version 1.0 --containertag name
```


#### Docker-compose Up

```
inbc aota --app compose --command up --uri <remote URI to AOTA file>/compose-up.tar.gz --version 1.0 --containertag compose-up --dockerusername xxx --dockerregistry xxxxx
```

#### Docker-compose Up with custom file

```
inbc aota --app compose --command up --uri <remote URI to AOTA file>/compose-up-multiple-yml.tar.gz --version 1.0 --containertag compose-up-multiple-yml --file docker-compose-2.yml
```

#### Docker-compose Pull

```
inbc aota --app compose --command pull --uri <remote URI to AOTA file>/compose-pull.tar.gz --version 1.0 --containertag compose-pull
```

#### Docker-compose Pull with custom file

```
inbc aota --app compose --command up --uri <remote URI to AOTA file>/compose-pull-multiple-yml.tar.gz --version 1.0 --containertag compose-pull-multiple-yml --file docker-compose-2.yml
```

#### Docker-compose Down

```
inbc aota --app compose --command down --version 1.0 --containertag compose-up
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
Append is only applicable to two config tags, which are trustedRepositories and sotaSW

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
Remove is only applicable to two config tags, which are trustedRepositories and sotaSW

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
[Allowed Options and Results](../docs/Query.md)

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

## SOURCE APPLICATION ADD
### Description
Optionally Downloads and encrypts GPG key and stores it on the system under <em>/usr/share/keyrings</em>.  Creates a file under <em>/etc/apt/sources.list.d</em> to store the update source information.
This list file is used during 'sudo apt update' to update the application.  <em>Deb882</em> format may be used instead of downloading a GPG key.

### Usage
```
inbc source application add
   {--sources, -s=SOURCES}
   {--filename, -f=FILENAME}
   [--gpgKeyUri, -gku=GPG_KEY_URI]
   [--gpgKeyName, -gkn=GPG_KEY_NAME]
```

### Example
#### Add an Application Source (with remote GPG key)
```
inbc source application add 
   --gpgKeyUri https://dl-ssl.google.com/linux/linux_signing_key.pub 
   --gpgKeyName google-chrome.gpg 
   --sources "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main"  
   --filename google-chrome.list
```

#### Add an Application Source (using deb822 format)
```
inbc source application add 
   --sources "Types: deb\nURIs: https://files.internal.ledgepark.intel.com\nSuites: ledgepark\nComponents: release\nSigned-By:\n-----BEGIN PGP PUBLIC KEY BLOCK-----\n.\nthegibberishasciikeydatagoesherethegibberishasciikeydatagoeshere\nthegibberishasciikeydatagoesherethegibberishasciikeydatagoeshere\nthegibberishasciikeydatagoesherethegibberishasciikeydatagoeshere=/Xiv\n-----END PGP PUBLIC KEY BLOCK-----\n"  
   --filename google-chrome.list
```

## SOURCE APPLICATION REMOVE
### Description
Removes the source file from under /etc/apt/sources.list.d/.  Optionally removes the GPG key file from under <em>/usr/share/keyrings</em>. 

### Usage
```
inbc source application remove    
   {--filename, -f=FILE_NAME}
   [--gpgKeyName, -gkn=GPG_KEY_NAME]
```

### Example
#### Remove an application source (Both GPG key and Source File)
```commandline
inbc source application remove 
    --gpgKeyName google-chrome.gpg 
    --filename google-chrome.list
```

#### Remove an application source (Source File only)
```commandline
inbc source application remove 
    --filename google-chrome.list
```

## SOURCE APPLICATION UPDATE
### Description
Updates Application sources that are used to update the system
NOTE: Currently this only works on Ubuntu

### Usage
```
inbc source application update 
   {--filename, -f=FILEPATH} 
   {--sources, -s=SOURCES}
```

### Examples
#### Update an application source file
```
inbc source application update 
   --filename google-chrome.list 
   --sources "deb [arch=amd64] https://dl.google.com/linux/chrome/deb/ stable test" "debsrc [arch=amd64] https://dl.google.com/linux/chrome/deb/ stable test2"
```

## SOURCE APPLICATION LIST
### Description
Lists Application sources
NOTE: Currently this only works on Ubuntu

### Usage
```
inbc source application list
```

### Examples
#### Lists all application source files
```
inbc source application list
```

## SOURCE OS ADD
### Description
Appends new source(s) to the <em>/etc/apt/sources.list</em> file

### Usage
```
inbc source os add 
   {--sources, -s=SOURCES}
```

### Example
#### Adds two sources
```
inbc source os add 
   --sources="deb http://archive.ubuntu.com/ubuntu/ jammy-security main restricted" "deb http://archive.ubuntu.com/ubuntu/ jammy-security universe"
```

## SOURCE OS REMOVE
### Description
Removes the provided source(s) from the <em>/etc/apt/sources.list</em> file, if they are present.

### Usage
```
inbc source os remove 
   {--sources, -s=SOURCES}
```

### Example
#### Removes the two provided source(s) from the <em>/etc/apt/sources.list</em> file
```
inbc source os remove 
   --sources="deb http://archive.ubuntu.com/ubuntu/ jammy-security main restricted" "deb http://archive.ubuntu.com/ubuntu/ jammy-security universe"
```

## SOURCE OS UPDATE
### Description
Creates a new <em>/etc/apt/sources.list</em> file with only the sources provided

### Usage
```
inbc source os update 
   {--sources, -s=SOURCES}
```

### Example
#### Creates a new <em>/etc/apt/sources.list</em> file with only the two provided sources
```
inbc source os update 
   --sources="deb http://archive.ubuntu.com/ubuntu/ jammy-security main restricted" "deb http://archive.ubuntu.com/ubuntu/ jammy-security universe"
```

## SOURCE OS LIST
### Description
Lists OS sources
NOTE: Currently this only works on Ubuntu

### Usage
```commandline
inbc source os list
```

### Examples
#### Lists all OS source files
```
inbc source os list
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
