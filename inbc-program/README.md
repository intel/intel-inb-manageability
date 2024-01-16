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
   10. [Source Application Add (Ubuntu)](#source-application-add-ubuntu)
   11. [Source Application Remove (Ubuntu)](#source-application-remove-ubuntu)
   12. [Source Application Update (Ubuntu)](#source-application-update-ubuntu)
   13. [Source Application List (Ubuntu)](#source-application-list-ubuntu)
   14. [Source OS Add (Ubuntu)](#source-os-add-ubuntu)
   15. [Source OS Remove (Ubuntu)](#source-os-remove-ubuntu)
   16. [Source OS Update (Ubuntu)](#source-os-update-ubuntu)
   17. [Source OS List (Ubuntu)](#source-os-list-ubuntu)
   18. [Source Cert Add (Ubuntu)](#source-cert-add-ubuntu)
   19. [Source Cert Remove (Ubuntu)](#source-cert-remove-ubuntu)
   20. [Source Cert Update (Ubuntu)](#source-cert-update-ubuntu)
   21. [Source Cert List (Ubuntu)](#source-cert-list-ubuntu)
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

## SOURCE APPLICATION ADD (Ubuntu)
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
#### Add an Application Source (non-deb822 format with remote GPG key)
```
inbc source application add 
   --gpgKeyUri https://dl-ssl.google.com/linux/linux_signing_key.pub 
   --gpgKeyName google-chrome.gpg 
   --sources "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main"  
   --filename google-chrome.list
```

#### Add an Application Source (Ubuntu) (using deb822 format)

**NOTE:** In the Signed-By: Section, use the following guidelines.

      - Each blank line has a period in it. -> " ."
      - Each line after the Signed-By: starts with a space -> " gibberish"

```
inbc source application add 
   --sources 
      "Enabled: yes" 
      "Types: deb"
      "URIs: http://dl.google.com/linux/chrome/deb/" 
      "Suites: stable" 
      "Components: main" 
      "Signed-By:" 
      " -----BEGIN PGP PUBLIC KEY BLOCK-----" 
      " Version: GnuPG v1.4.2.2 (GNU/Linux)" 
      " ." 
      " mQGiBEXwb0YRBADQva2NLpYXxgjNkbuP0LnPoEXruGmvi3XMIxjEUFuGNCP4Rj/a" 
      " kv2E5VixBP1vcQFDRJ+p1puh8NU0XERlhpyZrVMzzS/RdWdyXf7E5S8oqNXsoD1z" 
      " fvmI+i9b2EhHAA19Kgw7ifV8vMa4tkwslEmcTiwiw8lyUl28Wh4Et8SxzwCggDcA" 
      " feGqtn3PP5YAdD0km4S4XeMEAJjlrqPoPv2Gf//tfznY2UyS9PUqFCPLHgFLe80u" 
      " QhI2U5jt6jUKN4fHauvR6z3seSAsh1YyzyZCKxJFEKXCCqnrFSoh4WSJsbFNc4PN" 
      " b0V0SqiTCkWADZyLT5wll8sWuQ5ylTf3z1ENoHf+G3um3/wk/+xmEHvj9HCTBEXP" 
      " 78X0A/0Tqlhc2RBnEf+AqxWvM8sk8LzJI/XGjwBvKfXe+l3rnSR2kEAvGzj5Sg0X" 
      " 4XmfTg4Jl8BNjWyvm2Wmjfet41LPmYJKsux3g0b8yzQxeOA4pQKKAU3Z4+rgzGmf" 
      " HdwCG5MNT2A5XxD/eDd+L4fRx0HbFkIQoAi1J3YWQSiTk15fw7RMR29vZ2xlLCBJ" 
      " bmMuIExpbnV4IFBhY2thZ2UgU2lnbmluZyBLZXkgPGxpbnV4LXBhY2thZ2VzLWtl" 
      " eW1hc3RlckBnb29nbGUuY29tPohjBBMRAgAjAhsDBgsJCAcDAgQVAggDBBYCAwEC" 
      " HgECF4AFAkYVdn8CGQEACgkQoECDD3+sWZHKSgCfdq3HtNYJLv+XZleb6HN4zOcF" 
      " AJEAniSFbuv8V5FSHxeRimHx25671az+uQINBEXwb0sQCACuA8HT2nr+FM5y/kzI" 
      " A51ZcC46KFtIDgjQJ31Q3OrkYP8LbxOpKMRIzvOZrsjOlFmDVqitiVc7qj3lYp6U" 
      " rgNVaFv6Qu4bo2/ctjNHDDBdv6nufmusJUWq/9TwieepM/cwnXd+HMxu1XBKRVk9" 
      " XyAZ9SvfcW4EtxVgysI+XlptKFa5JCqFM3qJllVohMmr7lMwO8+sxTWTXqxsptJo" 
      " pZeKz+UBEEqPyw7CUIVYGC9ENEtIMFvAvPqnhj1GS96REMpry+5s9WKuLEaclWpd" 
      " K3krttbDlY1NaeQUCRvBYZ8iAG9YSLHUHMTuI2oea07Rh4dtIAqPwAX8xn36JAYG" 
      " 2vgLAAMFB/wKqaycjWAZwIe98Yt0qHsdkpmIbarD9fGiA6kfkK/UxjL/k7tmS4Vm" 
      " CljrrDZkPSQ/19mpdRcGXtb0NI9+nyM5trweTvtPw+HPkDiJlTaiCcx+izg79Fj9" 
      " KcofuNb3lPdXZb9tzf5oDnmm/B+4vkeTuEZJ//IFty8cmvCpzvY+DAz1Vo9rA+Zn" 
      " cpWY1n6z6oSS9AsyT/IFlWWBZZ17SpMHu+h4Bxy62+AbPHKGSujEGQhWq8ZRoJAT" 
      " G0KSObnmZ7FwFWu1e9XFoUCt0bSjiJWTIyaObMrWu/LvJ3e9I87HseSJStfw6fki" 
      " 5og9qFEkMrIrBCp3QGuQWBq/rTdMuwNFiEkEGBECAAkFAkXwb0sCGwwACgkQoECD" 
      " D3+sWZF/WACfeNAu1/1hwZtUo1bR+MWiCjpvHtwAnA1R3IHqFLQ2X3xJ40XPuAyY" 
      " /FJG" 
      " %20=Quqp" 
      " -----END PGP PUBLIC KEY BLOCK-----"
   --filename google-chrome.sources
```

## SOURCE APPLICATION REMOVE (Ubuntu)
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

#### Remove an application source (Ubuntu) (deb822 format)
```commandline
inbc source application remove 
    --filename google-chrome.sources
```

## SOURCE APPLICATION UPDATE (Ubuntu)
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

## SOURCE APPLICATION LIST (Ubuntu)
### Description
Lists Application sources

### Usage
```
inbc source application list
```

### Examples
#### Lists all application source files
```
inbc source application list
```

## SOURCE OS ADD (Ubuntu)
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

## SOURCE OS REMOVE (Ubuntu)
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

## SOURCE OS UPDATE (Ubuntu)
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

## SOURCE OS LIST (Ubuntu)
### Description
Lists OS sources

### Usage
```
inbc source os list
```

### Examples
#### Lists all OS source files
```
inbc source os list
```

## SOURCE CERT ADD (Ubuntu)
### Description
Adds a CA Certificate to the _/etc/ssl/certs_ directory.

### Usage
```
inbc source cert add
   {--cert, -c=CERT}
   {--filename, -f=FILENAME}
```

### Example
#### Add a certificate
```
inbc source cert add
   --filename example.crt
   --Cert "-----BEGIN CERTIFICATE-----"
      "MIIF/TCCA+WgAwIBAgITEwDUCI4G8jP3hk98fgACANQIjjANBgkqhkiG9w0BAQsF"
      "ADBQMQswCQYDVQQGEwJVUzEaMBgGA1UEChMRSW50ZWwgQ29ycG9yYXRpb24xJTAj"
      "BgNVBAMTHEludGVsIEludGVybmFsIElzc3VpbmcgQ0EgNUEwHhcNMjMwMjE4MDEx"
      "MzMzWhcNMjQwMjEzMDExMzMzWjB2MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2Fs"
      "aWZvcm5pYTEUMBIGA1UEBxMLU2FudGEgQ2xhcmExGjAYBgNVBAoTEUludGVsIENv"
      "cnBvcmF0aW9uMSAwHgYDVQQDExd0ZWxlbWV0cnkuYXBwLmludGVsLmNvbTCCASIw"
      "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN8eBDZW4AfyvcKSopuEF1bYCmV/"
      "ba9PkL3CouaRYGZHV3mkXoxCNg+PeTKlbkHW8PEWNjVRoi8jnexlzUqLTlQ2bkM7"
      "rJPuzR7iR5zci2KPFoHrJeWCsAOQj0lC73RQ3valn7Ex6xH8bFhv6OhklCXkgpGS"
      "VxBZVzBPQR6YxbO+u25V8BRvsA0KkTX89qnkbXmH0/fOw8yUNpZ5CMxdiT/pTICR"
      "YnzOfy6GxCtwdSGlReesBJpVbFPJVYmPJhEm5UUoH0X0wD9Uc967MLGi5sjVVxOq"
      "qBBJ6JGywpzqYSGYm6+O7hsQA3cUxZQslsJbWgt0LtfatIr16y/KoZJYxjkCAwEA"
      "AaOCAagwggGkMB0GA1UdDgQWBBS7/cLQNf+W0SC75d7X8oiywNAyUTAfBgNVHSME"
      "GDAWgBRpkJZpxwBpltt7XZqP9jrqKJStJjA6BgNVHR8EMzAxMC+gLaArhilodHRw"
      "Oi8vcGtpLmludGVsLmNvbS9jcmwvSW50ZWxDQTVBKDIpLmNybDBFBggrBgEFBQcB"
      "AQQ5MDcwNQYIKwYBBQUHMAKGKWh0dHA6Ly9wa2kuaW50ZWwuY29tL2NydC9JbnRl"
      "bENBNUEoMikuY3J0MAsGA1UdDwQEAwIFoDA9BgkrBgEEAYI3FQcEMDAuBiYrBgEE"
      "AYI3FQiGw4x1hJnlUYP9gSiFjp9TgpHACWeC7d1OgbvMdwIBZAIBITAdBgNVHSUE"
      "FjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwJwYJKwYBBAGCNxUKBBowGDAKBggrBgEF"
      "BQcDATAKBggrBgEFBQcDAjBLBgNVHREERDBCghd0ZWxlbWV0cnkuYXBwLmludGVs"
      "LmNvbYIndGVsZW1ldHJ5LmFwcHMxLW9yLWludC5pY2xvdWQuaW50ZWwuY29tMA0G"
      "CSqGSIb3DQEBCwUAA4ICAQAbNfjUKcjBVg4mo8iULIRw/s4P0LvXTK17/XfddVA7"
      "K0QIZwTjIkzElviov+ZRWgdyGNxTO8DZYgp2pGHWsGL019lRnxzd8rKRYHTX8Uuv"
      "IZC3u9CzFIug4AUm7z2n9oOPiG9f57Yj1DPGSEpOuWlJWMqz6RFMdt6P31y8ZFfi"
      "JTDzAz+iKSRJZMd8JXmowzE7mOqc5MalQ/3uwNypNiw+m9/dcGx5aDPbk9KButvD"
      "QweLPA2SicXLIDkK7IbcSJk/a5Q5HcaMFg0aojEPMt0bdsRzzU+hUX5T90it73FM"
      "UZCm23c2Ts7driW7sM3Are87vgSkcZQmZ/+ypHPF1mEdlifJNyUpQ/tLYZmYzRwt"
      "WEHrOyxeDb9xlgx/KwIR9VSR26uWOovDQOhUtsCPF6PWJP1xE53uHb3NtEwRiuXg"
      "3zJxmO6MxgmJgQTN9QIPkv6cAlUobObYLjDVejw0kFvnS4/uX6x0ZhqmvNwkKjFN"
      "FHzcjlb7fbAS6kfjWzUHUvA29b8k3yJ0B3HKVR/T9w/6GSRcoFWin+51pGL/kckD"
      "Ekv7PDpE+idGVq+T9Rd5U3G+RYWMMYAirTNlqvY7aDq2itxcjMB5zCxtr8k2Utkb"
      "/C0MOtewruf09JYeZZSNfP9NF0YlSaQlqZCC8AmPdV8w786ezZg56hRXxg0Wmw1M"
      "AQ=="
      "-----END CERTIFICATE-----"
```

## SOURCE CERT REMOVE (Ubuntu)
### Description
Removes a CA Certificate from the _/etc/ssl/certs/_ directory. 

### Usage
```
inbc source cert remove    
   {--filename, -f=FILE_NAME}
```

### Example
#### Remove a certificate
```
inbc source cert remove 
    --filename example.crt
```

## SOURCE CERT UPDATE (Ubuntu)
### Description
Removes the certificate in the provided file, and creates a new certificate using the provided cert information.

### Usage
```
inbc source cert update
   {--filename, -f=FILE_NAME}
   {--cert, -c=CERT}
```

### Examples
#### Update an application source file
```
inbc source cert update
   --filename example.crt
   --cert "-----BEGIN CERTIFICATE-----"
      "MIIF/TCCA+WgAwIBAgITEwDUCI4G8jP3hk98fgACANQIjjANBgkqhkiG9w0BAQsF"
      "ADBQMQswCQYDVQQGEwJVUzEaMBgGA1UEChMRSW50ZWwgQ29ycG9yYXRpb24xJTAj"
      "BgNVBAMTHEludGVsIEludGVybmFsIElzc3VpbmcgQ0EgNUEwHhcNMjMwMjE4MDEx"
      "MzMzWhcNMjQwMjEzMDExMzMzWjB2MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2Fs"
      "aWZvcm5pYTEUMBIGA1UEBxMLU2FudGEgQ2xhcmExGjAYBgNVBAoTEUludGVsIENv"
      "cnBvcmF0aW9uMSAwHgYDVQQDExd0ZWxlbWV0cnkuYXBwLmludGVsLmNvbTCCASIw"
      "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN8eBDZW4AfyvcKSopuEF1bYCmV/"
      "ba9PkL3CouaRYGZHV3mkXoxCNg+PeTKlbkHW8PEWNjVRoi8jnexlzUqLTlQ2bkM7"
      "rJPuzR7iR5zci2KPFoHrJeWCsAOQj0lC73RQ3valn7Ex6xH8bFhv6OhklCXkgpGS"
      "VxBZVzBPQR6YxbO+u25V8BRvsA0KkTX89qnkbXmH0/fOw8yUNpZ5CMxdiT/pTICR"
      "YnzOfy6GxCtwdSGlReesBJpVbFPJVYmPJhEm5UUoH0X0wD9Uc967MLGi5sjVVxOq"
      "qBBJ6JGywpzqYSGYm6+O7hsQA3cUxZQslsJbWgt0LtfatIr16y/KoZJYxjkCAwEA"
      "AaOCAagwggGkMB0GA1UdDgQWBBS7/cLQNf+W0SC75d7X8oiywNAyUTAfBgNVHSME"
      "GDAWgBRpkJZpxwBpltt7XZqP9jrqKJStJjA6BgNVHR8EMzAxMC+gLaArhilodHRw"
      "Oi8vcGtpLmludGVsLmNvbS9jcmwvSW50ZWxDQTVBKDIpLmNybDBFBggrBgEFBQcB"
      "AQQ5MDcwNQYIKwYBBQUHMAKGKWh0dHA6Ly9wa2kuaW50ZWwuY29tL2NydC9JbnRl"
      "bENBNUEoMikuY3J0MAsGA1UdDwQEAwIFoDA9BgkrBgEEAYI3FQcEMDAuBiYrBgEE"
      "AYI3FQiGw4x1hJnlUYP9gSiFjp9TgpHACWeC7d1OgbvMdwIBZAIBITAdBgNVHSUE"
      "FjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwJwYJKwYBBAGCNxUKBBowGDAKBggrBgEF"
      "BQcDATAKBggrBgEFBQcDAjBLBgNVHREERDBCghd0ZWxlbWV0cnkuYXBwLmludGVs"
      "LmNvbYIndGVsZW1ldHJ5LmFwcHMxLW9yLWludC5pY2xvdWQuaW50ZWwuY29tMA0G"
      "CSqGSIb3DQEBCwUAA4ICAQAbNfjUKcjBVg4mo8iULIRw/s4P0LvXTK17/XfddVA7"
      "K0QIZwTjIkzElviov+ZRWgdyGNxTO8DZYgp2pGHWsGL019lRnxzd8rKRYHTX8Uuv"
      "IZC3u9CzFIug4AUm7z2n9oOPiG9f57Yj1DPGSEpOuWlJWMqz6RFMdt6P31y8ZFfi"
      "JTDzAz+iKSRJZMd8JXmowzE7mOqc5MalQ/3uwNypNiw+m9/dcGx5aDPbk9KButvD"
      "QweLPA2SicXLIDkK7IbcSJk/a5Q5HcaMFg0aojEPMt0bdsRzzU+hUX5T90it73FM"
      "UZCm23c2Ts7driW7sM3Are87vgSkcZQmZ/+ypHPF1mEdlifJNyUpQ/tLYZmYzRwt"
      "WEHrOyxeDb9xlgx/KwIR9VSR26uWOovDQOhUtsCPF6PWJP1xE53uHb3NtEwRiuXg"
      "3zJxmO6MxgmJgQTN9QIPkv6cAlUobObYLjDVejw0kFvnS4/uX6x0ZhqmvNwkKjFN"
      "FHzcjlb7fbAS6kfjWzUHUvA29b8k3yJ0B3HKVR/T9w/6GSRcoFWin+51pGL/kckD"
      "Ekv7PDpE+idGVq+T9Rd5U3G+RYWMMYAirTNlqvY7aDq2itxcjMB5zCxtr8k2Utkb"
      "/C0MOtewruf09JYeZZSNfP9NF0YlSaQlqZCC8AmPdV8w786ezZg56hRXxg0Wmw1M"
      "AQ=="
      "-----END CERTIFICATE-----"
```

## SOURCE CERT LIST (Ubuntu)
### Description
Lists Cert files in the _/etc/sll/certs/_ directory.

### Usage
```commandline
inbc source cert list
```

### Examples
#### Lists name of all cert files
```
inbc source cert list
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
