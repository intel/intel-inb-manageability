# Intel® In-band Manageability Command-line Utility (INBC)

<details>
<summary>Table of Contents</summary>

1. [Introduction](#introduction)
2. [Commands](#commands)
   1. [SOTA](#sota)
   2. [Source Application Add](#source-application-add)
   3. [Source Application Remove](#source-application-remove)
   4. [Source OS Update](#source-os-update)

</details>

# Introduction

Intel® In-Band Manageability command-line utility, INBC, is a software utility running on a host managing an Edge IoT Device.  It allows the user to perform Device Management operations like system update from the command-line. This may be used in lieu of using the cloud update mechanism.

# Commands

## SOTA

### Description
Performs a Software Over The Air (SOTA) update.

#### Edge Device
There are two possible software updates on an edge device depending on the Operating System on the device. If the OS is Ubuntu, then the update will be performed using the Ubuntu update mechanism.

System update flow can be broken into two parts:

1. Pre-reboot: The pre-boot part is when a system update is triggered.
2. Post-reboot: The post-boot checks the health of critical manageability services and takes corrective action.

SOTA on Ubuntu and EMT OS is supported in 3 modes:

1. Update/Full - Performs the software update.
2. No download - Retrieves and installs packages.
3. Download only - Retrieve packages (will not unpack or install).

By default, when SOTA is performing an installation, it will upgrade all eligible packages. The user can optionally specify a list of packages to upgrade (or install if not present) via the [--package-list, -p=PACKAGES] option.

### Usage

```commandline
inbc sota {--uri URI} 
   [--releasedate RELEASE_DATE; default="2026-12-31"] 
   [--mode MODE; default="full", choices=["full","no-download", "download-only"] ]
   [--reboot; default=yes]
   [--package-list PACKAGES]
```

### Examples

#### Edge Device on Ubuntu in Update/Full mode

```commandline
inbc sota
```

#### Edge Device on Ubuntu in Update/Full mode with package list

```commandline
inbc sota --package-list less,git
```

This will install (or upgrade) the less and git packages and any necessary
dependencies.

#### Edge Device on Ubuntu in download-only mode

```commandline
inbc sota --mode download-only
```

#### Edge Device on Ubuntu in download-only mode with package list

```commandline
inbc sota --mode download-only --package-list less,git
```

This will download the latest versions of less and git and any necessary
dependencies.

#### Edge Device on Ubuntu in no-download mode

```commandline
inbc sota --mode no-download
```

#### Edge Device on Ubuntu in no-download mode with package list

```commandline
inbc sota --mode no-download --package-list less,git
```

This will upgrade or install the packages and get any necessary
dependencies, as long as all packages needed to do this have already been
downloaded. (see download-only mode)

## SOURCE APPLICATION ADD

### Description

Optionally Downloads and encrypts GPG key and stores it on the system under <em>/usr/share/keyrings</em>.  Creates a file under <em>/etc/apt/sources.list.d</em> to store the update source information.
This list file is used during 'sudo apt update' to update the application.  <em>Deb882</em> format may be used instead of downloading a GPG key.

**NOTE:** Make sure to add gpgKeyUri to the trustedrepositories before using INBC source application ADD command

### Usage

```commandline
inbc source application add
   {--sources SOURCES}
   {--filename FILENAME}
   [--gpgKeyUri GPG_KEY_URI]
   [--gpgKeyName GPG_KEY_NAME]
```

### Example

#### Add an Application Source (non-deb822 format with remote GPG key)

```commandline
inbc source application add 
   --gpgKeyUri https://dl-ssl.google.com/linux/linux_signing_key.pub 
   --gpgKeyName google-chrome.gpg 
   --sources "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main"  
   --filename google-chrome.list
```

#### Add an Application Source (using deb822 format)

**NOTE:** In the Signed-By: Section, use the following guidelines.

   - Each blank line has a period in it. -> " ."
   - Each line after the Signed-By: starts with a space -> " gibberish"

```commandline
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

## SOURCE APPLICATION REMOVE

### Description

Removes the source file from under /etc/apt/sources.list.d/.  Optionally removes the GPG key file from under <em>/usr/share/keyrings</em>.

### Usage

```commandline
inbc source application remove    
   {--filename FILE_NAME}
   [--gpgKeyName GPG_KEY_NAME]
```

### Example

#### Remove an application source (Both GPG key and Source File)

```commandline
inbc source application remove 
    --gpgKeyName google-chrome.gpg 
    --filename google-chrome.list
```

#### Remove an application source (deb822 format)

```commandline
inbc source application remove 
    --filename google-chrome.sources
```

## SOURCE OS UPDATE

### Description
Creates a new <em>/etc/apt/sources.list</em> file with only the sources provided

### Usage

```commandline
inbc source os update
    {--sources SOURCES}
```

### Example

### Creates a new <em>/etc/apt/sources.list</em> file with only the two provided sources

```commandline
inbc source os update
    --sources "deb http://archive.ubuntu.com/ubuntu/ jammy-security main restricted" "deb http://archive.ubuntu.com/ubuntu/ jammy-security universe"
```
