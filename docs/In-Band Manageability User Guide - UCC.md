# User Guide – Ultra Cloud Client (UCC)

<details>
<summary>Table of Contents</summary>

1. [Introduction](#introduction)
    1. [Purpose](#purpose)
    2. [Audience](#audience)
2. [Ultra Cloud Client (UCC) Overview](#ultra-cloud-client-ucc-overview)
    1. [Generating Device Keys and Certificates](#generating-device-keys-and-certificates)
3. [Provisioning a Device](#provisioning-a-device)
   1. [Provisioning Command Parameters](#provisioning-command-parameters)
4. [Issues and Troubleshooting](#issues-and-troubleshooting)
    1. [Acquiring Debug Messages from Agents](#acquiring-debug-messages-from-agents)

</details>

## Introduction
### Purpose

This User Guide serves to provide the reader an overview on how to:
- Provision the Edge IoT device running In-Band Manageability Framework

### Audience

This guide is intended for

- System Integrators administrating devices running In-Band
    Manageability framework.

## Ultra Cloud Client (UCC) Overview

### Generating Device Keys and Certificates

Prior to having the device authentication done using X509 mechanism, it
is mandatory to have TLS set on the UCC server. 

## Provisioning a Device

**NOTE:**
> Prerequisite and assumptions: The Intel® In-Band Manageability Framework is installed on the Edge IoT device.

1. Launch the provisioning script using the command.
```shell
sudo provision-tc
```

2. If the device was previously provisioned, the following message
    appears. To override the previous cloud configuration, press **Y**:

```
A cloud configuration already exists: "ucc"
Replace configuration?
[Y/N] Y
```

3. A prompt appears to choose the cloud service; press **3** and
    **\[ENTER\]** for ThingsBoard:

```
Please choose a cloud service to use:
1) Azure IoT Central
2) Thingsboard
3) UCC
4) Custom
#? 3
```

4. A prompt appears for the **IP address** and **Port**   
    
```
Please enter the Server IP:

127.0.0.1
```
> Note that the server port entry can be left empty to use the default port
```
Please enter the server port (default 1883):

8883
```

5. A prompt for **Device** **provision type** appears; select the type
    of device authentication preferred:
``` 
Please choose provision type:
1. Token Authentication
2. X509 Authentication
```

6. Choosing option **1. Token Authentication** requires user to enter
    the token. This file may be named ucc.ca.pem.crt.

7. Choosing option **2. X509 Authentication** requires user to have
    device certificate and key generated.
    The file paths of the files with extension *.crt* and *.key* are entered in
    the prompts.
```
Configuring device to use X509 auth requires device certificate verification.

Are device certs and keys generated?  [Y/N] Y

Input Device certificate from file? [Y/N] y

Please enter a filename to import 

Input path to Device certificate file (*.crt):
/home/abc/client1.crt

Input Device key from file? [Y/N] Y

Input path to Device key file (*.key):
/home/abc/client1.key

```

8. If user selects Token based authentication in step 6, an option for
    TLS will appear; press **Y** if the server was configured for TLS).
> If the user selects X509 authentication, it is mandatory to have TLS configured. By default, the application proceeds with the TLS configuration.

```
Configure TLS? [Y/N]
```

9. Choose an input method for the *\*.pem.crt* file. The `Absolute file
    path` option requires a path to the file that does not include
    wildcards like \~. The `Console input` option will ask for the file
    to be input into the console; note that all lines preceding a line
    break cannot be edited:
```
Configuring TLS.
Input ucc CA from file? [Y/N] y

Please enter a filename to import 

UCC CA file (*.pem.crt):

/home/abc/ucc.ca.pem.crt
```

10. If the cloud provisioning is successful, the following message
    appears:
```
Successfully configured cloud service!
```

11. A Yes/No user prompt appears asking for a certificate verification
    on an OTA package. Choose `N`.
```
Signature checks on OTA packages cannot not be validated without provisioning a cert file.
Do you wish to use a pre-provisioned cert file for signature checks for OTA packages? [Y/N] N
```

12. In-Band Manageability Framework Services are Enabled and Started.

    The script will then start the Intel Manageability services; when
    the script finishes, the device should be able to interact with the
    UCC Server.

```
Enabling and starting agents...
reated symlink /etc/systemd/system/multi-user.target.wants/inbm-cloudadapter.service → /etc/systemd/system/inbm-cloudadapter.service.
Intel(R) In-Band Manageability Provisioning Complete
```

13. If at any time the cloud service configuration needs to be changed
    or updated, run the provisioning steps again.

**Note:** 
> If provisioning is unsuccessful, refer to **[Provisioning Unsuccessful](#issues-and-troubleshooting)** for Troubleshooting.

### Provisioning Command Parameters

Provisioning can be done with or without TPM security by setting
`PROVISION_TPM`. `PROVISION_TPM` can be set to:

-   `auto`: use TPM if present; disable if not present; do not prompt.

-   `disable`: do not use TPM.

-   `enable`: use TPM; return error code if TPM not detected.

-   (unset): default behavior; use TPM if present, prompt if not.

To run provisioning that automatically detects the presence of TPM
security:

```shell
sudo PROVISION_TPM=auto provision-tc
```

To run without TPM security:
```shell
sudo PROVISION_TPM=disable provision-tc
```

## Issues and Troubleshooting

[General Troubleshooting](Issues%20and%20Troubleshooting.md)

### Acquiring Debug Messages from Agents

Refer to the [Developer Guide](In-Band%20Manageability%20Developer%20Guide.md).
