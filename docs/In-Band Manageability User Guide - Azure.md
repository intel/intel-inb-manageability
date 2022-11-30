# In-Band Manageability Framework User Guide – Azure&reg;

<details>
<summary>Table of Contents</summary>

1. [Introduction](#introduction)
    1. [Audience](#audience)
3. [Azure&reg; Overview](https://github.com/intel/intel-inb-manageability/blob/Broken_link_522523/docs/In-Band%20Manageability%20User%20Guide%20-%20Azure.md#azure-overview)
    1. [Getting Started with Azure&reg;](https://github.com/intel/intel-inb-manageability/blob/Broken_link_522523/docs/In-Band%20Manageability%20User%20Guide%20-%20Azure.md#getting-started-with-azure)
        1. [Creating Azure&reg; portal account](https://github.com/intel/intel-inb-manageability/blob/Broken_link_522523/docs/In-Band%20Manageability%20User%20Guide%20-%20Azure.md#creating-azure-portal-account)
        2. [Setting up an Azure&reg; IoT Central Application ](https://github.com/intel/intel-inb-manageability/blob/Broken_link_522523/docs/In-Band%20Manageability%20User%20Guide%20-%20Azure.md#setting-up-an-azure-iot-central-application)
        3. [Accessing Azure&reg;](https://github.com/intel/intel-inb-manageability/blob/Broken_link_522523/docs/In-Band%20Manageability%20User%20Guide%20-%20Azure.md#accessing-azure)
        4. [Setting up the application for X509 based device enrollment](#setting-up-the-application-for-x509-based-device-enrollment)
    2. [Creating a Device and Obtaining Device Credentials](#creating-a-device-and-obtaining-device-credentials)
        1. [Shared Access Signature (SAS) authentication:](#shared-access-signature-sas-authentication)
        2. [X509 authentication:](#x509-authentication)
4. [Provisioning a Device](#provisioning-a-device)
    1. [NOTE ON PREREQUISITE AND ASSUMPTIONS:](#note-on-prerequisite-and-assumptions)
    2. [Provisioning Command Parameters](#provisioning-command-parameters)
5. [Using the IoT Central Application](#using-the-iot-central-application)
    1. [Viewing and Managing Devices](#viewing-and-managing-devices)
    2. [Navigating the Device Interface](#navigating-the-device-interface)
6. [Performing batch operations](#performing-batch-operations)
7. [OTA Updates](#ota-updates)
    1. [Trusted Repositories ](#trusted-repositories)
    2. [Preparing OTA Update Packages](#preparing-ota-update-packages)
        1. [Creating FOTA Package](#creating-fota-package)
        2. [Creating SOTA Package](#creating-sota-package)
        3. [Creating AOTA Package](#creating-aota-package)
        4. [Creating Configuration Load Package](#creating-configuration-load-package)
    3. [How to Generate Signature](#how-to-generate-signature)
8. [OTA Commands](#ota-commands)
    1. [Commands - Definitions and Usage](#commands---definitions-and-usage)
    2. [AOTA](#aota)
       1. [Supported AOTA commands and AOTA form Descriptions](#supported-aota-commands-and-aota-form-descriptions)
    3. [AOTA Docker-Compose Operations](#aota-docker-compose-operations)
        1. [Docker Compose Up](#docker-compose-up)
        2. [Docker-Compose Down](#docker-compose-down)
    4. [Docker-Compose Pull](#docker-compose-pull)
        1. [Docker-Compose List](#docker-compose-list)
        2. [Docker-Compose Remove](#docker-compose-remove)
    5. [AOTA Docker Operations](#aota-docker-operations)
        1. [Docker Import](#docker-import)
        2. [Docker Load](#docker-load)
        3. [Docker Pull](#docker-pull)
        4. [Docker Remove](#docker-remove)
        5. [Docker Stats](#docker-stats)
    6. [AOTA Application Operations](#aota-application-operations)
        1. [Application Update](#application-update)
        2. [AOTA Docker/Docker-Compose Operations via Manifest](#aota-dockerdocker-compose-operations-via-manifest)
    7. [FOTA Updates](#fota-updates)
        1. [FOTA Update via Button Click](#fota-update-via-button-click)
        2. [FOTA Update via Manifest](#fota-update-via-manifest)
    8. [SOTA Updates](#sota-updates)
        1. [SOTA Update Via ‘Trigger SOTA’ Button Click (Debian Package Manager, Ubuntu OS)](#sota-update-via-trigger-sota-button-click-debian-package-manager-ubuntu-os)
        2. [SOTA Update Via ‘Trigger SOTA’ Button Click (Mender)](#sota-update-via-trigger-sota-button-click-mender)
        3. [SOTA Update via Manifest](#sota-update-via-manifest)
    9. [Configuration Update ](#configuration-update)
        1. [Configuration Set](#configuration-set)
        2. [Configuration Get](#configuration-get)
        3. [Configuration Load](#configuration-load)
        4. [Configuration Append](#configuration-append)
        5. [Configuration Remove](#configuration-remove)
        6. [Configuration Operation via Manifest](#configuration-operation-via-manifest)
    11. [Power Management](#power-management)
        1. [Power Management via Button Click](#power-management-via-button-click)
        2. [System Reboot](#system-reboot)
        3. [System Shutdown](#system-shutdown)
    12. [Power Management via Manifest](#power-management-via-manifest)
    13. [Decommission Command](#decommission-command)
    14. [Query Command](#query-command)
        1. [Query Command via Manifest](#query-command-via-manifest)
9. [Telemetry Data](#telemetry-data)
    1. [Static Telemetry Data](#static-telemetry-data)
    2. [Dynamic Telemetry Data](#dynamic-telemetry-data)
    3. [Viewing Telemetry Data](#viewing-telemetry-data)
        1. [Static Telemetry:](#static-telemetry)
        2. [Dynamic Telemetry:](#dynamic-telemetry)
10. [Issues and Troubleshooting](#issues-and-troubleshooting)
    1. [Error viewing Devices on Azure Portal](#error-viewing-devices-on-azure-portal)
    2. [OTA Error Status](#ota-error-status)
    3. [Acquiring Debug Messages from Agents](#acquiring-debug-messages-from-agents)

</details>

## Introduction

### Audience

This guide is intended for

-   Independent BIOS Vendors providing Firmware Update packages to
    ensure FW update binary packaging.

-   Independent Software Vendors (ISV) providing OS and Application
    update packages.

-   System Integrators administrating devices running the Intel® In-Band
    Manageability framework.

## Azure&reg; Overview

### Getting Started with Azure&reg;


Creating an Azure&reg; account and obtaining the connection tokens from
Azure&reg; is required for provisioning or enabling Over-the-Air updates.
For reference and quick setup, you will also need to import INB’s IoT
Central Application which will provide the same UI interface described
in this document to monitor the device and perform OTA commands.

This section will walk through the setup steps:

-   Creating Azure&reg; portal account

-   Setting up an Azure&reg; IoT Central Application

-   Accessing Azure&reg; portal account

-   Setting up the application for X509 based device enrollment

#### Creating Azure&reg; portal account

In order to setup an Azure&reg; account, follow the steps below:

-   If not done already, an Azure&reg; account can be created through the
    link below:  
    <https://azure.microsoft.com/en-us/free/>

#### Setting up an Azure&reg; IoT Central Application 

-   To use the reference Intel® In-Band Manageability Framework IoT Central application, use the link mentioned within the following path.

```
/usr/share/cloudadapter-agent/azure_template_link.txt
```

-   Log in with an Azure&reg; Account when prompted.

-   The following form will appear

    <img src="media/In-Band Manageability User Guide - Azure/media/image4.png" style="width:4.84028in;height:4.77014in" />

-   Fill out the form accordingly, then click **Create.**

    <img src="media/In-Band Manageability User Guide - Azure/media/image3.png" style="width:4.82431in;height:1.12778in" />

-   After provisioning, the IoT Central application with premade device templates and dashboards will appear. As noted before, this can be accessed at 
    <https://apps.azureiotcentral.com/> under *My Apps* tab or through the Azure&reg; portal.

#### Accessing Azure&reg;

-   Azure&reg; portal can be accessed at:  
    <https://portal.azure.com/#home>

-   If an Azure&reg; IoT Central has already been set up, it can be
    accessed at:  
    <https://apps.azureiotcentral.com>

-   Otherwise, follow next step to set up an IoT Central application

#### Setting up the application for X509 based device enrollment

The following Dashboard screen appears once the application is created.
The user can enroll for a X509 based enrollment group to enroll the
intermediate or root CA signed certificate, to authenticate the device
further by using the X509 authentication mechanism.

This step is necessary only if the user requires the X509 authentication
on the devices, else this step can be ignored.

-   To create an Enrollment Group, click **Administration** \[**A**\], **Device
Connection** \[**B**\], **Create enrollment group** \[**C**\] as seen in the image below.

<img src="media/In-Band Manageability User Guide - Azure/media/image5.png" style="width:5.99167in;height:2.43194in" />

Upon the display of the form as seen in the above image.
1.  Fill in the Enrollment group name.

2.  Select **Attestation type** as *Certificates (X509)*.

3.  Click**Save**.

<img src="media/In-Band Manageability User Guide - Azure/media/image6.png" style="width:5.99167in;height:5.78403in" />

Once the group is saved, the user needs to upload root or intermediate
certificate as shown in Figure 5:

1.  Click **Manage Primary**.

2.  Select the folder button as show below. This opens a window where
    user chooses the certificate from the currently operated user
    device.

<img src="media/In-Band Manageability User Guide - Azure/media/image7.png" style="width:5.99167in;height:5.52778in" />

3. After uploading the certificate, click **Generate verification code** as seen below.
<img src="media/In-Band Manageability User Guide - Azure/media/image8.png" style="width:6in;height:5.48819in" />

After the verification code is populated in the text box adjacent to the
**Generate verification code** button, the user needs to use this
verification code to generate a verification certificate which will
later be uploaded after clicking the **Verify** button in the form shown
in Figure 6.

<img src="media/In-Band Manageability User Guide - Azure/media/image9.png" style="width:5.99167in;height:5.53611in" />

Once the verification is done by the portal, the following screen displays
stating verification is successful. Next, click **Close** button to
close the form.

### Creating a Device and Obtaining Device Credentials


To connect a device to the Azure&reg; portal, a device needs to be created
first on the portal with the template that the user wishes to associate
the device with. The device created will have a name and an
auto-generated device-id, device-scope-id, and a shared access primary
key, which will be later used on the user’s device, while provisioning
the device to Azure&reg; cloud.

-   When accessing the dashboard for the IoT Central application, the following
    screen will appear. In **Devices** tab **A**, select Template (**Intel
    Manageability**) **B** and click **New** **C**. 

    <img src="media/In-Band Manageability User Guide - Azure/media/image10.png" style="width:6in;height:1.60972in" />

-   A new device registration form appears as shown in Figure 9. Fill in the
    **DeviceID** and **Device Name** information and click **Create**.

    <img src="media/In-Band Manageability User Guide - Azure/media/image11.png" style="width:3.56181in;height:3.05347in" />

-   The newly created device will appear on the Dashboard with the specified Device Name. Click the device created, the status will be shown as *Registerer*. Then, click **Connect** as seen below.

    <img src="media/In-Band Manageability User Guide - Azure/media/image12.png" style="width:5.99167in;height:0.68819in" />

-   As INBM supports both SAS and X509 authentication types, the user must choose one of the Authentication types supported. If the user intends to select SAS based authentication, refer to [Shared Access Signature (SAS) authentication](#shared-access-signature-sas-authentication). Else, if the user wants X509 based Authentication, refer to [X509 Authentication](#x509_authentication).<span id="_2.3.1_Shared_Access" class="anchor"></span>

#### Shared Access Signature (SAS) authentication:

-   By clicking the ‘Connect’ button shown in Figure 5, in the dialog that appears, **<span class="underline">note</span>** the **Scope ID \[A\]**, **Device ID \[B\]**, and **Shared Access Key(SAS) \[C\]**, as these information will be used to provision the device as depicted:

    <img src="media/In-Band Manageability User Guide - Azure/media/image13.png" style="width:4.37008in;height:4.66561in" />

#### X509 authentication:

>**Note:** To authenticate a device using X509 mechanism, a X509 based
> enrollment group needs to be created with CA signed root or
> intermediate certificates. The verification of the private key
> possession needs to be done as shown in [Setting up the application for X509 based device enrollment](#setting-up-the-application-for-x509-based-device-enrollment).

-   The user needs to generate a primary and secondary device certificates using the root or intermediate certificate used to enroll in [Setting up the application for X509 based device enrollment](#setting-up-the-application-for-x509-based-device-enrollment).

-   Once the device certs are generated, visit the Azure&reg; portal, select the device created earlier. Then click the **Connect** button. In the dialog that appears,     note the **Scope ID and Device ID \[A\]** as the information will be used to provision the device. Next, select Authentication type as **Individual Enrollment \[B\]**,     Authentication Method as **Certificates (X509) \[A\]**, and use the folder icons **\[D\]**, to upload the device primary and secondary certificates.

    <img src="media/In-Band Manageability User Guide - Azure/media/image14.png" style="width:4.42639in;height:4.82153in" />

## Provisioning a Device

Provisioning is a Device Management phase during which the Edge IoT
Device is configured with credentials to ensure that it can establish a
secure session with the Device Management backend. This usually involves
assigning Device ID’s and Secure tokens/keys which the Device may use to
identify and authenticate itself to the remote Device Management Portal.

### NOTE ON PREREQUISITE AND ASSUMPTIONS:

1.  The Intel® In-Band Manageability Framework is installed on the Edge
    IoT device.

2.  The date and time on the edge device needs to be set correct

3.  Device credentials (for example, Device ID, Scope ID, SAS token)
    that have been obtained from the Azure&reg; portal.

-   Launch the provisioning script using the command.

```shell
sudo provision-tc
```
    
-   If the device was previously provisioned, the following message appears. To override the previous cloud configuration, press **Y**.

```
A cloud configuration already exists: "Telit"
Replace configuration?
[Y/N] Y
```

-   Press **2** and **\[ENTER\]** for Azure&reg; to choose a cloud service.

```
Please choose a cloud service to use:

1) Telit Device Cloud 3) ThingsBoard
2) Azure IoT Central  4) Custom
#? 2
```

-   Next, enter the information for **Scope ID**, **Device ID**, and the
    **Shared Access Key**. Use the information collected in [Creating a Device and Obtaining Device Credentials](#creating-a-device-and-obtaining-device-credentials))**:**

```
Please enter the device scope ID:
dEviCeScopeID1234

Please enter the Device ID:
Device-ID-1234
```


-   Then, the user is required to select the authentication mechanism.

```
Please choose provision type.
1: SAS key authentication
2: X509 authentication
```

-   When the user selects 1: SAS key authentication, a prompt to enter SAS key is seen, the SAS key information can be obtained by
    following the steps in [Shared Access Signature (SAS) authentication](https://github.com/intel/intel-inb-manageability/blob/Broken_link_522523/docs/In-Band%20Manageability%20User%20Guide%20-%20Azure.md#shared-access-signature-sas-authentication):

```
Please enter the device SAS primary key (Hint: https://docs.microsoft.com/en-us/azure/iot-central/howto-generate-connection-string)
```

-   If the user selects 2: X509 authentication, the following prompt appears to confirm that the user has the device certificates generated.

```
Configuring device to use X509 auth requires device certificate verification.

Are device certs and keys generated? [Y/N]
```

-   If the user selects ‘**N**’, the provisioning exists stating that
    the device certificates are required to proceed further.

-   If the device certificates are already generated, select ‘**Y**’ and
    the user is requested to upload the certificates.

```
Please enter a filename to import
Input path to Device certificate file (*)
```

-   The user would be required to enter the path to the device key file:

```
Input Device Key from file? [Y/N] y

Please enter a filename to import
Input path to Device Key file (*key.pem):
/home/certs/device_key.pem
```


-   Once the information is provided by the user and if the cloud provisioning is successful, the following message appears.

```
Successfully configured cloud service!
```

-   A Yes/No user prompt appears requesting for a certificate verification on an OTA package. Choose **‘Y’** if FOTA or Config load packages need to be verified using signature, else choose **‘N’**.

```
Signature checks on OTA packages cannot not be validated without provisioning a cert file. Do you wish to use a pre-provisioned cert file for signature checks for OTA packages? [Y/N]
```

-   The script will then start the INB services; when the script
    finishes, the device should be able to interact with its associated
    IoT Central Application. To verify whether the device is provisioned
    to the right device on the Azure&reg; portal, check the status of the
    device created in section [Creating a Device and Obtaining Device Credentials](#creating-a-device-and-obtaining-device-credentials)
-   The device will be shown as ‘Provisioned’ on the top-right corner. Refer
    to [Using the IoT Central Application](#using-the-iot-central-application)

-   To verify the connectivity,

    1. Check to see if telemetry or events appear; refer
    [Using the IoT Central Application](#using-the-iot-central-application)

    2. Alternatively, trigger a command like Reboot; see
    [Using the IoT Central Application](#using-the-iot-central-application)


-   If at any time the cloud service configuration needs to be changed or updated, run the provisioning script again.

### Provisioning Command Parameters

Provisioning can be done with or without TPM security by setting
`PROVISION_TPM`. `PROVISION_TPM` can be set to:

-   `auto`: use TPM if present; disable if not present; do not prompt.

-   `disable`: do not use TPM.

-   `enable`: use TPM; return error code if TPM not detected.

-   (unset): default behavior; use TPM if present, prompt if not.

To run provisioning that automatically detecting the present of the TPM
security:

```shell
sudo PROVISION_TPM=auto provision-tc
```

To run without the TPM security:
```shell
sudo PROVISION_TPM=disable provision-tc
```

## Using the IoT Central Application

### Viewing and Managing Devices

-   To view and manage devices, go to the **Devices** tab on the side panel Ⓐ
    <img src="media/In-Band Manageability User Guide - Azure/media/image26.png" style="width:4.8375in;height:2.39375in" />
-   Alternatively, to quickly view a device, use the **Devices** panel Ⓑ

If the device list is showing an error: Refer to [Error viewing Devices on Azure Portal](#error-viewing-devices-on-azure-portal).

### Navigating the Device Interface

First, view a device using instructions from [Viewing and Managing Devices](#viewing-and-managing-devices).

-   If the device is successfully provisioned, the status of the device
    will be shown as Provisioned in the top-right corner.
    <img src="media/In-Band Manageability User Guide - Azure/media/image27.png" style="width:5.5in;height:1.23056in" />

-   Upon viewing a device, the **Measurement** tab Ⓐ is displayed, where
    the device’s telemetry and events can be seen

-   To see the device’s Attributes, click the **Properties** tab Ⓑ

-   To trigger methods from the cloud, click the **Commands** tab Ⓒ.

-   Refer to [OTA Commands](#ota-commands) for additional instructions on how to trigger methods.

    <img src="media/In-Band Manageability User Guide - Azure/media/image28.png" style="width:5.325in;height:2.48542in" />

-   To see an overview of the device, including the Properties and the Event log, click the **Dashboard** tab Ⓓ


## Performing batch operations


1.  To perform a batch OTA operation, i.e. send the same OTA command to
    multiple IoT Devices at the same time, click the **Jobs** tab Ⓐ,
    then click **New** Ⓑ:

    <img src="media/In-Band Manageability User Guide - Azure/media/image29.png" style="width:5.30694in;height:2.70833in" />

2.  Type out a meaningful name Ⓐ, then select an Intel Manageability device
    set to use Ⓑ, the “Commands” **Job type** Ⓒ, and the devices to
    perform the batch operation Ⓓ.

    <img src="media/In-Band Manageability User Guide - Azure/media/image30.png" style="width:5.33958in;height:2.98056in" />

3.  The **Commands** header should now appear in the **Create Job** panel;
    click the adjacent plus-sign button, then select an operation to
    perform:

    <img src="media/In-Band Manageability User Guide - Azure/media/image31.png" style="width:3.15625in;height:5.21736in" />

4.  Fill out any necessary fields that appear after selecting the command; refer [OTA Commands](#ota-commands) for more info.

5.  Finally, click the **Run** button at the top of the panel to run the bulk
    operation.
    
    <img src="media/In-Band Manageability User Guide - Azure/media/image32.png" style="width:3.94792in;height:6.98958in" />

6.  To run the same batch command again, click **Jobs** tab on the left
    side panel. Then check box next to the batch command Ⓐ, then click
    **Copy** Ⓑ and follow step 5:

    <img src="media/In-Band Manageability User Guide - Azure/media/image33.png" style="width:5.37569in;height:1.40556in" />

## OTA Updates

After the Intel® In-Band Manageability Framework running on the Edge IoT
Device is provisioned, it will establish a secure session with the
Azure&reg; portal and the status of the device can is visible as
‘Provisioned’ – refer to [Navigating the Device Interface](#navigating-the-device-interface).

Users shall be able to perform the updates listed below on the device
that is provisioned:

- AOTA (Application Over the Air update)
- FOTA (Firmware-over-the-Air update)
- SOTA (Software/OS-over-the-Air update)
- POTA (Platform-over-the Air update)
- Config Update (configuration parameter update)
- Power Management (Remote Shutdown and Restart)

### Trusted Repositories 

As part of a security measure, In-band Manageability requires the Server
URL(location) of the OTA update repository be included in a “trusted
repository list”, which is maintained internally. Hence, it is mandatory
that the OTA URL be included in the “trusted repository list” prior to
initiating an OTA command. This can be achieved via OTA configuration
Append command to add a new Server URL the existing Trusted Repository
list.

**IMPORTANT NOTE:** It is critical for the user to ensure that the OTA
packages are hosted in secure repositories. This is outside the scope of
INBM.

OTA Configuration Update: refer to **[Configuration Append](#configuration-append)** for
adding the Server URL in the trustedRepositories via ‘Trigger Config
Update’.

**NOTE:** If the URL from which the package for an OTA update is being
fetched doesn’t exist in the trustedRepositories list, INB would abort
the update since the fetch URL is not in the trusted list.

### Preparing OTA Update Packages

Before updates can be dispatched to the endpoint, some preparation needs
to be done at the repository server to facilitate the updates.

#### Creating FOTA Package

The FOTA package structure remains the same when signature is used. For
a more secure FOTA update, users can provision a device with a PEM file
containing the signing certificate to validate the downloaded file
against a signature provided as part of the OTA command, refer [How to Generate Signature](#how-to-generate-signature) to generate signature. Users may create a PEM file
using the OpenSSL and Cryptography libraries.

**With Signature:** 
-   FOTA package structure with signature accepts a
    `tar` (archive) file or just a binary file as a FW update package.
    If using a `tar` file, the `tar` file should consist of the firmware
    update binary (e.g., `*.bin`, `*.cap`, and so on) file as a capsule.
    Archiving the `*.bin` file with a `tar` archive tool can be performed
    with the below command:

```shell
tar cvf ifwi_update.tar ifwi_update.bin
```

-   When a device is provisioned with a PEM file to check the signature, the
    expectation is that every FOTA method triggered with a firmware package
    is validated against the signature using the provisioned PEM file.

**Note**
> When using the secure method, do ensure to send the signature generated for the \*.tar file. Refer [How to Generate Signature](#how-to-generate-signature)

**Without Signature:** 
-   FOTA package structure without signature only
    accepts a single firmware update binary (e.g., `*.bin`, `*.cap`, and
    so on) file as a capsule.

#### Creating SOTA Package

SOTA on Ubuntu Operating System does not require any SOTA package.

SOTA on Yocto is handled by INB based on OS implementation:

1.  Debian package manager: in does not require any SOTA package
    creation but instead requires the APT repositories set correctly and
    path included in the apt resources.

2.  Mender.io: These involve OS update images, also known as **mender
    artifacts**, generated by the build infrastructure. More information
    on mender integration can be found at <https://docs.mender.io> .

AOTA Package structure for the below commands should follow the below
format

#### Creating AOTA Package


| AOTA Command                                             | AOTA Package Structure                                                                                                                                                                                                                                                                                                                                                                                                        |
|----------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| AOTA docker-compose package<br>(Same format for up/pull) | Container Tag == Container Image Name<br>Example: The container Image name and the tar file name should be the same<br>*Container Tag =* `CPU`<br>*Tar file =* `CPU.tar.gz`<br>*Note: The tar file should contain a folder with the same name `CPU`. This folder `CPU` needs to have the `docker-compose.yml` file.*<br>Steps:<br>1. Make a folder<br>2. Copy the `docker-compose.yml` file into the folder<br>Tar the folder |
| AOTA Docker&reg; Load/Import                             | Package needs to be `tar.gz` format<br>The package needs to have a folder within the same name as the package.                                                                                                                                                                                                                                                                                                                |

#### Creating Configuration Load Package

The Configuration load package structure remains unchanged when
signature field is used. For a more secure OTA update, users can
provision a device with a PEM file containing the certificate to
validate the downloaded file against a signature provided as part of the
OTA command, refer to [How to Generate Signature](#how-to-generate-signature).
Users may create a PEM file using the OpenSSL and Cryptography libraries.

1. **With Signature**: Configuration Load package structure with
    signature accepts both `tar` file with the
    `intel_manageability.conf` file and just the
    `intel_manageability.conf` file alone. Archiving the
    `intel_manageability.conf` file with a `tar` archive tool can be
    performed with below command:

When a device is provisioned with a PEM file to validate the downloaded
config file or package, it is expected that every Config Load method
triggered with a firmware package will be having a signature that is
validated against the signature using the provisioned PEM file.

1. **Without Signature**: Configuration Load package structure with no
    signature only contains `intel_manageability.conf` file

### How to Generate Signature

To generate certificate, private key and signatures, OpenSSL or
Cryptography libraries can be used.

Once the above are generated, to validate the OTA package for
FOTA/Config Load, we need to have the device provisioned with a
certificate (cert.pem). While triggering OTA command from cloud fill the
signature field in the OTA form before clicking ‘Execute’ to trigger
OTA.

1. While creating a signature INB, use shar-256 or sha-384 based
    encryption mechanism. <span class="underline"> </span>

## OTA Commands

To trigger OTA commands on the device provisioned with Azure*, navigate to the ‘Commands’ tab of the device on the portal as stated in [Navigating the Device Interface](#navigating-the-device-interface).


### Commands - Definitions and Usage

| Command               | Definition                                                                                                                                                                            |
|-----------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Trigger AOTA          | Remotely launch/update docker containers on the Edge IoT Device                                                                                                                       |
| Trigger FOTA          | Update the BIOS firmware on the system                                                                                                                                                |
| Trigger SOTA          | User-friendly, parameter driven updates to OS software packages on the system                                                                                                         |
| Trigger Config Update | Update the In-Band Manageability configurations                                                                                                                                       |
| Reboot                | Remotely reboot the Endpoint                                                                                                                                                          |
| Shutdown              | Remotely shutdown the Endpoint                                                                                                                                                        |
| Manifest Update       | Any OTA update type can be done via the Manifest Update, by entering XML text to update the Endpoint. Refer to the [Developer Guide](In-Band%20Manageability%20Developer%20Guide.md). |

#### AOTA

##### Supported AOTA commands and AOTA form descriptions
[AOTA Updates](AOTA.md)


To trigger Application-over the Air updates:
-   Select Edge Device by clicking on **Dashboard** tab and by clicking
    on the **device name**.

    <img src="media/In-Band Manageability User Guide - Azure/media/image34.png" style="width:6in;height:1.15417in" />

-   Now select the **Commands** tab

    <img src="media/In-Band Manageability User Guide - Azure/media/image35.png" style="width:6in;height:1.47639in" />

-   Scroll the page to the text area named *Trigger AOTA:*

    <img src="media/In-Band Manageability User Guide - Azure/media/image36.png" style="width:3.55069in;height:7.14861in" />

AOTA Field Details

| Field                                                          | Input description                                                                                                                                                                                                                                                                                                               |
|----------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| App and its command                                            | `docker-compose` supports: `up`, `down`, `pull`, `list` and `remove`.<br>`docker` supports: `list', load`, `import`, `pull`, `remove` and `stats`<br>Application: update                                                                                                                                                        |
| Container Tag                                                  | Name tag for image/container.<br>Note: Conatiner Tag can have both the Name and Version in this format Image:Version                                                                                                                                                                                                            |
| Docker&reg; Compose File                                       | Field to specify the name of custom yaml file for docker-compose command. Example: `custom.yml`                                                                                                                                                                                                                                 |
| Fetch                                                          | Server URL to download the AOTA container `tar.gz` file<br>If the server requires username/password to download the file, you can provide in server username/ server password<br>*NOTE*: Follow [Creating AOTA Package](https://github.com/intel/intel-inb-manageability/blob/Broken_link_522523/docs/In-Band%20Manageability%20User%20Guide%20-%20Azure.md#creating-aota-package)                                                                                |
| Server Username/<br>Server Password                            | If server where we host the package to download AOTA file needs credentials, we need to specify the username and password                                                                                                                                                                                                       |
| Docker&reg; Registry<br>Docker&reg; Registry Username/Password | Specify Docker&reg; Registry if accessing any registry other than the default ‘index.docker.io’.<br>Example for docker Registry: `registry.hub.docker.com`<br>Optional fields Docker&reg; Registry Username/Password can be used to when using private images in AOTA through docker pull and docker-compose up, pull commands. |

**NOTE:**: 
Following sections demonstrate what fields to fill for
respective AOTA operations with required and optional fields.

<img src="media/In-Band Manageability User Guide - Azure/media/image37.png" style="width:0.17431in;height:0.17361in" />

For each of the AOTA functions, insert the correct parameters as
described and click **Run.** The result log can be viewed by clicking on
the **Dashboard** tab.

### AOTA Docker-Compose Operations

#### Docker Compose Up

**NOTE:**

>  1. The Container Tag name should be same as the file name in the fetch field. 
>   Example: Container Tag: CPU Downloaded fetch file: `CPU.tar.gz`.
>  2. Docker-Compose yml file should have the correct docker version.

<img src="media/In-Band Manageability User Guide - Azure/media/image39.png" style="width:3.94167in;height:6.74653in" />


#### Docker-Compose Down

<img src="media/In-Band Manageability User Guide - Azure/media/image40.png" style="width:4.47083in;height:7.69792in" />

### Docker-Compose Pull 
**NOTE:**
> The Container Tag name should be same as the file name in the fetch field. 
> Example: Container Tag: CPU Downloaded fetch file: `CPU.tar.gz`

<img src="media/In-Band Manageability User Guide - Azure/media/image41.png" style="width:4.47083in;height:7.58056in" />

#### Docker-Compose List 

<img src="media/In-Band Manageability User Guide - Azure/media/image42.png" style="width:4.82292in;height:8.04167in" />

#### Docker-Compose Remove

<img src="media/In-Band Manageability User Guide - Azure/media/image43.png" style="width:4.68335in;height:8.05208in" />

### AOTA Docker Operations

#### Docker Import

**NOTE:** 
> The Container Tag name should be same as the file name in the fetch field.
> Example: Container Tag: CPU Downloaded fetch file: `CPU.tar.gz`

<img src="media/In-Band Manageability User Guide - Azure/media/image44.png" style="width:4.28679in;height:7.0814in" /><img src="media/In-Band Manageability User Guide - Azure/media/image45.png" style="width:3.27917in;height:0.28333in" />

#### Docker Load

**NOTE:** 
> The Container Tag name should be same as the file name in the fetch field.
>  Example: Container Tag: CPU Downloaded fetch file: `CPU.tar.gz`

<img src="media/In-Band Manageability User Guide - Azure/media/image46.png" style="width:4.41944in;height:7.5in" />

#### Docker Pull

<img src="media/In-Band Manageability User Guide - Azure/media/image47.png" style="width:4.68681in;height:8.09722in" />

#### Docker Remove

<img src="media/In-Band Manageability User Guide - Azure/media/image48.png" style="width:4.54792in;height:7.79097in" />

#### Docker Stats 

<img src="media/In-Band Manageability User Guide - Azure/media/image49.png" style="width:4in;height:6.88542in" />

### AOTA Application Operations

#### Application Update

**NOTE:** The Device Reboot is an optional field.

For any Xlink driver update it is mandatory to reboot the device.

Input “yes” for Device Reboot as seen below.

You can only use signed packages to update Xlink Driver application

<img src="media/In-Band Manageability User Guide - Azure/media/image51.png" alt="Graphical user interface, application Description automatically generated" style="width:5.64166in;height:5.95643in" />

#### AOTA Docker/Docker-Compose Operations via Manifest

Refer to the [Developer Guide](In-Band%20Manageability%20Developer%20Guide.md).

### FOTA Updates

To perform FOTA updates, IBVs must supply the SMBIOS or Device Tree info
that is unique to each platform SKU and fulfill the vendor, version,
release date, manufacturer and product name that matches the endpoint as
shown below.

1.  The following information must match the data sent in the FOTA
    update command for the Intel® In-Band Manageability Framework to
    initiate a Firmware update process.

**FOTA Update Info**

| Information | Field  | Checks  |
|-------------|--------------|-----------------------------------------------|
| FW  | Vendor | Exact string match  |
| | Version  | Unused  |
| | Release Date | Checks if the FOTA date is newer than current |
| System  | Manufacturer | Exact string match  |
| | Product Name | Exact string match  |

To find the FW and System fields at the endpoint, run the commands
below:

**Intel x86 UEFI-based Products**

For UEFI-based platforms, the firmware and system information can be
found by running the following command.

```shell
sudo dmidecode -t bios -t system
```

####  FOTA Update via Button Click

In order to trigger Firmware-Over the Air updates:

-   Select Edge Device by clicking on **Dashboard** tab and by clicking on the
    **device name**.

    <img src="media/In-Band Manageability User Guide - Azure/media/image34.png" style="width:6in;height:1.15417in" />

-   Now select the ‘Commands’ tab

    <img src="media/In-Band Manageability User Guide - Azure/media/image35.png" style="width:6in;height:1.47639in" />

-   Scroll the page to the text area named **Trigger FOTA**

    <img src="media/In-Band Manageability User Guide - Azure/media/image52.png" style="width:3.62986in;height:7.3in" />

-   Populate the text fields within the ‘Trigger FOTA’ block with the parameters in the table below.
 **NOTE:**
 > If triggering a secure FOTA update with a `*.pem` file within the `tar`, a signature needs to be given in the respective field. The signature can be generated using OpenSSL, or Cryptography libraries along with the key.pem file.


Parameter Details

|Parameter|Description|
|--- |--- |
|BIOSVersion|Verify with BIOS Vendor (IBV)|
|Fetch|Repository URL
||NOTE: Follow Creating FOTA Package|
|Manufacturer|Endpoint Manufacturer Name|
|Path|FOTA path created in repository|
|Product|Product name set by Manufacturer|
|Release Date|Specify the release date of the BIOS file you are applying. Verify with BIOS Vendor (IBV)
||IMPORTANT NOTE: Date format: yyyy-mm-dd|
|Signature|Digital signature|
|ToolOptions|Any Tool options to be given for the Firmware Tool|
|Server Username/Password|If server where we host the package to download FOTA file needs credentials, we need to specify the username and password|


 **NOTE:** Following sections demonstrate what fields to fill for respective FOTA operations with required and optional fields.

<img src="media/In-Band Manageability User Guide - Azure/media/image37.png" style="width:0.17431in;height:0.17361in" />

<img src="media/In-Band Manageability User Guide - Azure/media/image53.png" style="width:4.3125in;height:7.35764in" />

-   After filling the correct parameters as described in the table, click **Run** to commission the FOTA update.
-   The result log can be viewed by clicking on the **Dashboard** tab.

#### FOTA Update via Manifest

Refer to the [Developer Guide](In-Band%20Manageability%20Developer%20Guide.md).

### SOTA Updates

SOTA commands vary based on OS type and update mechanisms supported by
it. Ubuntu OS or Yocto based OS which include Debian package manager do
not require any package preparation, while a Yocto based OS with
Mender.io based solution does. This changes the interface slightly as
explained below.

#### SOTA Update Via ‘Trigger SOTA’ Button Click (Debian Package Manager, Ubuntu OS)

In order to trigger Software-Over the Air updates:

-   Select Edge Device by clicking on **Dashboard** tab and by clicking on the
    **device name**.

    <img src="media/In-Band Manageability User Guide - Azure/media/image34.png" style="width:6in;height:1.15417in" />

-   Now select the ‘Commands’ tab.

    <img src="media/In-Band Manageability User Guide - Azure/media/image35.png" style="width:6in;height:1.47639in" />

-   Scroll the page to the text area named **‘Trigger SOTA’**:

    <img src="media/In-Band Manageability User Guide - Azure/media/image54.png" style="width:3.23135in;height:3.86793in" /> 

-   Populate the SOTA text fields on screen with the parameters below:

<span id="_Toc76140159" class="anchor"></span>SOTA Parameters

|Command|Specifies the SOTA ‘update’ command.|
|--- |--- |
|Log to File|Specifies if the logs be written to a file or to the cloud. Values “Y” or “N”
||SOTA log files can be located at the endpoint /var/cache/manageability/repository-tool/sota/|

**NOTE:** Following sections demonstrate what fields to fill for respective FOTA operations with required and optional fields.

<img src="media/In-Band Manageability User Guide - Azure/media/image37.png" style="width:0.17431in;height:0.17361in" />

<img src="media/In-Band Manageability User Guide - Azure/media/image55.png" style="width:5.40556in;height:4.95486in" />

-   Click **Run** to commission SOTA update.

#### SOTA Update Via ‘Trigger SOTA’ Button Click (Mender)

In order to trigger Software-Over the Air updates:

-   Select Edge Device by clicking on **Dashboard** tab and by clicking on the
    **device name**.

    <img src="media/In-Band Manageability User Guide - Azure/media/image34.png" style="width:6in;height:1.15417in" />

-   Now select the ‘**Commands’** tab.

    <img src="media/In-Band Manageability User Guide - Azure/media/image35.png" style="width:6in;height:1.47639in" />

-   Scroll the page to the text area named **‘Trigger SOTA’**:

    <img src="media/In-Band Manageability User Guide - Azure/media/image54.png" style="width:3.23135in;height:3.86793in" /> 

Populate the SOTA text fields on screen with the parameters below:

Parameter Details

| Command                                                                                        | Specifies the SOTA ‘update’ command.                                          |
|:-----------------------------------------------------------------------------------------------|:------------------------------------------------------------------------------|
| Fetch                                                                                          | URL patch to download the Mender artifact from                                |
| Log to File                                                                                    | Specifies if the logs be written to a file or to the cloud. Values “Y” or “N” |
|| SOTA log files can be located at the endpoint `/var/cache/manageability/repository-tool/sota/` |     |
| Username                                                                                       | Mender artifact repository Username                                           |
| Password                                                                                       | Mender artifact repository Password                                           |
| Release Date                                                                                   | Release date of the new mender file used in fetch field                       |

 **NOTE:** Following sections demonstrate what fields to fill for respective FOTA operations with required and optional fields.

<img src="media/In-Band Manageability User Guide - Azure/media/image37.png" style="width:0.17431in;height:0.17361in" />

<img src="media/In-Band Manageability User Guide - Azure/media/image56.png" style="width:4.02351in;height:3.9802in" />

-   Click **Run** to commission SOTA update.
#### SOTA Update via Manifest

[SOTA Manifest Parameters and Examples](Manifest%20Parameters.md#SOTA)

### Configuration Update 


Configuration update is used to change/retrieve/append/remove
configuration parameters value from the Configuration file located at
`/etc/intel_manageability.conf`. Refer to table to understand
the configuration tags, it’s values and the description.

[Configuration Parameters](Configuration%20Parameters.md)

**Below are the configuration update commands and input field description**

| Trigger Configs | Description of field                                                 |
|:----------------|:---------------------------------------------------------------------|
| Set             | Command used to update the configuration value using key:value pair. |
| Get             | Retrieve a specific configuration value using key:value pair         |
| Load            | Replace an entire configuration file.                                |
| Append          | Append values to a configuration parameter.                          |
| Remove          | Remove a specific values from the configuration parameter.           |
| Fetch           | URL to fetch config file from in the case of a load                  |
| Path            | Path of element to get, set, append or remove in key:value format    |
| Signature       | Digital signature                                                    |


In order to trigger Configuration updates:

-   Select Edge Device by clicking on **Dashboard** tab and by clicking on the
    **device name**.

    <img src="media/In-Band Manageability User Guide - Azure/media/image34.png" style="width:6in;height:1.15417in" />

-   Now select the ‘**Commands’** tab.

    <img src="media/In-Band Manageability User Guide - Azure/media/image35.png" style="width:6in;height:1.47639in" />

-   Scroll the page to the text area named **‘Trigger Configuration Update’**:

    <img src="media/In-Band Manageability User Guide - Azure/media/image57.png" style="width:3.58125in;height:4.26528in" />


-   Populate the Config Update pop-up window with required parameters.

**Note:**
> If triggering a secure config update load with a `*.pem` file
> a signature needs to be given in the respective
> field. The signature can be generated using OpenSSL, or Cryptography
> libraries along with the `key.pem` file.
-   Click **Run** to trigger the Config update.

-   The result log can be viewed by clicking on the **Dashboard** tab.

**NOTE:** Following sections demonstrate what fields to fill for respective Config operations with required and optional fields.

<img src="media/In-Band Manageability User Guide - Azure/media/image37.png" style="width:0.17431in;height:0.17361in" />

#### Configuration Set

> **Examples:**
To set one value: `minStorageMB:10`

To set multiple values at once: `minStorageMB:10;minMemoryMB:250`

**NOTE:**
> Path takes in key value pairs as an input with key as the
> configuration parameter tag and value to be set as the value. Also, to
> set multiple key:value pairs, use; to separate one pair from another
> as shown above in the example.

<img src="media/In-Band Manageability User Guide - Azure/media/image58.png" style="width:4.85356in;height:4.92647in" />

#### Configuration Get

> **Examples:**
To get one value: `minStorageMB`

To get multiple values at once: `minStorageMB;minMemoryMB`

**NOTE:** 
> Path takes in keys as an input with key as the configuration
> parameter tag whose value needs to be retrieved. Also, to retrieve
> multiple values at once use `;` to separate one tag from another as
> shown above in the example.

<img src="media/In-Band Manageability User Guide - Azure/media/image59.png" style="width:4.79861in;height:4.93333in" />

#### Configuration Load

**NOTE:** 
> The configuration file you provide in Fetch needs to be
> named as `intel_manageability.conf` file. If you wish to send with
> signature, tar both the pem file and the `intel_manageability.conf` in
> a tar file.

<img src="media/In-Band Manageability User Guide - Azure/media/image60.png" style="width:4.72639in;height:4.77292in" />

#### Configuration Append

**NOTE:**
> Append is only applicable to three configuration tags i.e
> `trustedRepositories`, `sotaSW` and `ubuntuAptSource`
>
> Path takes in key value pair format, example:
> `trustedRepositories:https://abc.com/`

<img src="media/In-Band Manageability User Guide - Azure/media/image61.png" style="width:4.75034in;height:4.85849in" />

#### Configuration Remove

**NOTE:** 
> Remove is only applicable to three configuration tags i.e
> `trustedRepositories`, `sotaSW` and `ubuntuAptSource`

-   Path takes in key value pair format, example: `trustedRepositories:https://abc.com/`

    <img src="media/In-Band Manageability User Guide - Azure/media/image62.png" style="width:4.41617in;height:4.5572in" />

#### Configuration Operation via Manifest

Refer to the [Developer Guide](In-Band%20Manageability%20Developer%20Guide.md).

### Power Management


The Shutdown and Restart capabilities are supported via button click or
through manifest.

#### Power Management via Button Click

In order to trigger Reboot/Shutdown:

-   Select Edge Device by clicking on **Dashboard** tab and by clicking on the
    **device name**.

    <img src="media/In-Band Manageability User Guide - Azure/media/image34.png" style="width:6in;height:1.15417in" />

-   Now select the ‘**Commands’** tab.

    <img src="media/In-Band Manageability User Guide - Azure/media/image35.png" style="width:6in;height:1.47639in" />

#### System Reboot

-   To reboot the device, click the **Run** button on the box titled
    *Reboot***.**

    <img src="media/In-Band Manageability User Guide - Azure/media/image63.png" style="width:3.61458in;height:2.34792in" />


#### System Shutdown

-   To shut down the device, click the **Run** button on the box titled
    *Shutdown.*

    <img src="media/In-Band Manageability User Guide - Azure/media/image64.png" style="width:3.67222in;height:1.73681in" />

### Power Management via Manifest

Refer to the [Developer Guide](In-Band%20Manageability%20Developer%20Guide.md).

### Decommission Command

The Intel® In-Band Manageability provides a mechanism to handle the
decommission request over the air.

**NOTE:** 
> Upon receiving a decommission command:
> -   The Intel® In-Band Manageability credentials (all user/device data which allows the device to identify and connect to cloud) will be deleted from the device.
> -   The device shutdowns.
In order to trigger Decommission:
-   Select Edge Device by clicking on **Dashboard** tab and by clicking on the
    **device** **name**.

    <img src="media/In-Band Manageability User Guide - Azure/media/image34.png" style="width:6in;height:1.15417in" />

-   Now select the **Commands** tab.

    <img src="media/In-Band Manageability User Guide - Azure/media/image35.png" style="width:6in;height:1.47639in" />

-   Select **Run** in the  *Decommission* section.

    <img src="media/In-Band Manageability User Guide - Azure/media/image65.png" style="width:3.02153in;height:1.91736in" />

### Query Command
The Intel® In-Band Manageability provides a way to query attribute information on either the Host, Edge Device, or Nodes.

-   To query attributes, provide the desire option type in the text box.  Then click the **Trigger Query** button.

    <img src="media/In-Band Manageability User Guide - Azure/media/image87.png" style="width:6in;height:1.47639in"/>

For the details on **Query options**
Refer to [Query options ](https://github.com/intel/intel-inb-manageability/blob/develop/docs/Query.md) 

The query command capabilities are supported via manifest.

#### Query Command via Manifest
Refer to [Query Manifest and Examples](Manifest%20Parameters.md#Query)

## Telemetry Data

The Intel® In-Band Manageability provides two types of telemetry data,
static telemetry and dynamic telemetry. The telemetry data will indicate
the health of each endpoint.
### Static Telemetry Data

This contains the following information and can be viewed under the
**Properties** tab for a selected *Device*.
- BIOS-release-date
- BIOS-vendor
- BIOS-version
- CPU-ID
- OS-information
- System-Manufacturer
- System-Product-Name
- Total-physical-memory
- System-Product-Name

### Dynamic Telemetry Data
Each endpoint publishes the following Dynamic Telemetry Data in 5-minute
intervals.
-   Available-memory
-   Core-temp-Celsius
-   Percent-disk-used
-   System-cpu-percent
-   Container-stats(cpu-usage)
-   Network Information

### Viewing Telemetry Data
The device must be connected in order to view the telemetry information
on the Azure\* portal.
To view the telemetry data, navigate to the device item that is
provisioned. 

#### Static Telemetry:
To view the device’s static telemetry, click the **Properties** tab of
the device item.

<img src="media/In-Band Manageability User Guide - Azure/media/image66.png" style="width:5.68958in;height:4.35in" />

#### Dynamic Telemetry:
To view the device’s static telemetry, click the **Measurements** tab of
the device item.

<img src="media/In-Band Manageability User Guide - Azure/media/image67.png" style="width:6in;height:5.69444in" />

## Issues and Troubleshooting

[General Troubleshooting](Issues%20and%20Troubleshooting.md)

### Error viewing Devices on Azure Portal:

While following the steps in [Viewing and Managing Devices](#viewing-and-managing-devices), if there is an error viewing device, do the following:

-   Click **Edit** in the upper right-hand corner:

<img src="media/In-Band Manageability User Guide - Azure/media/image68.png" style="width:6in;height:1.14167in" />

-   Hover the cursor over the *Devices* panel,

    <img src="media/In-Band Manageability User Guide - Azure/media/image69.png" style="width:6in;height:3in" />

    click the icon as shown below:

    <img src="media/In-Band Manageability User Guide - Azure/media/image70.png" style="width:0.16806in;height:0.15972in" />

-   On the left-hand panel, click **Device** **Set** and select the option <span class="underline">without</span> “Copied” appended to
    it, then click **Save**:

    <img src="media/In-Band Manageability User Guide - Azure/media/image71.png" style="width:5.84097in;height:3.25347in" />

-   Finally, click **Done** in the upper right-hand- corner:
    
    <img src="media/In-Band Manageability User Guide - Azure/media/image72.png" style="width:5.88819in;height:1.01458in" />

### OTA Error Status

[Error Messages](Error%20Messages.md)

### Acquiring Debug Messages from Agents

Refer to the [Developer Guide](In-Band%20Manageability%20Developer%20Guide.md#enable-debug-logging).
