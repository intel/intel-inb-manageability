# User Guide – ThingsBoard&reg;

<details>
<summary>Table of Contents</summary>

1. [Introduction](#introduction)
    1. [Purpose](#purpose)
    2. [Audience](#audience)
2. [ThingsBoard&reg; Overview](https://github.com/intel/intel-inb-manageability/blob/Broken_link_522523/docs/In-Band%20Manageability%20User%20Guide%20-%20ThingsBoard.md#thingsboard-overview)
    1. [Getting Started with ThingsBoard&reg;](https://github.com/intel/intel-inb-manageability/blob/Broken_link_522523/docs/In-Band%20Manageability%20User%20Guide%20-%20ThingsBoard.md#getting-started-with-thingsboard)
    2. [Adding a Device](#adding-a-device)
    3. [Obtaining Device Credentials](#obtaining-device-credentials)
    4. [Creating a Device to Use X.509 Auth](#creating-a-device-to-use-x509-auth)
    5. [Provisioning a Device](#provisioning-a-device)
    6. [Setting up the Dashboards](#setting-up-the-dashboards)
    7. [Getting Familiar with ThingsBoard&reg;](https://github.com/intel/intel-inb-manageability/blob/Broken_link_522523/docs/In-Band%20Manageability%20User%20Guide%20-%20ThingsBoard.md#getting-familiar-with-thingsboard)
    8. [Interacting with Individual Devices](#interacting-with-individual-devices)
    9. [Interacting with Multiple Devices](#interacting-with-multiple-devices)
    10. [Modifying and Working with Intel Manageability Widgets](#modifying-and-working-with-intel-manageability-widgets)
3. [Commands](#commands)
    1. [Trusted Repositories](#trusted-repositories)
    2. [Preparing OTA Update Packages](#preparing-ota-update-packages)
    3. [OTA Updates](#ota-updates)
    3. [Configuration Update](#configuration-update)
    4. [Power Management](#power-management)
    5. [Decommission Command](#decommission-command)
    6. [Query Command](#query-command)
4. [Telemetry Data](#telemetry-data)
    1. [Static Telemetry Data](#static-telemetry-data)
    2. [Dynamic Telemetry Data](#dynamic-telemetry-data)
    3. [Viewing Telemetry Data](#viewing-telemetry-data)
5. [Issues and Troubleshooting](#issues-and-troubleshooting)
    1. [OTA Error Status](#ota-error-status)
    3. [Acquiring Debug Messages from Agents](#acquiring-debug-messages-from-agents)

</details>

## Introduction
### Purpose

This User Guide serves to provide the reader an overview on how to:

- Login and setup ThingsBoard&reg; Cloud Service
- Provision the Edge IoT device running In-Band Manageability Framework
- Perform OTA updates through ThingsBoard.

It also provides examples of the Web-UI configuration, reported
Telemetry from device and commands for performing OTA updates.

### Audience

This guide is intended for

- Independent BIOS Vendors providing Firmware Update packages to
    ensure FW update binary packaging.

- Independent Software Vendors (ISV) providing OS and Application
    update packages.

- System Integrators administrating devices running In-Band
    Manageability framework.

## ThingsBoard&reg; Overview

### Getting Started with ThingsBoard&reg;

Creating a ThingsBoard&reg; account and obtaining the connection tokens from
ThingsBoard&reg; is required for provisioning/enabling In-Band Manageability
Over-the-Air updates. For reference and quick setup, you will also need
to import INB`s ThingsBoard&reg; things definition. which will provide the
same UI interface described in this document to monitor the device and
perform OTA commands.

This section will walk through the setup steps:

- Accessing ThingsBoard&reg;
- Setting up ThingsBoard&reg; TLS
- Changing ThingsBoard&reg; Server Port
- Creating ThingsBoard&reg; Account

#### Accessing ThingsBoard&reg;

To set up a ThingsBoard&reg; installation, follow the steps below:

- If not done already, create a ThingsBoard&reg; installation through the
    following link:  
    [**https://thingsboard.io/docs/installation/**](https://thingsboard.io/docs/installation/)

    ❗ In a sandbox environment, choose the `Community` edition

- In order to run a ThingsBoard&reg; server instance on the same device as
    Intel Manageability, see [**Changing ThingsBoard&reg; Server Port**](#changing-thingsboard-server-port)

#### Setting up ThingsBoard TLS

To allow for a secure TLS connection to be established between a device
with Intel Manageability and a self-hosted ThingsBoard&reg; server, some
configuration must be done to the server. Information on that process
can be found below, or at:
[**https://thingsboard.io/docs/user-guide/mqtt-over-ssl/**](https://thingsboard.io/docs/user-guide/mqtt-over-ssl/)

1. Download the *server.keygen.sh* and *keygen.properties* files from the link above

2. Fill out the *keygen.properties* accordingly:
    1. Change is the **DOMAIN\_SUFFIX** field, which should match the
        hostname of the ThingsBoard&reg; server

    2. Export both MQTT\_BIND\_PORT and MQTT\_SSL\_BIND\_PORT in the
        thingsboard.conf file

    3. Any other changes (e.g. the **SERVER\_\*\_PASSWORD** fields)
        should be noted

3. Run the *server.keygen.sh* file with root privileges

4. Copy the resulting *\*.jks* file to the ThingsBoard&reg; configuration
    directory

    - This may be under: ```/etc/thingsboard/conf/```

5. The *\*.pub.pem* file will be needed later to provision Intel
    Manageability devices

#### Changing ThingsBoard&reg; Server Port

Because both ThingsBoard&reg; and the Intel Manageability framework use MQTT
protocol, it is necessary to change the ThingsBoard&reg; MQTT Broker port to
a different number for both to coexist on the same device.

To do this:

1. Locate and open the *thingsboard.yml* file
    - On Yocto, this file is located in ```/etc/thingsboard/conf/```

2. Change the property **transport \> mqtt \> bind\_port** to any other
    number (e.g. 2883)

    1. This property should be under a section labeled: `Local MQTT transport parameters`

    2. Be sure to note the new port number, and enter it accordingly in
        the provisioning step

3. If the ThingsBoard&reg; service is currently running, restart it to apply
    the changes

For the Docker&reg; version of Thingsboard, change the binding for port 1883,
e.g. with 2883:

#### Creating a ThingsBoard&reg; Account

If not done already, a ThingsBoard&reg; account will need to be created by a
ThingsBoard&reg; System Administrator. Note that in order to provision
devices and set up the dashboard, an account with the privileges of a
`Tenant Administrator` is required:

1. Log into a system administrator account; the default system
    administrator account details can be found here:
    [**https://thingsboard.io/docs/samples/demo-account/\#system-administrator**](https://thingsboard.io/docs/samples/demo-account/#system-administrator)

2. Add a tenant by clicking on `Tenants`, then the plus button:  
    <img src="media/In-Band Manageability User Guide - ThingsBoard/media/image4.png" style="width:5.78125in;height:3.59762in" />

3. Fill out the form that appears accordingly, then click `Add`

4. The tenant should appear as a new entry; click the *Users* icon:  
    <img src="media/In-Band Manageability User Guide - ThingsBoard/media/image5.png" style="width:5.78125in;height:2.92708in" />

5. On the page that appears, click the big plus icon, and fill out the
    form accordingly

6. After clicking add, the new user should be presented with an
    activation link

7. Clicking on the activation link will lead to a page where the
    account password is set

8. The new user should now be able to sign in with the account`s
    associated email and password

### Adding a Device

1. Add a device by clicking on `Devices`, then the plus button:  
    <img src="media/In-Band Manageability User Guide - ThingsBoard/media/image6.png" style="width:5.48333in;height:2.94028in" />

2. The following window should appear; fill it out accordingly, then
    click `Add`.

<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image7.png" style="width:5.73333in;height:4.09653in" />

### Obtaining Device Credentials

1. Click the shield icon on the newly created menu entry:

<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image8.png" style="width:5.75in;height:3.04167in" />

1. Note the **Access Token** in the window that appears:  
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image9.png" alt="P261L16#yIS1" style="width:2.61706in;height:2.35281in" />

### Creating a Device to Use X.509 Auth

#### Generating Device Keys and Certificates

Prior to having the device authentication done using X509 mechanism, it
is mandatory to have TLS set on the ThingsBoard&reg; server. Refer section
[**Setting up ThingsBoard&reg; TLS**](#setting-up-thingsboard-tls) on how to setup ThingsBoard&reg; TLS.

Once the TLS is set up on the server, the instructions on how to
generate a client-side certificate can be found in the following link:

<https://thingsboard.io/docs/user-guide/certificates/>

- Enter and save the *keygen.properties* accordingly and download the
    *client.keygen.sh* script.

- Running the script will generate *.jks*, *.nopass.pem*, *.pub.pem*
    files.

- The *.nopass.pem* file is used during provisioning in [Provisioning a Device](#provisioning-a-device).

- The *.pub.pem* file content is used during the creation of a device
    on the ThingsBoard&reg; portal.

#### Enrolling Device Created with X509 Public Key

1. Once the device is added as shown in [**Adding a Device**](#adding-a-device), click the **shield** icon on the created device entry.

<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image10.png" style="width:5.78333in;height:3.025in" />

2. Select X.509 Certificate as the **Credentials type**.

<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image11.png" style="width:2.4375in;height:4.32292in" />

3. Copy and paste the content of the client public key generated in the
**RSA public key** field and click **Save**. 

### Provisioning a Device

**NOTE:**
> Prerequisite and assumptions: The Intel® In-Band Manageability Framework is installed on the Edge IoT device.

1. Launch the provisioning script using the command.
```shell
sudo provision-tc
```

2. If the device was previously provisioned, the following message
    appears. To override the previous cloud configuration, press **Y**:

```
A cloud configuration already exists: "Telit"
Replace configuration?
[Y/N] Y
```

3. A prompt appears to choose the cloud service; press **3** and
    **\[ENTER\]** for ThingsBoard:

```
Please choose a cloud service to use:
1) Telit Device Cloud 3) ThingsBoard
2) Azure IoT Central  4) Custom
#? 3
```

4. A prompt appears for the **IP address** and **Port** set up in
    section [Accessing ThingsBoard&reg;](#accessing-thingsboard)  
    
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
    the token. Refer [Obtaining Device Credentials](#obtaining-device-credentials)

7. Choosing option **2. X509 Authentication** requires user to have
    device certificate and key generated as mention in [Generating Device Keys and Certificates](#generating-device-keys-and-certificates).
    The file path of the file with extension *nopass.pem* is entered in
    the prompt.
```
Configuring device to use X509 auth requires device certificate verification.

Are device certs and keys generated?  [Y/N] Y

Input Device certificate from file? [Y/N] y

Please enter a filename to import 

Input path to Device certificate file (*nopass.pem):
/home/abc/device_cert_nopass.pem
```

8. If user selects Token based authentication in step 6, an option for
    TLS will appear; press **Y** if the server was configured in
    [**Setting up ThingsBoard&reg; TLS**](#setting-up-thingsboard-tls). Otherwise, press **N** and
    skip to step 11.
> If the user selects X509 authentication, it is mandatory to have TLS configured. By default, the application proceeds with the TLS configuration.

```
Configure TLS? [Y/N]
```

9. Choose an input method for the *\*.pub.pem* file. The `Absolute file
    path` option requires a path to the file that does not include
    wildcards like \~. The `Console input` option will ask for the file
    to be input into the console; note that all lines preceding a line
    break cannot be edited:
```
Configuring TLS.
Input ThingsBoard CA from file? [Y/N] y

Please enter a filename to import 

ThingsBoard CA file (*.pub.pem):

/home/abc/mqttserver.pub.pem
```

10. If the cloud provisioning is successful, the following message
    appears:
```
Successfully configured cloud service!
```

11. A Yes/No user prompt appears asking for a certificate verification
    on an OTA package. Choose `Y` if FOTA/Config load packages need to
    be verified using signature else choose `N`.
```
Signature checks on OTA packages cannot not be validated without provisioning a cert file.
Do you wish to use a pre-provisioned cert file for signature checks for OTA packages? [Y/N]
```

12. In-Band Manageability Framework Services are Enabled and Started.

    The script will then start the Intel Manageability services; when
    the script finishes, the device should be able to interact with the
    ThingsBoard&reg; dashboard; refer [Setting up the Dashboards](#setting-up-the-dashboards).

```
Enabling and starting agents...
Created symlink /etc/systemd/system/multi-user.target.wants/inbm-configuration.service → /etc/systemd/system/inbm-configuration.service.
Created symlink /etc/systemd/system/multi-user.target.wants/inbm-dispatcher.service → /etc/systemd/system/inbm-dispatcher.service.
Created symlink /etc/systemd/system/multi-user.target.wants/inbm-diagnostic.service → /etc/systemd/system/inbm-diagnostic.service.
Created symlink /etc/systemd/system/multi-user.target.wants/inbm-cloudadapter.service → /etc/systemd/system/inbm-cloudadapter.service.
Created symlink /etc/systemd/system/multi-user.target.wants/inbm-telemetry.service → /etc/systemd/system/inbm-telemetry.service.
Turtle Creek Provisioning Complete
```

13. If at any time the cloud service configuration needs to be changed
    or updated, run the provisioning steps again.

**Note:** 
> If provisioning is unsuccessful, refer to **[Provisioning Unsuccessful](https://github.com/intel/intel-inb-manageability/blob/Broken_link_522523/docs/Issues%20and%20Troubleshooting.md#issues-and-troubleshooting)** for Troubleshooting.

#### Provisioning Command Parameters

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

### Setting up the Dashboards

1. Click `Widgets Library` Ⓐ, then the plus button Ⓑ, then the import
    button Ⓒ:  
    <img src="media/In-Band Manageability User Guide - ThingsBoard/media/image12.png" style="width:5.75in;height:3.26042in" />

2. The following window should appear. Choose the
    *intel\_manageability\_widgets.json* file; if INB has been
    installed, this file can be found at
    ```
    /usr/share/cloudadapter-agent/thingsboard/  
    ```
    <img src="media/In-Band Manageability User Guide - ThingsBoard/media/image13.png" alt="P329L19#yIS1" style="width:5.3125in;height:1.89514in" />

3. Click `Dashboards`, then the plus button and the import button as
    before

4. A window similar to the one in step 4 should appear; this time,
    choose the *intel\_manageability\_devices.json* and
    *intel\_manageability\_batch.json* files, which can also be found in
    the same directory.

5. The dashboards should now appear as options in the menu.

### Getting Familiar with ThingsBoard&reg;

More information on using ThingsBoard&reg; can be found at:
[**https://thingsboard.io/docs/**](https://thingsboard.io/docs/)

### Managing Devices
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image14.png" style="width:5.76667in;height:3.0in" />

A.  To manage devices, click `Devices`:  

B. Edit the details for a device, click the device entry

C. View the access token

D. Remove the device

E. Add a device; see [**Adding a Device**](#adding-a-device)

### Interacting with Individual Devices

To access the dashboard, click `Dashboards` Ⓐ, then on the `Intel
Manageability Devices` entry Ⓑ:

A dashboard similar to the one below should appear:  
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image15.png" style="width:5.525in;height:3.0in" />

A. Change the dashboard (i.e. to the Intel Manageability Batch; see
[**Interacting with Multiple Devices**](#interacting-with-multiple-devices)

B. Change the device being viewed

C. Change the time interval of the dashboard, affecting the dynamic
    telemetry displayed

D. Display the online status of the device; click the bar to manually
    check the online status

E. Display the static telemetry of the device

F. Display dynamic telemetry of the device

G. Trigger Docker&reg; Container Stats

H. Trigger a remote procedure call by clicking on the corresponding
    buttons

I. View the event logs of the device

### Interacting with Multiple Devices

To access the dashboard, click `Dashboards`, then on the `Intel
Manageability Batch` entry:  
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image16.png" style="width:5.78333in;height:2.34975in" />

A dashboard similar to the one below should appear:  
<img src="https://github.com/intel/intel-inb-manageability/blob/RTC_Fixed_Branch_516194/docs/media/In-Band%20Manageability%20User%20Guide%20-%20ThingsBoard/media/image17.PNG" style="width:5.78333in;height:3.0in" />

A. Change the dashboard (i.e. to the Intel Manageability Devices; refer
    [Setting up the Dashboards](#setting-up-the-dashboards))

B. Select the devices to send the batch remote procedure call to

C. Trigger a remote procedure call by clicking on the corresponding
    button

D. View the event logs for all devices

### Modifying and Working with Intel Manageability Widgets

ThingsBoard&reg; widgets are coded in HTML/CSS/JavaScript + AngularJS through
ThingsBoard`s built-in Widget IDE. They can then be added to dashboards
and exported for later use. Resources on how to edit and use the widgets
can be found below:

- [**Getting Started with
    AngularJS**](https://www.w3schools.com/angular/default.asp)

- [**About AngularJS
    Material**](https://material.angularjs.org/latest/)

- [**ThingsBoard&reg; Widgets Development
    Guide**](https://thingsboard.io/docs/user-guide/contribution/widgets-development/)

The Intel Manageability Widgets bundle consists of seven widgets:

- **Device Information**: Provides a well formatted device properties
    display

- **Connectivity Status**: Displays the device connectivity status

- **Dynamic Telemetry**: Extension of built-in time series display

- **Event Log**: Extension of built-in textual time series display

- **OTA Form**: Provides a flexible RPC request trigger with user
    input fields

- **Device List**: Provides a selection box for batch RPC calls

- **Docker&reg; Stats Widget**: Provides a human readable view of the
    latest Docker&reg; statistics

The Device Information is self-contained. However, the other widgets
communicate with each other through [**Custom JavaScript
Events**](https://developer.mozilla.org/en-US/docs/Web/Guide/Events/Creating_and_triggering_events).
The relationships of the events are illustrated below:
<p align="center">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image18.png" alt="P377#yIS2" style="width:3.91895in;height:2.61563in" />
</p>

The Events allow for the widgets to overcome their single API
limitation:

- Connectivity Status is actually an RPC widget, hence it cannot
    access Time Series data. To overcome this, Dynamic Telemetry and
    Event Log widgets broadcast updates that Connectivity Status uses in
    its polling decisions.

- Device List is used to send a list of selected devices to OTA Form
    widgets for batch operations

## Commands

After the In-Band Manageability Framework running on the Edge IoT Device
is provisioned, it will establish a secure session with the ThingsBoard
portal and the status of the device can is visible as `Online` – refer
as seen below:

Users shall be able to perform the updates listed below on the device
that is provisioned:

- AOTA (Application Over the Air update)

- FOTA (Firmware-over-the-Air update)

- SOTA (Software/OS-over-the-Air update)

- Config Update (Configuration Parameter update)

- Query Command

- Power Management (Remote Shutdown and Restart)

### Trusted Repositories

As part of a security measure, In-band Manageability requires the Server
URL(location) of the OTA update repository be included in a `trusted
repository list`, which is maintained internally. Hence, it is mandatory
that the OTA URL be included in the `trusted repository list` prior to
initiating an OTA command. This can be achieved via OTA configuration
Append command to add a new Server URL the existing Trusted Repository
list.

**IMPORTANT NOTE:** 
> It is critical for the user to ensure that the OTA packages are hosted in secure repositories. This is outside the scope of INBM.

**OTA Configuration Update:** refer to **[Configuration Append](#configuration-append)** for adding the Server URL in the trustedRepositories via `Trigger Config
Update`.

**NOTE:** 
> If the URL from which the package for an OTA update is being fetched doesn`t exist in the trustedRepositories list, INB would abort the update since the fetch URL is not in the trusted list.

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

SOTA on Ubuntu\* Operating System does not require any SOTA package.

SOTA on Yocto is handled by INB based on OS implementation:

1. Debian package manager: in does not require any SOTA package
    creation but instead requires the APT repositories set correctly and
    path included in the apt resources.

2. Mender.io: These involve OS update images, also known as **mender
    artifacts**, generated by the build infrastructure. More information
    on mender integration can be found at <https://docs.mender.io> .

#### Creating AOTA Package

AOTA Package structure for the below commands should follow the below
format

|AOTA Command|AOTA Package Structure|
|---|---|
|AOTA docker-compose package<br>(Same format for up/pull)|Container Tag == Container Image Name<br>Example: The container Image name and the tar file name should be the same<br>*Container Tag =* `CPU`<br>*Tar file =* `CPU.tar.gz`<br>*Note: The tar file should contain a folder with the same name `CPU`. This folder `CPU` needs to have the `docker-compose.yml` file.*<br>Steps:<br>1. Make a folder<br>2. Copy the `docker-compose.yml` file into the folder<br>Tar the folder|
|AOTA Docker&reg; Load/Import|Package needs to be `tar.gz` format<br>The package needs to have a folder within the same name as the package.|

#### Creating Configuration Load Package

The Configuration load package structure remains unchanged when
signature field is used. For a more secure OTA update, users can
provision a device with a PEM file containing the certificate to
validate the downloaded file against a signature provided as part of the
OTA command, refer  [How to Generate Signature](#how-to-generate-signature). Users may create a
PEM file using the OpenSSL and Cryptography libraries.

1. **With Signature**: Configuration Load package structure with
    signature accepts both *tar* file with the
    *intel\_manageability.conf* file and just the
    *intel\_manageability.conf* file alone. Archiving the
    *intel\_manageability.conf* file with a *tar* archive tool can be
    performed with below command:
```shell
tar cvf conf_update.tar intel_manageability.conf signing_cert.pem
```

-   When a device is provisioned with a PEM file to validate the downloaded
    config file or package, it is expected that every Config Load method
    triggered with a firmware package will be having a signature that is
    validated against the signature using the provisioned PEM file.

2. **Without Signature**: Configuration Load package structure with no
    signature only contains *intel\_manageability.conf* file

### How to Generate Signature

To generate certificate, private key and signatures, OpenSSL or
Cryptography libraries can be used.

Once the above are generated, to validate the OTA package for
FOTA/Config Load, we need to have the device provisioned with a
certificate (cert.pem). While triggering OTA command from cloud fill the
signature field in the OTA form before clicking `Execute` to trigger
OTA.
**NOTE:**
> While creating a signature INB, use shar-256 or sha-384 based encryption mechanism.

### OTA Updates

To trigger Over the Air (OTA) updates, Device Status should be online as
seen in [**Interacting with Multiple Devices**](#interacting-with-multiple-devices). Go to
**DashBoards** tab and select the correct **DashBoard\[1\]** and under
entities, select your **Edge Device\[2\]** and click any **OTA
buttons\[3\]** as seen below

<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image19.png"/>

### Commands - Definitions and Usage

| Command                     | Definition                                                                                                                        |
|-----------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| Trigger AOTA          | Remotely launch/update docker containers on the Edge IoT Device                                                                   |
| Trigger FOTA          | Update the BIOS firmware on the system                                                                                            |
| Trigger SOTA          | User-friendly, parameter driven updates to OS software packages on the system                                                     |
| Trigger Config Update | Update the In-Band Manageability configurations                                                                                   |
| Reboot                | Remotely reboot the Endpoint                                                                                                      |
| Shutdown             | Remotely shutdown the Endpoint                                                                                                     |
| Query                | Fetch device firmware, software, guid and other hardware related informatin                                                        | 
| Manifest Update             | Any OTA update type can be done via the Manifest Update, by entering XML text to update the Endpoint. Refer to the [Developer Guide](In-Band%20Manageability%20Developer%20Guide.md).
 

#### Supported AOTA commands and AOTA form descriptions
[AOTA Updates](AOTA.md)


To trigger Application-over the Air updates click the `Trigger AOTA`
button as seen below.

<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image20.png" style="width:6.02083in;height:2.94792in" />

Now, populate the AOTA pop-up window with the required parameters and
then click `Send` to trigger the AOTA update.

AOTA Field Details

| Field                                                          | Input description                                                                                                                                                                                                                                                                                   |
|----------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Application and supported command                              | `docker-compose` supports: `up`, `down`, `pull`, `list` and `remove`.<br>`docker` supports: `list`, `load`, `import`, `pull`, `remove` and `stats`<br>Application: update                                                                                                                           |
| Container Tag                                                  | Name tag for image/container.<br>Note: Container Tag can have both the Name and Version in this format Image:Version                                                                                                                                                                                |
| Docker&reg; Compose File                                       | Name of custom YAML file for docker-compose command. Example: `custom.yml`                                                                                                                                                                                                                          |
| Fetch                                                          | Server URL to download the AOTA container `tar.gz` file<br>If the server requires username/password to download the file, you can provide in server username/ server password<br>*NOTE*: Follow [Creating AOTA Package](https://github.com/intel/intel-inb-manageability/blob/Broken_link_522523/docs/In-Band%20Manageability%20User%20Guide%20-%20ThingsBoard.md#creating-aota-package)                                                    |
| Server Username/<br>Server Password                            | Credentials to download remote package when required.                                                                                                                                                                                                                                               |
| Docker&reg; Registry<br>Docker&reg; Registry Username/Password | Docker&reg; Registry if accessing any registry other than the default `index.docker.io`.<br>Example: `registry.hub.docker.com`<br>Optional fields Docker&reg; Registry Username/Password can be used to when using private images in AOTA through docker pull and docker-compose up, pull commands. |

**Note:** 
> Following sections demonstrate what fields to fill for respective AOTA operations with required and optional fields.
<p align="center">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image21.png" alt="P607#yIS2" style="width:2.11458in;height:1.23958in" />
</p>

For each of the AOTA functions, insert the correct parameters as
described and click **`send` button. The results can be viewed** by
clicking on the **Events** tab.

### AOTA docker-compose Operations 

#### Docker-Compose UP  

Follow [**Creating AOTA Package**](#creating-aota-package) to create the AOTA
Package.

>  1. The Container Tag name should be same as the file name in the fetch field. 
>       Example: Container Tag: CPU Downloaded fetch file: `CPU.tar.gz`.
>  2. Docker-Compose yml file should have the correct docker version.

<p align="center">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image24.PNG" style="width:3.20833in;height:6.31666in" />
</p>

#### Docker-Compose DOWN
<p align="center">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image23.PNG" alt="P619#yIS2" style="width:3.20833in;height:6.31666in" />
</p>

#### Docker-Compose PULL

Follow [**Creating AOTA Package**](#creating-aota-package) to create the AOTA
Package.

**NOTE:**
> The Container Tag name should be same as the file name in the fetch field. 
> Example: Container Tag: CPU Downloaded fetch file: `CPU.tar.gz`
<p align="center">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image25.PNG" style="width:3.20833in;height:6.31666in" />
</p>

#### Docker-Compose LIST 
<p align="center">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image27.PNG" style="width:3.20833in;height:6.31666in" />
</p>

#### Docker-Compose REMOVE
<p align="center">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image26.PNG" style="width:3.99167in;height:6.1743in" />
</p>

### AOTA Docker&reg; Operations

#### Docker IMPORT

**NOTE**: 
> The Container Tag name should be same as the file name in the fetch field.

Example: Container Tag: CPU, Downloaded fetch file: CPU.targ.gz

Follow [**Creating AOTA Package**](#creating-aota-package)

#### Docker LIST
<p align="center">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image57.png" alt="P654#yIS2" style="width:3.99201in;height:6.18387in" />
</p>

#### Docker LOAD

**NOTE:** 
> The Container Tag name should be same as the file name in the fetch field.
>  Example: Container Tag: CPU Downloaded fetch file: `CPU.tar.gz`

Refer [**Creating AOTA Package**](#creating-aota-package)
<p align="center">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image28.PNG" alt="P650#yIS2" style="width:4.00868in;height:6.26721in" />
</p>

#### Docker PULL
<p align="center">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image29.PNG" alt="P654#yIS2" style="width:3.99201in;height:6.18387in" />
</p>

#### Docker REMOVE
<p align="center">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image30.PNG" alt="P657#yIS2" style="width:3.55in;height:6.08264in" />
</p>

#### Docker STATS
<p align="center">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image51.png" alt="P657#yIS2" style="width:3.55in;height:6.08264in" />
</p>

### AOTA Application Operations

#### Application Update

**NOTE:** 
> The Device Reboot is an optional field.

For any Xlink driver update it is mandatory to reboot the device.

Input `yes` for Device Reboot as seen below.

You can only use signed packages to update Xlink Driver application
<p align="center">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image33.PNG" style="width:5.64166in;height:5.95643in" />
</p>

#### AOTA Docker/Docker-Compose Operations via Manifest

[AOTA Manifest Parameters and Examples](Manifest%20Parameters.md#AOTA)

### FOTA Updates 

To perform FOTA updates, IBVs must supply the SMBIOS or Device Tree info
that is unique to each platform SKU and fulfill the vendor, version,
release date, manufacturer, and product name that matches the endpoint
as shown below.

1. The following information must match the data sent in the FOTA
    update command for In-Band Manageability Framework to initiate a
    Firmware update process.

| Information | Field        | Checks                                                                                      |
|-------------|--------------|---------------------------------------------------------------------------------------------|
| FW          | Vendor       | Checks for string match between the user input and platform vendor                          |
|             | Version      |                                                                                             |
|             | Release Date | Checks if the current firmware file release date is newer than release date on the platform |
| System      | Manufacturer | Checks for a string match between the user input and platform manufacturer                  |
|             | Product Name | Checks for string match between the user input and platform product name                    |

To find the FW and System fields at the endpoint, run the commands
below:

#### Intel x86 UEFI-based products

For UEFI-based platforms the Firmware and system information can be
found running the following command.
```shell
sudo dmidecode –t bios –t system 
```

#### FOTA Update via Button Click 

-   In order to trigger Firmware-over the Air updates click the `Trigger
FOTA` button as seen below
<p align="center">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image32.png" alt="Graphical user interface Description automatically generated" style="width:6.14167in;height:3.39167in" />
</p>

-   Populate the text fields within the `Trigger FOTA` block with the parameters in the table below.

**NOTE:**
 > If triggering a secure FOTA update with a \*.pem file within the *tar*, a signature needs to be given in the respective field. The signature can be generated using OpenSSL, or Cryptography libraries along with the key.pem file.



Parameter Details

| Parameter                | Description                                                                                                                            |
|--------------------------|----------------------------------------------------------------------------------------------------------------------------------------|
| BIOSVersion              | Verify with BIOS Vendor (IBV)                                                                                                          |
| Fetch                    | Repository URL<br>NOTE: Follow Creating FOTA Package                                                                                   |
| Manufacturer             | Endpoint Manufacturer Name                                                                                                             |
| Path                     | FOTA path created in repository                                                                                                        |
| Product                  | Product name set by Manufacturer                                                                                                       |
| Release Date             | Specify the release date of the BIOS file you are applying. Verify with BIOS Vendor (IBV) <br> IMPORTANT NOTE: Date format: yyyy-mm-dd |
| Signature                | Digital signature                                                                                                                      |
| ToolOptions              | Any Tool options to be given for the Firmware Tool                                                                                     |
| Server Username/Password | If server where we host the package to download FOTA file needs credentials, we need to specify the username and password              |

Following sections demonstrate what fields to fill for respective FOTA operations with required and optional fields.

<p align="center">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image21.png" alt="P744#yIS2" style="width:2.11458in;height:1.23958in" />
</p>
<p align="center">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image31.png"/>
</p>

-   After filling the correct parameters as described in the table, click **Send** to commission the FOTA update.

#### FOTA Update via Manifest

[FOTA Manifest Parameters and Examples](Manifest%20Parameters.md#FOTA)

### SOTA Updates 

SOTA commands vary based on OS type and update mechanisms supported by
it. Ubuntu&reg; OS or Yocto Project&reg;-based OS, which includes the Debian
package manager do not require any package preparation, while a Yocto
Project&reg;-based OS with Mender.io based solution does. This changes the
interface slightly as explained below.

#### SOTA Update Via Button Click (Debian Package Manager and Ubuntu OS) 

In order to trigger Software-over the Air updates click the `Trigger
SOTA` button as seen below

<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image35.png" alt="Graphical user interface, table Description automatically generated" style="width:9.12in;height:1.65833in" />

Populate the SOTA pop-up screen with `Log to File` as `Yes` to have logs
will be written to the file otherwise `No` to have logs to be written to
the cloud. SOTA log files can be located at the endpoint
```
/var/cache/manageability/repository-tool/sota/
```

##### SOTA Parameters

| Command     | Specifies the SOTA `update` command.                                                                                                                                              |
|-------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Log to File | Specifies if the logs be written to a file or to the cloud. Values `Y` or `N` <br> SOTA log files can be located at the endpoint `/var/cache/manageability/repository-tool/sota/` |

**Note:**
> Following screenshot demonstrates what fields to fill for a
> SOTA operation with required and optional fields.

Populate the SOTA pop-up window with the required parameters and click
`send` to trigger the SOTA update.
<p align="center">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image36.PNG" alt="Graphical user interface, application Description automatically generated" style="width:4.38333in;height:5.61667in" />
</p>

#### SOTA Update Via Button Click (Mender) 

In order to trigger Software-over the Air updates click the `Trigger
SOTA` button as seen below:
<p align="center">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image37.PNG" alt="Graphical user interface Description automatically generated" style="width:4.56706in;height:5.67549in" />
</p>

- Populate the SOTA pop-up screen with `Log to File` as `Yes` to have logs
will be written to the file otherwise `No` to have logs to be written to
the cloud. SOTA log files can be located at the endpoint
```
/var/cache/manageability/repository-tool/sota/
```

**Parameter Details:**

| Command      | Specifies the SOTA `update` command.                                                                                                                                              |
|--------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Fetch        | URL patch to download the Mender artifact from                                                                                                                                    |
| Log to File  | Specifies if the logs be written to a file or to the cloud. Values `Y` or `N` <br> SOTA log files can be located at the endpoint `/var/cache/manageability/repository-tool/sota/` |
| Username     | Mender artifact repository Username                                                                                                                                               |
| Password     | Mender artifact repository Password                                                                                                                                               |
| Release Date | Release date of the new mender file used in fetch field                                                                                                                           |

**Note:**
> Following screenshot demonstrates what fields to fill for a
> SOTA operation with required and optional fields.

Populate the SOTA pop-up window with the required parameters and click
`send` to trigger the SOTA update. Release date should be in format
`yyyy-mm-dd`

<p align="center">
  <img src="media/In-Band Manageability User Guide - ThingsBoard/media/image38.png" style="width:3.43564in;height:5.06031in" />
</p>


#### SOTA Update Via Manifest
[SOTA Manifest Parameters and Examples](Manifest%20Parameters.md#SOTA)

### Configuration Update

Configuration update is used to update, retrieve, append, and remove
configuration parameter values from the Configuration file located at
```
/etc/intel_manageability.conf
```
Refer to table below to understand the
configuration tags, its values and the description.

#### Default Configuration Parameters

| Telemetry                                   |                         |                                                                                                                                          |
|---------------------------------------------|-------------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| Collection Interval Seconds                 | 60 seconds              | Time interval after which telemetry is collected from the system.                                                                        |
| Publish interval seconds                    | 300 seconds             | Time interval after which collected telemetry is published to dispatcher and the cloud                                                   |
| Max Cache Size                              | 100                     | Maximum cache set to store the telemetry data. This is the count of messages that telemetry agent caches before sending out to the cloud |
| Container Health Interval Seconds           | 600 seconds             | Interval after which container health check is run and results are returned.                                                             |
| Enable SwBom                                | True                    | Specifies if Software BOM needs to be published in the initial telemetry.                                                                |
| SwBom Interval Hours                        | 24 Hours                | Interval after which swbom details are published.                                                                                        |
| Diagnostic Values                           |                         |                                                                                                                                          |
| Min Storage                                 | 100 MB                  | Value of minimum storage that the system should have before or after an update                                                           |
| Min Memory                                  | 200 MB                  | Value of minimum memory that the system should have before or after an update                                                            |
| Min Power Percent                           | 20%                     | Value of minimum battery percent that the system should have before or after an update                                                   |
| Mandatory SW                                | docker, trtl, telemetry | List of software that should be present and are checked for.                                                                             |
| Docker&reg; Bench Security Interval Seconds | 900 seconds             | Time interval after which DBS will run and report back to the cloud.                                                                     |
| Network Check                               | True                    | This configures network check on the platforms based on their Ethernet capability.                                                       |
| Dispatcher Values                           |                         |                                                                                                                                          |
| DBS Remove Image on Failed Container        | False                   | Specifies if the image should be removed in the event of a failed container as flagged by DBS.                                           |
| Trusted Repositories                        |                         | List of repositories that are trusted and packages can be fetched from them                                                              |
| SOTA Values                                 |                         |                                                                                                                                          |
| Ubuntu Apt Source                           | Repository link         | Location used to update Debian packages                                                                                                  |
| Proceed Without Rollback                    | True                    | Whether SOTA update should go through even when rollback is not supported on the system.                                                 |

**Below are the configuration update commands and input field
description**

| Trigger Configs | Description of field                                                                                                                                                                                                                                                                                                                                                                                  |
|-----------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Command         | `Set`: Command used to update the configuration value using key:value pair. <br>`Get`: Command used to retrieve a specific configuration value using key:value pair<br>`Load`: Command used to replace an entire configuration file.<br>`Append`: Command used to append values to a configuration parameter.<br>`Remove`: Command used to remove a specific values from the configuration parameter. |
| Fetch           | The URL to fetch config file from in the case of a load                                                                                                                                                                                                                                                                                                                                               |
| Path            | Specifies the path of element to get, set, append or remove in key:value format                                                                                                                                                                                                                                                                                                                       |
| Signature       | Digital signature                                                                                                                                                                                                                                                                                                                                                                                     |


**To trigger a configuration update, follow the steps below**:

In order to trigger Application-over the Air updates click the `Trigger
Config Update` button as seen below
<p align="center">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image40.png" style="width:5.58333in;height:3.45in" />
</p>

Populate the `Trigger Config Update` pop-up window with the required
parameters and click `send` to trigger the Config Update as shown below.

### Configuration Update Via Button Click 

#### Configuration Set 

**Required Fields**: Command and Path

**Examples:**
> To set one value: `minStorageMB:10`
> To set multiple values at once: `minStorageMB:10;minMemoryMB:250`

**NOTE:** 
> Path takes in key value pairs as an input with key as the
> configuration parameter tag and value to be set as the value. Also, to
> set multiple key:value pairs, use; to separate one pair from another
> as shown above in the example.
<p align="center">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image41.PNG" alt="P902#yIS2" style="width:3.75833in;height:4.58333in" />
</p>

Results of Configuration Set update can be seen in the ThingsBoard
Events Log in the dashboard below the OTA buttons.

#### Configuration Get 

**Required Fields**: Command and Path

**Examples:**

> To get one configuration value, use configuration tag as input for path- `minStorageMB`
>
> To get multiple values at once use **;** to separate tags- `minStorageMB;minMemoryMB`

**NOTE:** 
> Path takes in keys as an input with key as the configuration
> parameter tag whose value needs to be retrieved. Also, to retrieve
> multiple values at once use `;` to separate one tag from another as
> shown above in the example.
<p align="center">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image42.PNG" alt="P922#yIS2" style="width:2.7916in;height:3.41739in" />
</p>

Results of Configuration Get update can be seen in the ThingsBoard
Events Log in the dashboard below the OTA buttons.

#### Configuration Load 

**Required Fields**: Command and Fetch

**Optional Field**: Signature

**NOTE**: 
> Refer [**Creating Configuration Load Package**](#creating-configuration-load-package)
<p align="center">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image43.PNG" alt="P929#yIS2" style="width:3.6in;height:4.46374in" />
</p>

#### Configuration Append 

**Required Fields**: Command and Path


**NOTE:**
> - Append is only applicable to three configuration tags i.e
> `trustedRepositories`, `sotaSW` and `ubuntuAptSource`
>
> - Path takes in key value pair format, example:
> `trustedRepositories:https://abc.com/`
<p align="center">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image44.PNG" alt="P941#yIS2" style="width:3.33963in;height:3.65in" />
</p>

#### Configuration Remove 

**Required Fields**: Command and Path

**NOTE:** 
> - Remove is only applicable to three configuration tags i.e
> `trustedRepositories`, `sotaSW` and `ubuntuAptSource`
> -   Path takes in key value pair format, example: `trustedRepositories:https://abc.com/`

<p align="center">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image47.PNG" alt="P978#yIS2" style="width:4.10995in;height:4.74167in" />
</p>

### Configuration Update Via Manifest
[Configuration Command Manifests and Examples](Manifest%20Parameters.md)

### Power Management

Shutdown and Restart capabilities are supported via button click as seen
below.

#### System Reboot Via Button Click 

Click the `Reboot Button` as seen below in the dashboard to trigger a
Device Reboot
<p align="left">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image48.png" style="width:5.475in;height:3.21667in" />
</p>

Now on the pop-up window shows up, click the `Send` button on the box
titled **`Reboot Device`.**
<p align="left">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image49.PNG" alt="P1014#yIS2" style="width:3.33333in;height:1.18687in" />
</p>

#### System Shutdown Via Button Click 

Click the `Shutdown Button` as seen below in the dashboard to trigger a
Device Reboot.
<p align="left">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image50.png" style="width:5.63542in;height:3.24167in" />
</p>

Now on the pop-up window shows up, click the `Send` button on the box
titled **`Shutdown Device`.**

### Decommission Command

In-band manageability provides a mechanism to handle the decommission
request over the air. The Decommission command is used to remove all the
credentials and then result in a device shutdown.

To trigger Decommission, click the `Reboot Button` as seen below in the
dashboard to trigger a Device Reboot.
<p align="left">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image52.png" style="width:5.70833in;height:2.83333in" />
</p>

Now on the pop-up window shows up, click the `Send` button on the box
titled **`Decommission Device`**.

### Query Command

The Intel® In-Band Manageability provides a way to query attribute information on either the Host, Edge Device, or Nodes.

To trigger a query request, click the **Trigger Query** button as seen below.

<p align="left">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image65.png" style="width:5.70833in;height:2.83333in" />
</p>

Populate the **Trigger Query** pop-up window with the required parameters and click **send** to trigger the query request.

<p align="left">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image64.png" style="width:5.70833in;height:2.83333in" />
</p>

For the details on **Query options**
Refer to [Query options ](https://github.com/intel/intel-inb-manageability/blob/develop/docs/Query.md)							 
	
The query command capabilities are also supported via manifest.

### Query Command via Manifest

[Query Manifest and Examples](Manifest%20Parameters.md#Query)

## Telemetry Data

In-Band Manageability provides two types of telemetry data.  Telemetry can be viewed under Dashboard as displayed below:
- 1 - Static Telemetry
- 2 - Dynamic Telemetry.  The telemetry data will indicate the health of each endpoint.


<p align="left">
<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image54.png" style="width:5.70833in;height:3.74167in" />
</p>

### Static Telemetry Data

This contains the following information

- BIOS-release-date
- BIOS-vendor
- BIOS-version
- CPU-ID
- Disk Information
- OS-information
- System-Manufacturer
- System-Product-Name
- Total-physical-memory

 Static Telemetry can be viewed in the DashBoard when you maximize the Static Telemetry window.

### Dynamic Telemetry Data

Each endpoint publishes the following Dynamic Telemetry Data in 5-minute intervals.

The following are displayed in the data chart and also appear in the New Event Log:
- Available-memory
- Core-temp-Celsius
- Percent-disk-used
- System-cpu-percent
- Battery Status (if battery powered)

The following will only appear in the New Event Log:
- Container-stats (cpu usage and memory information for all running containers)
- Network Information

### Viewing Telemetry Data

The device must be connected in order to view the telemetry information
on the ThingsBoard.

#### Static Telemetry
To view the device`s static telemetry, click the Static Telemetry window.

<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image55.png" style="width:5.65625in;height:3.58333in" />

#### Dynamic Telemetry

To view the device`s Dynamic telemetry, click the Dynamic Telemetry to
see the below

<img src="media/In-Band Manageability User Guide - ThingsBoard/media/image56.png" style="width:5.78125in;height:3.03125in" />

## Issues and Troubleshooting

[General Troubleshooting](Issues%20and%20Troubleshooting.md)

### OTA Error Status
[Error Messages](Error%20Messages.md)

### Acquiring Debug Messages from Agents

Refer to the [Developer Guide](In-Band%20Manageability%20Developer%20Guide.md).
