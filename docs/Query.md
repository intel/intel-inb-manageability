# Query Command

## Description
The Query command can be called by either the cloud or INBC.  It will provide attribute information on either the Host, Edge Device, or Nodes.

### How to Call

- [INBC](https://github.com/intel/intel-inb-manageability/blob/develop/inbc-program/README.md#Query)

- [Manifest](https://github.com/intel/intel-inb-manageability/blob/develop/docs/Manifest%20Parameters.md#Query)

## Options

#### 'hw' - Hardware

| Attribute     | Description                                         | 
|:--------------|:----------------------------------------------------|
| is_flashless  | True if plug-in card is flashless; otherwise, False |
| manufacturer  | Hardware manufacturer                               |
| platform_type | Type of plug-in card.  TBH or KMB                   |
| product       | Product type                                        |
| stepping      | Stepping                                            |
| sku           | SKU                                                 |
| model         | Model number                                        |
| serial_sum    | Serial number                                       |

#### 'fw' - Firmware

| Attribute       | Description      | 
|:----------------|:-----------------|
| boot_fw_date    | Firmware date    |
| boot_fw_vendor  | Firmware vendor  |
| boot_fw_version | Firmware version |

#### 'guid' - GUID

| Attribute      | Description                                                | 
|:---------------|:-----------------------------------------------------------|
| guid           | GUID of HDDL plug-in card                                  |
| is_provisioned | True if HDDL plug-in card is provisioned; otherwise, False |

#### 'os' - Operating System

| Attribute       | Description                   | 
|:----------------|:------------------------------|
| os_type         | Operating System type         |
| os_version      | Operating System version      |
| os_release_date | Operating System release date |

#### 'security' - Security

| Attribute             | Description                                                | 
|:----------------------|:-----------------------------------------------------------|
| dm_verity_enabled     | True if DM verity is enabled; otherwise, False             |
| measured_boot_enabled | True if Measured Boot is enabled; otherwise, False         |
| is_provisioned        | True if HDDL plug-in card is provisioned; otherwise, False |
| is_xlink_secured      | True if using Secured Xlink; otherwise, False              |
| guid                  | GUID of HDDL plug-in card                                  |

#### 'status' - Status

| Attribute         | Description                                                     | 
|:------------------|:----------------------------------------------------------------|
| heartbeat_status  | Heartbeat status of HDDL plug-in card (Active, Idle)            |
| heartbeat_retries | Number of heartbeat retries attempted for the HDDL plug-in card |

 #### 'swbom' - Software BOM

SWBOM dynamic telemetry data
 
#### 'version' - Version

| Attribute | Description                         | 
|:----------|:------------------------------------|
| version   | Version of the vision-agent service |
