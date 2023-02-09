# Query Command

## Description
The Query command can be called by either the cloud or INBC.  It will provide attribute information on the Host.

### How to Call

- [INBC](https://github.com/intel/intel-inb-manageability/blob/develop/inbc-program/README.md#Query)

- [Manifest](https://github.com/intel/intel-inb-manageability/blob/develop/docs/Manifest%20Parameters.md#Query)

## Options

#### 'hw' - Hardware

| Attribute     | Description                                         | 
|:--------------|:----------------------------------------------------|
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

#### 'os' - Operating System

| Attribute       | Description                   | 
|:----------------|:------------------------------|
| os_type         | Operating System type         |
| os_version      | Operating System version      |
| os_release_date | Operating System release date |

 #### 'swbom' - Software BOM

SWBOM dynamic telemetry data
 
#### 'version' - Version

| Attribute | Description    | 
|:----------|:---------------|
| version   | Version number |
