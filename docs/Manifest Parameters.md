# Manifest Overview

The following outlines the manifest parameters used to perform the supported OTA updates, configuration commands, query, and provision node.

## Table of Contents
1. [Manifest Rules](#manifest-rules)
3. [FOTA](#FOTA)
4. [SOTA](#SOTA)
5. [POTA](#POTA)
6. [AOTA](#AOTA)
7. [Query](#Query)
8. [Configuration SET](#Set)
9. [Configuration GET](#Get)
10. [Configuration LOAD](#Load)
11. [Provision Node](#Provision-Node)

## Manifest Rules 

- All tags marked as **required (R)** in the manifest examples below
    must be in the manifest. Any tags marked as **optional (O)** can be
    omitted.

- The start of a section is indicated as follows **\<manifest\>**.

- The end of a section is indicated by **\</manifest\>**. All sections
    must have the start and the matching end tag.

- Remove spaces, tabs, comments and so on. Make it a single continuous
    long string.  
    Example: **\<xml
    ...\>\<manifest\>\<ota\>\<header\>...\</ota\>\<manifest\>**

- Parameter within a tag cannot be empty.  
    Example: **\<description\>\</description\>** is not allowed.


## FOTA

### FOTA Manifest Parameters

| Tag                                      | Example                                             | Required /Optional | Notes                                                                                                                                                       |
|:-----------------------------------------|:----------------------------------------------------|:------------------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `<?xml version='1.0' encoding='utf-8'?>` | `<?xml version='1.0' encoding='utf-8'?>`            |         R          ||
| `<manifest>`                             | `<manifest>`                                        |         R          ||
| `<type></type>`                          | `<type>ota</type>`                                  |         R          | Always OTA                                                                                                                                                  |
| `<ota>`                                  | `<ota>`                                             |         R          ||
| `<header>`                               | `<header>`                                          |         R          ||
| `<id></id>`                              | `<id>yourID</id>`                                   |         O          ||
| `<name></name>`                          | `<name>YourName</name>`                             |         O          | Endpoint Manufacturer Name                                                                                                                                  |
| `<description></description>`            | `<description>YourDescription</description`>        |         O          ||
| `<type></type>`                          | `<type>fota</type>`                                 |         R          ||
| `<repo></repo>`                          | `<repo>remote</repo>`                               |         O          | [local or remote].  If file is already downloaded on the system, then use _**local**_.  If it needs to be fetched from remote repository, use **_remote_**. |
| `</header>`                              | `</header>`                                         |         R          ||
| `<type>`                                 | `<type>`                                            |         R          ||
| `<fota name=''>`                         | `<fota name='text'>`                                |         R          | Text must be compliant with XML Standards                                                                                                                   |
| `<fetch></fetch>`                        | `<fetch>http://yoururl:80/BIOSUPDATE.tar</fetch>`   |         R          | FOTA path created in repository                                                                                                                             |
| `<targetType></targetType>`              | `<targetType>node</targetType>`                     |         O          | [host or node] Used when updating either the host of vision cards (host) or vision cards (node)                                                             |
| `<targets></targets>`                    | `<targets><target>389C0A</target></targets>`        |         O          | Used when targetType=node.  Designates the Ids of the nodes to update                                                                                       |
| `<signature></signature>`                | `<signature>ABC123</signature>`                     |         O          | Digital signature of *.tar file.                                                                                                                            |
| `<biosversion></biosversion>`            | `<biosversion>A..ZZZZ.B11.1</biosversion>`          |         R          | Verify with BIOS Vendor (IBV)                                                                                                                               |
| `<vendor></vendor>`                      | `<vendor>VendorName</vendor>`                       |         R          | Verify with BIOS Vendor (IBV)                                                                                                                               |
| `<manufacturer></manufacturer>`          | `<manufacturer>BIOS_Manufacturer</manufacturer>`    |         R          | In Release Notes supplied by BIOS vendor                                                                                                                    |
| `<product></product>`                    | `<product>BIOS_Product</product>`                   |         R          | Product Name set by Manufacturer                                                                                                                            |
| `<releasedate></releasedate>`            | `<releasedate>2021-06-23</releasedate>`             |         R          | Verify with BIOS Vendor (IBV)                                                                                                                               |
| `<tooloptions></tooloptions>`            | `<tooloptions>p/b/n</tooloptions>`                  |         O          | Verify with BIOS Vendor (IBV)                                                                                                                               |
| `<guid></guid>`                          | `<guid>7acbd1a5a-33a4-48c3ab11-a4c33b3d0e56</guid>` |         O          | Check for ‘System Firmware Type’ on running cmd:fwupdate -l                                                                                                 |
| `<username></username>`                  | `<username>user</username>`                         |         O          | Username used during fetch from remote repository                                                                                                           |
| `<password><password>`                   | `<password>pwd</password>`                          |         O          | Password used during fetch from remote repository                                                                                                           |
| `<path></path>`                          | `<path></path>`                                     |         R          ||
| `</fota>`                                | `</fota>`                                           |         R          ||
| `</type>`                                | `</type>`                                           |         R          ||
| `</ota>`                                 | `</ota>`                                            |         R          ||
| `</manifest>`                            | `</manifest>`                                       |         R          ||

The following table references each XML tag within a manifest that triggers the FOTA update. Using the following XML tags in the order of
description will trigger a FOTA update via Manifest.

### Sample FOTA Manifest - Edge device
```xml
<?xml version='1.0' encoding='utf-8'?>
<manifest>
    <type>ota</type>
    <ota>
        <header>
            <type>fota</type>
            <repo>remote</repo>
        </header>
        <type>
            <fota name='sample'>
                <fetch>http://yoururl/Afulnx+X041_BIOS.tar</fetch>
                <biosversion>5.12</biosversion>
                <vendor>American Megatrends Inc.</vendor>
                <manufacturer>Default string</manufacturer>
                <product>Default string</product>
                <releasedate>2017-1120</releasedate>
                <path>/var/cache/repositorytool</path>
            </fota>
        </type>
    </ota>
</manifest>
```

### Sample FOTA Manifest - Target Intel Vision cards: 
```xml
<?xml version='1.0' encoding='utf-8'?>
<manifest>
    <type>ota</type>
    <ota>
        <header>
            <type>fota</type>
            <repo>remote</repo>
        </header>
        <type>
            <fota name='sample'>
                <fetch>http://yoururl/Afulnx+X041_BIOS.tar</fetch>
                <biosversion>5.12</biosversion>
                <vendor>American Megatrends Inc.</vendor>
                <manufacturer>Default string</manufacturer>
                <product>Default string</product>
                <releasedate>2017-1120</releasedate>
                <path>/var/cache/repositorytool</path>
            </fota>
        </type>
    </ota>
</manifest>
```

## SOTA

### SOTA Manifest Parameters 

| Tag                                      | Example                                      | Required/Optional | Notes                                                                                                                                                       |
|:-----------------------------------------|:---------------------------------------------|:-----------------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `<?xml version='1.0' encoding='utf-8'?>` | `<?xml version='1.0' encoding='utf-8'?>`     |         R         ||
| `<manifest>`                             | `<manifest`>                                 |         R         ||
| `<type></type>`                          | `<type>ota</type>`                           |         R         | Always OTA                                                                                                                                                  |
| `<header>`                               | `<header>`                                   |         R         ||
| `<id></id>`                              | `<id>Example</id>`                           |         O         ||
| `<name></name>`                          | `<name>Example</name>`                       |         O         ||
| `<description></description>`            | `<description>Example</description>`         |         O         ||
| `<type></type>`                          | `<type>sota</type>`                          |         R         ||
| `<repo></repo>`                          | `<repo>remote</repo>`                        |         R         | [local or remote].  If file is already downloaded on the system, then use _**local**_.  If it needs to be fetched from remote repository, use **_remote_**. |
| `</header>`                              | `</header>`                                  |         R         ||
| `<type>`                                 | `<type>`                                     |         R         ||
| `<sota>`                                 | `<sota>`                                     |         R         ||
| `<cmd></cmd>`                            | `<cmd logtofile=”Y”>update</cmd>`            |         R         ||
| `<targetType></targetType>`              | `<targetType>node</targetType>`              |         O         | [host or node] Used when updating either the host of vision cards (host) or vision cards (node)                                                             |
| `<targets></targets>`                    | `<targets><target>389C0A</target></targets>` |         O         | Used when targetType=node.  Designates the Ids of the nodes to update                                                                                       |
| `<fetch></fetch>`                        | `<fetch>https://yoururl/file.mender</fetch>` |         O         | Used to download mender file from remote repository. (use repo=remote)                                                                                      |
| `<path></path>`                          | `<path>/var/cache/file.mender</path>`        |         O         | Used to update using a local mender file  .  (use repo=local)                                                                                               |
| `<username></username>`                  | `<username>xx</username>`                    |         O         | Username for remote repository                                                                                                                              |                                                                 |
| `<password></password>`                  | `<password>xxx</password>`                   |         O         | Password for remote repository                                                                                                                              |                                                                 |
| `<release_date></release_ date>`         | `<release_date>2020-01-01</release_date>`    |         R         | The release date provided should be in ‘YYYY-MM-DD’ format.                                                                                                 |
| `</sota>`                                | `</sota>`                                    |         R         ||
| `</type>`                                | `</type>`                                    |         R         ||
| `</ota>`                                 | `</ota>`                                     |         R         ||
| `</manifest>`                            | `</manifest`>                                |         R         ||

### Sample SOTA Manifest - Ubuntu on Edge device: 
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest>
    <type>ota</type>
    <ota>
        <header>
            <type>sota</type>
            <repo>remote</repo>
        </header>
        <type>
            <sota>
                <cmd logtofile="Y">update</cmd>
                <release-date>2020-0101</release_date>
            </sota>
        </type>
    </ota>
</manifest>
```

### Sample SOTA Manifest - Mender update on Edge device: 
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest>
    <type>ota</type>
    <ota>
        <header>
            <type>sota</type>
            <repo>remote</repo>
        </header>
        <type>
            <sota>
                <fetch>https://yoururl/mender.file</fetch>
                <username>user</username>
                <password>pwd</password>
                <cmd logtofile="Y">update</cmd>
                <release-date>2020-01-01</release_date>
            </sota>
        </type>
    </ota>
</manifest>
```

### Sample SOTA Manifest - Target specific Intel Vision cards: 

- Specific targets identified in <targets></targets> section.

- The Vision-agent will double-check to ensure that the targets are eligible for the upgrade.

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest>
    <type>ota</type>
    <ota>
        <header>
            <type>sota</type>
            <repo>remote</repo>
        </header>
        <type>
            <sota>
                <cmd logtofile="Y">update</cmd>
                <fetch>https://yoururl/mender.file</fetch>
                <username>user</username>
                <password>pwd</password>
                <targetType>node</targetType>
                <targets>
                    <target>000732767ffb-16781312</target>
                    <target>000732767ffb-16780544</target>
                </targets>
                <release-date>2020-0101</release_date>
            </sota>
        </type>
    </ota>
</manifest>
```

### Sample SOTA Manifest - Target all eligible Intel Vision cards: 

- No <targets></targets> section included.
- The Vision-agent will determine which Vision cards are eligible for the upgrade based on its internal registry.  It will compare the release-date in this manifest with the release date of each vision card in its registry.

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest>
    <type>ota</type>
    <ota>
        <header>
            <type>sota</type>
            <repo>remote</repo>
        </header>
        <type>
            <sota>
                <cmd logtofile="Y">update</cmd>
                <fetch>https://yoururl/mender.file</fetch>
                <username>user</username>
                <password>pwd</password>
                <targetType>node</targetType>
                <release-date>2020-0101</release_date>
            </sota>
        </type>
    </ota>
</manifest>
```

## POTA
The POTA manifest is used to perform both a FOTA and SOTA update at the same time to avoid conflicts when trying to update them individually.  This manifest combines both the FOTA and SOTA into one.

### POTA Manifest Parameters
| Tag                                      | Example                                                         | Required/Optional | Notes                                                                                           |
|:-----------------------------------------|:----------------------------------------------------------------|:-----------------:|:------------------------------------------------------------------------------------------------|
| `<?xml version='1.0' encoding='utf-8'?>` | `<?xml version='1.0' encoding='utf-8'?>`                        |         R         |                                                                                                 |
| `<manifest>`                             | `<manifest>`                                                    |         R         |                                                                                                 |
| `<type></type>`                          | `<type>ota</type>`                                              |         R         | Always 'ota'                                                                                    |
| `<ota>`                                  | `<ota>`                                                         |         R         |                                                                                                 |
| `<header>`                               | `<header>`                                                      |         R         |                                                                                                 |
| `<id></id>`                              | `<id>yourid</id>`                                               |         O         |                                                                                                 |
| `<name></name>`                          | `<name>SampleAOTA</name>`                                       |         O         |                                                                                                 |
| `<description></description>`            | `<description>Yourdescription</description>`                    |         O         |                                                                                                 |
| `<type></type>`                          | `<type>aota</type>`                                             |         R         | Always 'aota'                                                                                   |
| `<repo></repo>`                          | `<repo>remote</repo>`                                           |         R         | 'remote' or 'local'                                                                             |
| `</header>`                              | `</header>`                                                     |         R         |                                                                                                 |
| `<type>`                                 | `<type>`                                                        |         R         |                                                                                                 |
| `<pota>`                                 | `<pota>`                                                        |         R         ||
| `<targetType></targetType>`              | `<targetType>node</targetType>`                                 |         O         | [host or node] Used when updating either the host of vision cards (host) or vision cards (node) |
| `<targets></targets>`                    | `<targets><target>389C0A</target></targets>`                    |         O         | Used when targetType=node.  Designates the Ids of the nodes to update                           |
| `<fota name=''>`                         | `<fota name='text'>`                                            |         R         | Text must be compliant with XML Standards                                                       |
| `<fetch></fetch>`                        | `<fetch>http://yoururl:80/BIOSUPDATE.tar</fetch>`               |         R         | FOTA path created in repository                                                                 |
| `<targetType></targetType>`              | `<targetType>node</targetType>`                                 |         O         | [host or node] Used when updating either the host of vision cards (host) or vision cards (node) |
| `<targets></targets>`                    | `<targets><targets><target>389C0A</target></targets></targets>` |         O         | Used when targetType=node.  Designates the Ids of the nodes to update                           |
| `<signature></signature>`                | `<signature>ABC123</signature>`                                 |         O         | Digital signature of *.tar file.                                                                |
| `<biosversion></biosversion>`            | `<biosversion>A..ZZZZ.B11.1</biosversion>`                      |         R         | Verify with BIOS Vendor (IBV)                                                                   |
| `<vendor></vendor>`                      | `<vendor>VendorName</vendor>`                                   |         R         | Verify with BIOS Vendor (IBV)                                                                   |
| `<manufacturer></manufacturer>`          | `<manufacturer>BIOS_Manufacturer</manufacturer>`                |         R         | In Release Notes supplied by BIOS vendor                                                        |
| `<product></product>`                    | `<product>BIOS_Product</product>`                               |         R         | Product Name set by Manufacturer                                                                |
| `<releasedate></releasedate>`            | `<releasedate>2021-06-23</releasedate>`                         |         R         | Verify with BIOS Vendor (IBV)                                                                   |
| `<tooloptions></tooloptions>`            | `<tooloptions>p/b/n</tooloptions>`                              |         O         | Verify with BIOS Vendor (IBV)                                                                   |
| `<guid></guid>`                          | `<guid>7acbd1a5a-33a4-48c3ab11-a4c33b3d0e56</guid>`             |         O         | Check for ‘System Firmware Type’ on running cmd:fwupdate -l                                     |
| `<username></username>`                  | `<username>user</username>`                                     |         O         | Username used during fetch from remote repository                                               |
| `<password><password>`                   | `<password>pwd</password>`                                      |         O         | Password used during fetch from remote repository                                               |
| `<path></path>`                          | `<path></path>`                                                 |         R         ||
| `</fota>`                                | `</fota>`                                                       |         R         ||
| `<sota>`                                 | `<sota>`                                                        |         R         ||
| `<cmd></cmd>`                            | `<cmd logtofile=”Y”>update</cmd>`                               |         R         ||
| `<targetType></targetType>`              | `<targetType>node</targetType>`                                 |         O         | [host or node] Used when updating either the host of vision cards (host) or vision cards (node) |
| `<targets></targets>`                    | `<targets><targets><target>389C0A</target></targets></targets>` |         O         | Used when targetType=node.  Designates the Ids of the nodes to update                           |
| `<fetch></fetch>`                        | `<fetch>https://yoururl/file.mender</fetch>`                    |         O         | Used to download mender file from remote repository. (use repo=remote)                          |
| `<path></path>`                          | `<path>/var/cache/file.mender</path>`                           |         O         | Used to update using a local mender file  .  (use repo=local)                                   |
| `<username></username>`                  | `<username>xx</username>`                                       |         O         | Username for remote repository                                                                  |                                                                 |
| `<password></password>`                  | `<password>xxx</password>`                                      |         O         | Password for remote repository                                                                  |                                                                 |
| `<release_date></release_ date>`         | `<release_date>2020-01-01</release_date>`                       |         R         | The release date provided should be in ‘YYYY-MM-DD’ format.                                     |
| `</sota>`                                | `</sota>`                                                       |         R         ||
| `</pota>`                                | `</pota>`                                                       |         R         ||
| `</type>`                                | `</type>`                                                       |         R         |                                                                                                 |
| `</ota>`                                 | `</ota>`                                                        |         R         |                                                                                                 |
| `</manifest>`                            | `</manifest>`                                                   |         R         |                                                                                                 |

### POTA Example Manifest - Targets not specified
```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest>
   <type>ota</type>
   <ota> 
      <header>
         <type>pota</type>
         <repo>remote</repo>
      </header>
      <type>
         <pota>
            <targetType>node</targetType>
            <fota name="sample">
               <fetch>https://yoururl/fip-hddl2.bin</fetch>
               <biosversion>5.12</biosversion>
               <manufacturer>intel</manufacturer>
               <product>kmb-hddl2</product>
               <vendor>Intel</vendor>
               <releasedate>2021-02-08</releasedate>
            </fota>
            <sota>
               <cmd logtofile="y">update</cmd>
               <fetch>https://yoururl/core-image-minimal-keembay-20201028223515.dm-verity.mender</fetch>
               <release_date>2021-10-10</release_date>
            </sota>
         </pota>
      </type>
   </ota>
</manifest>
```

### POTA Example Manifest - Targets specified
```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest>
   <type>ota</type>
   <ota> 
      <header>
         <type>pota</type>
         <repo>remote</repo>
      </header>
      <type>
         <pota>
            <targetType>node</targetType>
            <targets>
               <target>000732767ffb-16781312</target>
                <target>000732767ffb-16780544</target>
            </targets>
            <fota name="sample">
               <fetch>https://yoururl/fip-hddl2.bin</fetch>
               <biosversion>5.12</biosversion>
               <manufacturer>intel</manufacturer>
               <product>kmb-hddl2</product>
               <vendor>Intel</vendor>
               <releasedate>2021-02-08</releasedate>
            </fota>
            <sota>
               <cmd logtofile="y">update</cmd>
               <fetch>https://yoururl/core-image-minimal-keembay-20201028223515.dm-verity.mender</fetch>
               <release_date>2021-10-10</release_date>
            </sota>
         </pota>
      </type>
   </ota>
</manifest>
```

## AOTA

### AOTA Manifest Parameters
| Tag                                      | Example                                                  | Required/Optional | Notes                                                                               |
|:-----------------------------------------|:---------------------------------------------------------|:-----------------:|:------------------------------------------------------------------------------------|
| `<?xml version='1.0' encoding='utf-8'?>` | `<?xml version='1.0' encoding='utf-8'?>`                 |         R         |                                                                                     |
| `<manifest>`                             | `<manifest>`                                             |         R         |                                                                                     |
| `<type></type>`                          | `<type>ota</type>`                                       |         R         | Always 'ota'                                                                        |
| `<ota>`                                  | `<ota>`                                                  |         R         |                                                                                     |
| `<header>`                               | `<header>`                                               |         R         |                                                                                     |
| `<id></id>`                              | `<id>yourid</id>`                                        |         O         |                                                                                     |
| `<name></name>`                          | `<name>SampleAOTA</name>`                                |         O         |                                                                                     |
| `<description></description>`            | `<description>Yourdescription</description>`             |         O         |                                                                                     |
| `<type></type>`                          | `<type>aota</type>`                                      |         R         | Always 'aota'                                                                       |
| `<repo></repo>`                          | `<repo>remote</repo>`                                    |         R         | 'remote' or 'local'                                                                 |
| `</header>`                              | `</header>`                                              |         R         |                                                                                     |
| `<type>`                                 | `<type>`                                                 |         R         |                                                                                     |
| `<aota name="">`                         | `<aota name=”text”>`                                     |         R         | Text must follow XML standards                                                      |
| `<cmd></cmd>`                            | `<cmd>up</cmd>`                                          |         R         | Valid values: [down, import, list, load, pull, remove, stats, up, update]           |
| `<app></app>`                            | `<app>docker</app>`                                      |         R         | Valid values: [application, btrfs, compose, docker]                                 |
| `<fetch></fetch>`                        | `<fetch>http://server name/AOTA/container.tar.gz<fetch>` |         R         | Trusted repo + name of package                                                      |
| `<file></file>`                          | `<file>custom.yml</file>`                                |         O         | Name of custom YAML file to use with docker-compose                                 |
| `<version></version>`                    | `<version>0.7.6</version>`                               |         O         | Update Package version.                                                             |
| `<signature></signature`>                | `<signature>96e92d</signature>`                          |         O         | Signature of package–signed checksum of package.  Recommended for security purposes |
| `<containerTag></containerTag>`          | `<containerTag>Modbusservice</containerTag>`             |         R         | Name of container image                                                             |
| `<deviceReboot></deviceReboot>`          | `<deviceReboot>yes</deviceReboot>`                       |         O         | [yes or no] Used by application update.  If yes, reboot system after update.        |
| `<username></username>`                  | `<username>user</username>`                              |         O         | Username credentials of the server where the package is hosted for downloads        |
| `<password></password>`                  | `<password>pwd</password>`                               |         O         | Password credentials of the server where the package is hosted for downloads        |
| `<dockerUsername></dockerUsername>`      | `<dockerUsername>usr</dockerUsername>`                   |         O         | Docker Username credentials of the private registry where docker images reside      |
| `<dockerPassword></dockerPassword>`      | `<dockerPassword>pwd</dockerPassword>`                   |         O         | Docker password credentials of the private registry where docker images reside      |
| `<dockerRegistry></dockerRegistry>`      | `<dockerRegistry>hub.intel.docker.com</dockerRegistry>`  |         O         | Used for Docker commands.                                                           |Docker registry URL of any private registry where the required docker images reside. |
| `</type>`                                | `</type>`                                                |         R         |                                                                                     |
| `</ota>`                                 | `</ota>`                                                 |         R         |                                                                                     |
| `</manifest>`                            | `</manifest>`                                            |         R         |                                                                                     |

### Docker manifest examples

#### Example of docker image import manifest 
```xml
<?xml version='1.0' encoding='utf-8'?>
<manifest>
    <type>ota</type>
    <ota>
        <header>
            <type>aota</type>
            <repo>remote</repo>
        </header>
        <type>
            <aota name='samplerpm'>
                <cmd>import</cmd>
                <app>docker</app>
                <fetch>yoururl/hdcrpmlite.tgz</fetch>
                <version>1.0</version>
                <containerTag>hdcrpmlite:1</containerTag>
            </aota>
        </type>
    </ota>
</manifest>
```

####  Example of docker image load manifest 
```xml
<?xml version='1.0' encoding='utf-8'?>
<manifest>
    <type>ota</type>
    <ota>
        <header>
            <type>aota</type>
            <repo>remote</repo>
        </header>
        <type>
            <aota name='samplerpm'>
                <cmd>load</cmd>
                <app>docker</app>
                <fetch>yoururl/coffee.tgz</fetch>
                <version>1.0</version>
                <containerTag>coffee</containerTag>
            </aota>
        </type>
    </ota>
</manifest>
```

####  Example of docker pull manifest 
```xml
<?xml version='1.0' encoding='utf-8'?>
<manifest>
    <type>ota</type>
    <ota>
        <header>
            <type>aota</type>
            <repo>remote</repo>
        </header>
        <type>
            <aota name='modbusservice'>
                <cmd>pull</cmd>
                <app>docker</app>
                <version>1.0</version>
                <containerTag>hello-world</containerTag>
            </aota>
        </type>
    </ota>
</manifest>
```

####  Example of docker remove manifest 
```xml
<?xml version='1.0' encoding='utf-8'?>
<manifest>
    <type>ota</type>
	<ota>
        <header>
            <type>aota</type>
            <repo>remote</repo>
        </header>
        <type>
            <aota name='modbusservice'>
                <cmd>remove</cmd>
                <app>docker</app>
                <version>1.0</version>
                <containerTag>hello-world</containerTag>
            </aota>
        </type>
    </ota>
</manifest>
```

####  Example of docker stats manifest 
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest>
    <type>ota</type>
    <ota>
        <header>
            <type>aota</type>
            <repo>remote</repo>
        </header>
        <type>
            <aota>name="sample-rpm">
                <cmd>stats</cmd>
                <app>docker</app>
            </aota>
        </type>
    </ota>
</manifest>
```
#### Docker-Compose Manifest Examples

#### Example of docker-compose up manifest 
```xml
<?xml version='1.0' encoding='utf-8'?>
<manifest>
    <type>ota</type>
    <ota>
        <header>
            <type>aota</type>
            <repo>remote</repo>
        </header>
        <type>
            <aota name='samplerpm'>
                <cmd>up</cmd>
                <app>compose</app>
                <fetch>yoururl/simplecompose.tar.gz</fetch>
                <version>2.0</version>
                <containerTag>simplecompose</containerTag>
            </aota>
        </type>
    </ota>
</manifest>
```

#### Example of ‘docker-compose -f <custom.yml> up’ manifest 
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest>
    <type>ota</type>
    <ota>
        <header>
            <type>aota</type>
            <repo>remote</repo>
        </header>
        <type>
            <aota name="samplerpm">
                <cmd>up</cmd>
                <app>compose</app>
                <fetch>yoururl/simplecompose.tar.gz</fetch>
                <file>custom.yml</file>
                <containerTag>simplecompose</containerTag>
                <username>username</username>
                <password>XXXXX</password>
            </aota>
        </type>
    </ota>
</manifest>
```

#### Example of docker-compose down manifest 
```xml
<?xml version='1.0' encoding='utf-8'?>
<manifest>
    <type>ota</type>
    <ota>
        <header>
            <type>aota</type>
            <repo>remote</repo>
        </header>
        <type>
            <aota name='modbusservice'>
                <cmd>down</cmd>
                <app>compose</app>
                <fetch>yoururl/modbusservice.tar.gz</fetch>
                <version>1.0</version>
                <containerTag>modbusservice</containerTag>
            </aota>
        </type>
    </ota>
</manifest>
```

#### Example of ‘docker-compose -f <custom.yml> down’ manifest 
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest>
    <type>ota</type>
    <ota>
        <header>
            <type>aota</type>
            <repo>remote</repo>
        </header>
        <type>
            <aota name="samplerpm">
                <cmd>down</cmd>
                <app>compose</app>
                <file>custom.yml</file>
                <containerTag>simple-compose</containerTag>
            </aota>
        </type>
    </ota>
</manifest>
```

#### Example of docker-compose pull manifest 
```xml
<?xml version='1.0' encoding='utf-8'?>
<manifest>
    <type>ota</type>
    <ota>
        <header>
            <type>aota</type>
            <repo>remote</repo>
        </header>
        <type>
            <aota name='sample-docker-compose-up'>
                <cmd>pull</cmd>
                <app>compose</app>
                <fetch>yoururl/simple-compose.tar.gz</fetch>
                <version>1.0</version>
                <containerTag>simplecompose</containerTag>
            </aota>
        </type>
    </ota>
</manifest>
```

#### Example of ‘docker-compose -f <custom.yml> pull’ manifest 
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest>
    <type>ota</type>
    <ota>
        <header>
            <type>aota</type>
            <repo>remote</repo>
        </header>
        <type>
            <aota name="samplerpm">
                <cmd>pull</cmd>
                <app>compose</app>
                <fetch>yoururl/simplecompose.tar.gz</fetch>
                <file>custom.yml</file>
                <containerTag>simplecompose</containerTag>
                <username>username</username>
                <password>XXXXX</password>
            </aota>
        </type>
    </ota>
</manifest>
```

#### Example of docker-compose list manifest 
```xml
<?xml version='1.0' encoding='utf-8'?>
<manifest>
    <type>ota</type>
    <ota>
        <header>
            <type>aota</type>
            <repo>remote</repo>
        </header>
        <type>
            <aota name='sample-docker-composeup'>
                <cmd>list</cmd>
                <app>compose</app>
                <containerTag>simplecompose</containerTag>
            </aota>
        </type>
    </ota>
</manifest>
```

#### Example of docker-compose remove manifest 
```xml
<?xml version='1.0' encoding='utf-8'?>
<manifest>
    <type>ota</type>
    <ota>
        <header>
            <type>aota</type>
            <repo>remote</repo>
        </header>
        <type>
            <aota name='sample-docker-composeremove'>
                <cmd>remove</cmd>
                <app>compose</app>
                <version>1.0</version>
                <containerTag>simple-compose</containerTag>
            </aota>
        </type>
    </ota>
</manifest>
```

## Query

### Query Manifest Parameters 

The query command can be used to gather information about the system and the Vision cards.

| XML Tags                                 | Definition             | Required/Optional | Notes                  |
|:-----------------------------------------|:-----------------------|:-----------------:|:-----------------------|
| `<?xml version='1.0' encoding='utf-8'?>` |                        |         R         |                        |
| `<manifest>`                             | `<manifest>`           |         R         ||
| `<type><type>`                           | `<type>cmd</type>`     |         R         | will always be 'cmd'   |
| `<cmd></cmd>`                            | `<cmd>query</cmd>`     |         R         | will always be 'query' |
| `<query>`                                | `<query>`              |         R         |                        |
| `<option></option>`                      | `<option>all</option>` |         R         | [optional type]()      |
| `</query>`                               | `</query>`             |         R         |                        |
| `</manifest>`                            | `</manifest>`          |         R         |                        |


#### Example of swbom query manifest examples
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest>
    <type>cmd\</type>
    <cmd>query</cmd>
    <query>
        <option>swbom</option>
    </query>
</manifest>
```

#### Example of hw query manifest 
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest>
    <type>cmd</type>
    <cmd>query</cmd>
    <query>
        <option>hw</option>
    </query>
</manifest>
```

#### Example of fw query manifest 
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest>
    <type>cmd</type>
    <cmd>query</cmd>
    <query>
        <option>fw</option>
    </query>
</manifest>
```

#### Example of os query manifest 
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest>
    <type>cmd</type>
    <cmd>query</cmd>
    <query>
        <option>os</option>
    </query>
</manifest>
```

#### Example of version query manifest 
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest>
    <type>cmd</type>
    <cmd>query</cmd>
    <query>
        <option>version</option>
    </query>
</manifest>
```

#### Example of all query manifest 
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest>
    <type>cmd</type>
    <cmd>query</cmd>
    <query>
        <option>all</option>
    </query>
</manifest>
```


## Configuration Settings

On an Edge device there will be only one configuration file that this command can target; therefore you will not need to use the <targetType> and <targets> tags in the chart below.

On an Intel Vision card solution, there will be 2 configuration files on the host and 2 configuration files on each node that can be targeted by the Get, Set, and Load commands.  
The '_Append_' and '_Remove_' commands only supported on the Host agents (not vision).

| \<TargetType> | System |                             Agent(s)                              |
|:--------------|:-------|:-----------------------------------------------------------------:|
| None          | Host   | INB = Dispatcher, Telemetry, Configuration, and Diagnostic agents |
| vision        | Host   |                           Vision-agent                            |
| node          | Node   |                            Node-agent                             |
| node_client   | Node   | INB = Dispatcher, Telemetry, Configuration, and Diagnostic agents |

### Get

#### Get Configuration Manifest Parameters
| Tag                                      | Example                                      | Required/Optional | Notes                                                                                                           |
|:-----------------------------------------|:---------------------------------------------|:-----------------:|:----------------------------------------------------------------------------------------------------------------|
| `<?xml version='1.0' encoding='utf-8'?>` | `<?xml version='1.0' encoding='utf-8'?>`     |         R         |                                                                                                                 |
| `<manifest>`                             | `<manifest>`                                 |         R         |                                                                                                                 |
| `<type></type>`                          | `<type>config</type>`                        |         R         | Always 'config'                                                                                                 |
| `<config>`                               | `<config>`                                   |         R         |                                                                                                                 |
| `<cmd></cmd>`                            | `<cmd>get_elemeent</cmd>`                    |         R         |                                                                                                                 |
| `<targetType></targetType>`              | `<targetType>node</targetType>`              |         O         | [vision, node, or node_client] Used when updating either the host of vision cards (host) or vision cards (node) |
| `<configtype>`                           | `<configtype>`                               |         R         |                                                                                                                 |
| `<targets></targets>`                    | `<targets><target>389C0A</target></targets>` |         O         | Used when targetType=node or node_client.  Designates the Ids of the nodes to update                            |
| `<get>`                                  | `<get>`                                      |         R         |                                                                                                                 |
| `<path></path>`                          | `<path>minStorageMB;minMemoryMB</path>`      |         R         |                                                                                                                 |
| `</get>`                                 | `</get>`                                     |         R         |                                                                                                                 |
| `</configtype>`                          | `</configtype>`                              |         R         |                                                                                                                 |
| `</config>`                              | `</config`                                   |         R         |                                                                                                                 |
| `</manifest>`                            | `</manifest>`                                |         R         |                                                                                                                 |

#### Get Configuration Examples 
-   To set one value: **minStorageMB**
-   To set multiple values at once: **minStorageMB;minMemoryMB**

* Path takes in keys as an input, with key as the configuration
    parameter tag, where the value needs to be retrieved. To retrieve
    multiple values at once, use ‘**;**’ to separate one tag from
    another as shown above.

##### Get Example on Host INB agents
```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest>
    <type>config</type>
    <config>
        <cmd>get_element</cmd>
        <configtype>
            <get>
                <path>minStorageMB;minMemoryMB</path>
            </get>
        </configtype>
    </config>
</manifest>
```

##### Get Example on Vision-agent
```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest>
    <type>config</type>
    <config>
        <cmd>get_element</cmd>
        <targetType>vision</targetType>
        <configtype>
            <get>
                <path>isAliveTimerSecs;heartbeatRetryLimit</path>
            </get>
        </configtype>
    </config>
</manifest>
```

##### Get Example on **ALL** Node-agents
```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest>
    <type>config</type>
    <config>
        <cmd>get_element</cmd>
        <targetType>node</targetType>
        <configtype>
            <get>
                <path>isAliveTimerSecs;heartbeatRetryLimit</path>
            </get>
        </configtype>
    </config>
</manifest>
```

##### Get Example on **SPECIFIC** Node-agents
```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest>
    <type>config</type>
    <config>
        <cmd>get_element</cmd>
        <targetType>node</targetType>
        <configtype>
            <targets>
                <target>000732767ffb-16781312</target>
                <target>000732767ffb-16780544</target>
            </targets>
            <get>
                <path>isAliveTimerSecs;heartbeatRetryLimit</path>
            </get>
        </configtype>
    </config>
</manifest>
```

#### Get Example on **ALL** INB Nodes
```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest>
    <type>config</type>
    <config>
        <cmd>get_element</cmd>
        <targetType>node_client</targetType>
        <configtype>
            <get>
                <path>isAliveTimerSecs;heartbeatRetryLimit</path>
            </get>
        </configtype>
    </config>
</manifest>
```

#### Get Example on **SPECIFIC** INB Nodes
```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest>
    <type>config</type>
    <config>
        <cmd>get_element</cmd>
        <targetType>node_client</targetType>
        <configtype>
            <targets>
                <target>000732767ffb-16781312</target>
                <target>000732767ffb-16780544</target>
            </targets>
            <get>
                <path>minStorageMB;minMemoryMB</path>
            </get>
        </configtype>
    </config>
</manifest>
```

## Set

#### Configuration Set Manifest Parameters
| Tag                                      | Example                                         | Required/Optional | Notes                                                                                                           |
|:-----------------------------------------|:------------------------------------------------|:-----------------:|:----------------------------------------------------------------------------------------------------------------|
| `<?xml version='1.0' encoding='utf-8'?>` | `<?xml version='1.0' encoding='utf-8'?>`        |         R         |                                                                                                                 |
| `<manifest>`                             | `<manifest>`                                    |         R         |                                                                                                                 |
| `<type></type>`                          | `<type>config</type>`                           |         R         | Always 'config'                                                                                                 |
| `<config>`                               | `<config>`                                      |         R         |                                                                                                                 |
| `<cmd></cmd>`                            | `<cmd>set_elemeent</cmd>`                       |         R         |                                                                                                                 |
| `<targetType></targetType>`              | `<targetType>node</targetType>`                 |         O         | [vision, node, or node_client] Used when updating either the host of vision cards (host) or vision cards (node) |
| `<configtype>`                           | `<configtype>`                                  |         R         |                                                                                                                 |
| `<targets></targets>`                    | `<targets><target>389C0A</target></targets>`    |         O         | Used when targetType=node or node_client.  Designates the Ids of the nodes to update                            |
| `<set>`                                  | `<set>`                                         |         R         |                                                                                                                 |
| `<path></path>`                          | `<path>minStorageMB:100;minMemoryMB:200</path>` |         R         |                                                                                                                 |
| `</set>`                                 | `</set>`                                        |         R         |                                                                                                                 |
| `</configtype>`                          | `</configtype>`                                 |         R         |                                                                                                                 |
| `</config>`                              | `</config>`                                     |         R         |                                                                                                                 |
| `</manifest>`                            | `</manifest>`                                   |         R         |                                                                                                                 |

#### Set Examples 
-   To set one value: minStorageMB:100
-   To set multiple values at once: minStorageMB:100;minMemoryMB:200
* Path takes in key value pairs as an input, with key as the
    configuration parameter tag and value to be set as the value. To set
    multiple key:value pairs, use “**;**” to separate one pair from
    another as shown in the example above.

##### Set Example on Host INB agents
```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest>
    <type>config</type>
    <config>
        <cmd>set_element</cmd>
        <configtype>
            <set>
                <path>minStorageMB:100;minMemoryMB:200</path>
            </set>
        </configtype>
    </config>
</manifest>
```

##### Set Example on Vision-agent
```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest>
    <type>config</type>
    <config>
        <cmd>set_element</cmd>
        <targetType>vision</targetType>
        <configtype>
            <set>
                <path>isAliveTimerSecs:100;heartbeatRetryLimit:3</path>
            </set>
        </configtype>
    </config>
</manifest>
```

##### Example Configuration SET on **ALL** Node-agents
```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest>
    <type>config</type>
    <config>
        <cmd>set_element</cmd>
        <targetType>node</targetType>
        <configtype>
            <set>
                <path>heartbeatResponseTimerSecs:350;registrationRetryLimit:7</path>
            </set>
        </configtype>
    </config>
</manifest>
```

##### Set Example on **SPECIFIC** Node-agents
```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest>
    <type>config</type>
    <config>
        <cmd>set_element</cmd>
        <targetType>node</targetType>
        <configtype>
            <targets>
                <target>000732767ffb-16781312</target>
                <target>000732767ffb-16780544</target>
            </targets>
            <set>
                <path>heartbeatResponseTimerSecs:350;registrationRetryLimit:7</path>
            </set>
        </configtype>
    </config>
</manifest>
```

#### Set Example on **ALL** INB Nodes
```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest>
    <type>config</type>
    <config>
        <cmd>set_element</cmd>
        <targetType>node_client</targetType>
        <configtype>
            <set>
                <path>minStorageMB:100;minMemoryMB:200</path>
            </set>
        </configtype>
    </config>
</manifest>
```

#### Set Example on **SPECIFIC** INB Nodes
```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest>
    <type>config</type>
    <config>
        <cmd>set_element</cmd>
        <targetType>node_client</targetType>
        <configtype>
            <targets>
                <target>000732767ffb-16781312</target>
                <target>000732767ffb-16780544</target>
            </targets>
            <set>
                <path>minStorageMB:100;minMemoryMB:200</path>
            </set>
        </configtype>
    </config>
</manifest>
```

## Load

#### Configuration LOAD Manifest Parameters
| Tag                                      | Example                                                       | Required/Optional | Notes           |
|:-----------------------------------------|:--------------------------------------------------------------|:-----------------:|:----------------|
| `<?xml version='1.0' encoding='utf-8'?>` | `<?xml version='1.0' encoding='utf-8'?>`                      |         R         |                 |
| `<manifest>`                             | `<manifest>`                                                  |         R         |                 |
| `<type></type>`                          | `<type>config</type>`                                         |         R         | Always 'config' |
| `<config>`                               | `<ota>`                                                       |         R         |                 |
| `<cmd></cmd>`                            | `<cmd>load</cmd>`                                             |         R         |                 |
| `<configtype>`                           | `<configtype>`                                                |         R         |                 |
| `<load>`                                 | `<load>`                                                      |         R         |                 |
| `<fetch></fetch>`                        | `<fetch>http://yoururl:port/intel_manageability.conf</fetch>` |         R         |                 |
| `</load>`                                | `</load>`                                                     |         R         |                 |
| `</configtype>`                          | `</configtype>`                                               |         R         |                 |
| `</config>`                              | `</config>`                                                   |         R         |                 |
| `</manifest>`                            | `</manifest>`                                                 |         R         |                 |


* The configuration file you provide in Fetch needs to be named *intel_manageability.conf*. If you wish to send with
    signature; then TAR both the PEM file and the *intel_manageability.conf* in a TAR file.

##### Load Example on Host INB agents
```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest>
    <type>config</type>
    <config>
        <cmd>load</cmd>
        <configtype>
            <load>
                <fetch>http://yoururl:port/intel_manageability.conf</fetch>
            </load>
        </configtype>
    </config>
</manifest>
```

##### Load Example on Vision-agent
```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest>
    <type>config</type>
    <config>
        <cmd>load</cmd>
        <targetType>vision</targetType>
        <configtype>
            <load>
                <fetch>http://yoururl:port/intel_manageabilty_vision.conf</fetch>
            </load>
        </configtype>
    </config>
</manifest>
```

##### Load Example on **ALL** Node-agents
```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest>
    <type>config</type>
    <config>
        <cmd>load</cmd>
        <targetType>node</targetType>
        <configtype>
            <load>
                <fetch>http://yoururl:port/intel_manageabilty_node.conf</fetch>
            </load>
        </configtype>
    </config>
</manifest>
```

##### Load Example on **SPECIFIC** Node-agents
```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest>
    <type>config</type>
    <config>
        <cmd>load</cmd>
        <targetType>node</targetType>
        <configtype>
            <targets>
                <target>000732767ffb-16781312</target>
                <target>000732767ffb-16780544</target>
            </targets>
            <load>
                <fetch>http://yoururl:port/intel_manageabilty_node.conf</fetch>
            </load>
        </configtype>
    </config>
</manifest>
```

#### Load Example on **ALL** INB Nodes
```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest>
    <type>config</type>
    <config>
        <cmd>load</cmd>
        <targetType>node_client</targetType>
        <configtype>
            <load>
                <fetch>http://yoururl:port/intel_manageabilty.conf</fetch>
            </load>
        </configtype>
    </config>
</manifest>
```

#### Load Example on **SPECIFIC** INB Nodes
```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest>
    <type>config</type>
    <config>
        <cmd>load</cmd>
        <targetType>node_client</targetType>
        <configtype>
            <targets>
                <target>000732767ffb-16781312</target>
                <target>000732767ffb-16780544</target>
            </targets>
            <load>
                <fetch>http://yoururl:port/intel_manageabilty.conf</fetch>
            </load>
        </configtype>
    </config>
</manifest>
```


## Append

#### Configuration Append Manifest Parameters
| Tag                                      | Example                                         | Required/Optional | Notes           |
|:-----------------------------------------|:------------------------------------------------|:-----------------:|:----------------|
| `<?xml version='1.0' encoding='utf-8'?>` | `<?xml version='1.0' encoding='utf-8'?>`        |         R         |                 |
| `<manifest>`                             | `<manifest>`                                    |         R         |                 |
| `<type></type>`                          | `<type>config</type>`                           |         R         | Always 'config' |
| `<config>`                               | `<config>`                                      |         R         |                 |
| `<cmd></cmd>`                            | `<cmd>append</cmd>`                             |         R         |                 |
| `<configtype>`                           | `<configtype>`                                  |         R         |                 |
| `<append>`                               | `<append>`                                      |         R         |                 |
| `<path></path>`                          | `<path>minStorageMB:100;minMemoryMB:200</path>` |         R         |                 |
| `</append>`                              | `</append>`                                     |         R         |                 |
| `</configtype>`                          | `</configtype>`                                 |         R         |                 |
| `</config>`                              | `</config`                                      |         R         |                 |
| `</manifest>`                            | `</manifest>`                                   |         R         |                 |

#### Append Example

* Append can currently only be used on INB agents in either the Edge or Vision card solution.
* Append is only applicable to three configuration tags, for example,
    **trustedRepositories**, **sotaSW** and **ubuntuAptSource**
* Path takes in key value pair format, example: trustedRepositories:  https://dummyURL.com
```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest>
    <type>config</type>
    <config>
        <cmd>append</cmd>
        <configtype>
            <append>
                <path>trustedRepositories:https://dummyURL.com</path>
            </append>
        </configtype>
    </config>
</manifest>
```

## Remove

#### Configuration Remove Manifest Parameters
| Tag                                      | Example                                         | Required/Optional | Notes           |
|:-----------------------------------------|:------------------------------------------------|:-----------------:|:----------------|
| `<?xml version='1.0' encoding='utf-8'?>` | `<?xml version='1.0' encoding='utf-8'?>`        |         R         |                 |
| `<manifest>`                             | `<manifest>`                                    |         R         |                 |
| `<type></type>`                          | `<type>config</type>`                           |         R         | Always 'config' |
| `<config>`                               | `<config>`                                      |         R         |                 |
| `<cmd></cmd>`                            | `<cmd>remove</cmd>`                             |         R         |                 |
| `<configtype>`                           | `<configtype>`                                  |         R         |                 |
| `<remove>`                               | `<remove>`                                      |         R         |                 |
| `<path></path>`                          | `<path>minStorageMB:100;minMemoryMB:200</path>` |         R         |                 |
| `</remove>`                              | `</remove>`                                     |         R         |                 |
| `</configtype>`                          | `</configtype>`                                 |         R         |                 |
| `</config>`                              | `</config>`                                     |         R         |                 |
| `</manifest>`                            | `</manifest>`                                   |         R         |                 |

#### Remove Example
* Append can currently only be used on INB agents in either the Edge or Vision card solution.
* *Remove* is only applicable to three configuration tags, for
    example, **trustedRepositories**, **sotaSW** and
    **ubuntuAptSource**.
* Path takes in key value pair format, example: trustedRepositories:https://dummyURL.com

```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest>
    <type>config</type>
    <config>
        <cmd>remove</cmd>
        <configtype>
            <remove>
                <path>trustedRepositories:https://dummyURL.com</path>
            </remove>
        </configtype>
    </config>
</manifest>
```

## Provision Node

Provision Node is only used by the INBM Vision solution to provision a flashless device.

#### Configuration Provision Node Manifest Parameters
| Tag                                      | Example                                             | Required/Optional | Notes                                                                               |
|:-----------------------------------------|:----------------------------------------------------|:-----------------:|:------------------------------------------------------------------------------------|
| `<?xml version='1.0' encoding='utf-8'?>` | `<?xml version='1.0' encoding='utf-8'?>`            |         R         |                                                                                     |
| `<manifest>`                             | `<manifest>`                                        |         R         |                                                                                     |
| `<type></type>`                          | `<type>cmd</type>`                                  |         R         | Always 'cmd'                                                                        |
| `<cmd></cmd>`'`                          | `<cmd>provisionNode</cmd>`                          |         R         | Always 'provisionNode'                                                              |
| `<provisionNode>`                        | `<provisionNode>`                                   |         R         |                                                                                     |
| `<fetch></fetch>`                        | `<fetch>https://www.repo.com/provision.tar</fetch>` |         R         |                                                                                     |
| `<signature></signature`>                | `<signature>96e92d</signature>`                     |         O         | Signature of package–signed checksum of package.  Recommended for security purposes |
| `<hash_algorithm></hash_algorithm`       | `<hash_algorithm>384</hash_algorithm`               |         O         | 256 or 384 or 512                                                                   |
| `<username></username>`                  | `<username>user</username>`                         |         O         | Username used during fetch from remote repository                                   |
| `<password><password>`                   | `<password>pwd</password>`                          |         O         | Password used during fetch from remote repository                                   |
| `</provisionNode>`                       | `</provisionNode>`                                  |         R         |                                                                                     |
| `</manifest>`                            | `</manifest>`                                       |         R         |                                                                                     |

#### Provision Node Example

```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest>
	<type>cmd</type>
	<cmd>provisionNode</cmd>
	<provisionNode>
		<fetch>https://www.repo.com/provision.tar</fetch>
		<signature>signature</signature>
		<hash_algorithm>384</hash_algorithm>
	</provisionNode>
</manifest>
```
