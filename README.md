# Intel In-Band Manageability Framework (INBM)

The Intel®  In-Band Manageability Framework is software which enables an administrator to perform critical Device Management operations over-the-air remotely from the cloud. It also facilitates the publishing of telemetry and critical events and logs from an IoT device to the cloud enabling the administrator to take corrective actions if, and when necessary. The framework is designed to be modular and flexible ensuring scalability of the solution across preferred Cloud Service Providers (for example, Azure* IoT Central, ThingBoard.io, and so on).

Key advantages of the Intel® In-Band Manageability solution are:
1.  Out-of-box cloud support: Azure* IoT Central and ThingsBoard.io.   
2.  Single interface to handle OS, FW and Application (Docker container) updates.    
3.  Scalable across Intel x86 (Intel® Atom® and Intel® Core®) architectures SoCs and on Vision platforms from Intel.

Intel In-Band Manageability is capable of supporting both Edge devices and Intel Vision Cards.

<img src="docs/media/INBM Readme/media/image1.PNG" />

## Features

| INB Features                  | Description                                                                                                                                             |
|:------------------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| Application OTA               | Install / Remove Application (Native and Docker containers) </br>Integrates wrappers for Docker tools & utilities                                       |
| System OTA                    | Supports remote OS software updates, Kernel patches etc. </br> Ubuntu, Debian, Yocto project                                                            |
| Firmware OTA                  | Supports remote firmware updates. </br>UEFI, U-boot, AFULNX (AMI)                                                                                       |
| Rollback                      | Supports Auto-rollback of System Software, Containers and Firmware </br>❗Dependent on underlying OS and FW capabilities.                                |
| Security                      | Supports AppArmor profiles, TPM for key management, Signature checks for packages.  </br>Integrates Docker Bench Security for Container security checks |
| FS Snapshots                  | Support differential updates via BTRFS snapshots,  ‘A/B’ FS partition-based updates. </br>❗Dependent on underlying OS capabilities.                     |
| Device Cloud Connect          | Supports Azure IOT Central, ThingsBoard (on-premise)                                                                                                    |
| 3rd Party Repositories        | Pull packages from 3rd party repositories (e.g. ODM/IBV, Stack vendors etc., Registries (e.g. Docker registry)                                          |
| Extensible Interface          | Quick CSP Scaling possible by using Turtle Creek MQTT interfaces.                                                                                       |
| Telemetry                     | Rules based Application, System, Firmware periodic report out to device cloud services                                                                  |
| Diagnostics (System Health)   | Rules based monitoring of software operations, system health, interfaces and report out to device cloud                                                 |
| Diagnostics (Container Checks | Rules based monitoring of containers and report out to device cloud                                                                                     |

## Device Management OTA Flow

The below diagram depicts the INBM OTA uses cases and flow on both an Edge device and Intel Vision Cards.  

The flow is as follows:
1. An Administrator sends a request via the cloud.
2. A manifest is created based on the cloud request and sent to INBM.
3. Downloads any required packages from the remote repository as specified in the manifest.
4. Performs the update and sends the result back to the Administrator.

<img src="docs/media/INBM Readme/media/image2.PNG" />


## Device Management Administrator Options

INBM Device Management can be performed either via the cloud or the INBC command-line tool.

INBC on the diagram (right side) is a command line tool that can be used instead of the cloud to perform the updates. 

The below diagram also depicts where the Vision and Node agents reside and how they communicate with each other to perform the OTA update and Telemetry services.

<img src="docs/media/INBM Readme/media/image3.PNG" />


## BUILD INSTRUCTIONS

### How to build
* Prepare a Linux machine with Docker installed.  Ensure the 'm4' and 'bash' packages are also installed (these are available in all major Linux distributions).
* If you are behind a proxy, ensure your http_proxy, https_proxy, and no_proxy variables are set correctly and exported.  E.g., in bash, you could run: "http_proxy=http://foo.com:1234/ && export http_proxy"
* Optional but recommended for better build speed and caching: export DOCKER_BUILDKIT=1
* Run: ./build.sh

If you see something like 'unable to resolve' or a DNS error or 'unable to look up' near the start of the build, follow the instructions under https://docs.docker.com/install/linux/linux-postinstall/ --> "DISABLE DNSMASQ".  This can occur in some Linux distributions that put 127.0.0.1 in /etc/resolv.conf.

### Build output
* When build is complete, build output will be in the `dist` folder. 
* See `dist/README.txt` for a description of the build output.
