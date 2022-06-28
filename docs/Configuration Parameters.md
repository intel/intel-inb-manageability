# Configuration Parameters

Each of the agents has its own set of configuration key/value pairs which can be dynamically set either via the cloud, INBC, or directly in the file.  Note, that if the changes 
are made via the cloud or using INBC that the changes will be dynamic.  If they are made to the file directly, then the service will need to be restarted to pick up the changes.

## INBM Configuration

Configuration update is used to change/retrieve/append/remove configuration parameter values from the Configuration file located at
```/etc/intel_manageability.conf```. Refer to the tables below to understand the configuration key/value pairs

The below tables represent the different sections of the configuration file.

### All
| Key | Default Value | Description                                                                                    |
|:----|:-------------:|:-----------------------------------------------------------------------------------------------|
| dbs |     WARN      | How the system should be respond if there is a Docker Bench Security alert. [ON, OFF, or WARN] |

### Telemetry
| Key                            | Default Value | Description                                                                                                                              |
|:-------------------------------|:-------------:|:-----------------------------------------------------------------------------------------------------------------------------------------|
| collectionIntervalSeconds      |      60       | Time interval after which telemetry is collected from the system.                                                                        |
| publishIntervalSeconds         |      300      | Time interval after which collected telemetry is published to dispatcher and the cloud                                                   |
| maxCacheSize                   |      100      | Maximum cache set to store the telemetry data. This is the count of messages that telemetry agent caches before sending out to the cloud |
| containerHealthIntervalSeconds |      600      | Interval after which container health check is run and results are returned.                                                             |
| enableSwBom                    |     true      | Specifies if Software BOM needs to be published in the initial telemetry.                                                                |
| swBomIntervalHours             |      24       | Number of hours between swBom publish.                                                                                                   |

### Diagnostic
| Key                                |        Default Value         | Description                                                                     |
|:-----------------------------------|:----------------------------:|:--------------------------------------------------------------------------------|
| minStorageMB                       |             100              | Minimum storage that the system should have before or after an update           |
| minMemoryMB                        |              10              | Minimum memory that the system should have before or after an update            |
| minPowerPercent                    |              20              | Value of minimum battery percent that system should have before or after update |
| sotaSW                             | docker, trtl, inbm-telemetry | Mandatory software list.                                                        |
| dockerBenchSecurityIntervalSeconds |             900              | Time interval after which DBS will run and report back to the cloud.            |
| networkCheck                       |             true             | True if network connection is mandatory; otherwise, False.                      |

### Dispatcher
| Key                             | Default Value | Description                                                                        |
|:--------------------------------|:-------------:|:-----------------------------------------------------------------------------------|
| dbsRemoveImageOnFailedContainer |     false     | True if image should be removed on BSD flagged failed container; otherwise, False. |
| trustedRepositories             |               | List of trusted repositories for fetching packages                                 | 

### Orchestrator
| Key                  |             Default Value              | Description        |
|:---------------------|:--------------------------------------:|:-------------------|
| orchestratorResponse |                  true                  |                    |
| ip                   |   /etc/opt/csl/csl-node/csl-manager    | path to IP         |
| token                | /etc/opt/csl/csl-node/long-lived-token | path to token      |
| certFile             |     /etc/ssl/certs/csl-ca-cert.pem     | path the cert file |

### SOTA
| Key                    |     Default Value      | Description                                                                              |
|:-----------------------|:----------------------:|:-----------------------------------------------------------------------------------------|
| ubuntuAptSource        | http://yoururl/ubuntu/ | Location used to update Ubuntu                                                           |
| proceedWithoutRollback |          true          | Whether SOTA update should go through even when rollback is not supported on the system. |

## INBM Vision Configuration

### Vision Agent

Vision Agent configuration file is located at: ````/etc/intel-manageability/public/vision-agent/intel_manageability_vision.conf````.

The best way to update the file is either by using the cloud or INBC.

| Key                               | Default Value  | Lower Limit | Upper Limit | Description                                                                                                                                                                                 |
|:----------------------------------|:--------------:|:------------|:------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| heartbeatCheckIntervalSecs        |      300       | 10          | 1200        | Time interval for Vision agent to perform periodic heartbeat check.                                                                                                                         |
| heartbeatTransmissionIntervalSecs |       60       | 10          | 240         | Time interval for node agent to send heartbeat to the vision-agent.                                                                                                                         |
| fotaCompletionTimerSecs           |      600       | 120         | 1200        | Expiration time of a FOTA request.  The next OTA can only start once this timer has expired.                                                                                                |
| sotaCompletionTimerSecs           |      900       | 300         | 1680        | Expiration time of a SOTA request.  The next OTA can only start once this timer has expired.                                                                                                |
| potaCompletionTimerSecs           |      900       | 300         | 1680        | Expiration time of a POTA request.  The next OTA can only start once this timer has expired.                                                                                                |
| isAliveTimerSecs                  |      180       | 60          | 600         | Expiration time of 'isAlive' request.  Vision agent will  delete the node agent from it's in-memory registry if the node agent does not send back a heartbeat before the timer has expired. |
| heartbeatRetryLimit               |       3        | 2           | 15          | Number of heartbeat retries allowed before the Vision agent sends an 'isAlive' request.                                                                                                     |
| flashlessFileLocation             | /lib/firmware/ | N/A         | N/A         | Location to store the flash-less firmware image.                                                                                                                                            |
| XLinkPCIeDevID                    |       0        | N/A         | N/A         | Number used to connect the Xlink PCIe devices to the Vision agent.                                                                                                                          | 
| xlinkFirstChannel                 |      1530      | N/A         | N/A         | First channel of xlink channel range.                                                                                                                                                       |
| xlinkLastChannel                  |      1730      | N/A         | N/A         | Last channel of xlink channel range.                                                                                                                                                        |
| flashlessRollbackWaitTimeSecs     |      600       | 120         | 1200        | Time interval to wait for flashless rollback to complete.
                                                                                                         |
                                                                                                         
Note: In a Flashless System for POTA update flashlessRollbackWaitTimeSecs time supersedes potaCompletionTimerSecs.                                                                                                                                                                                  

### Node Agent

Node Agent configuration file is located at: ````/etc/intel-manageability/public/node-agent/intel_manageability_node.conf````.

The best way to update the file is either by using the cloud or INBC.

| Key                        | Default Value | Lower Limit | Upper Limit | Description                                                                                                                                                    |
|:---------------------------|:-------------:|:------------|:------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| registrationRetryTimerSecs |      20       | 1           | 60          | Timer interval for the Node agent to send a registration request if a response is not received from the Vision Agent.                                          |
| registrationRetryLimit     |       8       | 3           | 15          | Number of attempted retries for the Node Agent to send a registration request.                                                                                 |
| XLinkPCIeDevID             |       0       | N/A         | N/A         | Number used to connect the XLink PCIe devices to the Node Agent.                                                                                               |
| heartbeatResponseTimerSecs |      300      | 90          | 1800        | Timer interval to wait for heartbeat response from vision-agent after sending heartbeat message.  If not received node will re-register with the Vision agent. |
