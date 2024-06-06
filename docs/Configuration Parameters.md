# Configuration Parameters

Each of the agents has its own set of configuration key/value pairs which can be dynamically set either via the cloud, INBC, or directly in the file.  Note, that if the changes are made via the cloud or using INBC that the changes will be dynamic.  If they are made to the file directly, then the service will need to be restarted to pick up the changes.

## INBM Configuration

Configuration update is used to change/retrieve/append/remove configuration parameter values from the Configuration file located at
```/etc/intel_manageability.conf```. Refer to the tables below to understand the configuration key/value pairs

The below tables represent the different sections of the configuration file.

### All

| Key | Default Value | Description                                                                                    |
|:----|:-------------:|:-----------------------------------------------------------------------------------------------|
| dbs |     WARN      | How the system should be respond if there is a Docker Bench Security alert. [ON, OFF, or WARN] |

### Telemetry

| Key                            | Default Value | Lower Limit | Upper Limit | Description                                                                                                                              |
|:-------------------------------|:-------------:|:------------|-------------|------------------------------------------------------------------------------------------------------------------------------------------|
| collectionIntervalSeconds      |      60       | 30          | 120         | Time interval after which telemetry is collected from the system.                                                                        |
| publishIntervalSeconds         |      300      | 120         | 480         | Time interval after which collected telemetry is published to dispatcher and the cloud                                                   |
| maxCacheSize                   |      100      | 50          | 200         | Maximum cache set to store the telemetry data. This is the count of messages that telemetry agent caches before sending out to the cloud |
| containerHealthIntervalSeconds |      600      | 300         | 1800        | Interval after which container health check is run and results are returned.                                                             |
| enableSwBom                    |     true      | N/A         | N/A         | Specifies if Software BOM needs to be published in the initial telemetry.                                                                |
| swBomIntervalHours             |      24       | 1           | 168         | Number of hours between swBom publish.                                                                                                   |

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

Note: ubuntuAptSource tag is no longer used. 

| Key                    |     Default Value      | Description                                                                              |
|:-----------------------|:----------------------:|:-----------------------------------------------------------------------------------------|
| proceedWithoutRollback |          true          | Whether SOTA update should go through even when rollback is not supported on the system. |
