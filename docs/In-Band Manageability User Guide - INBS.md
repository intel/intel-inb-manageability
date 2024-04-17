# In-Band Manageability Framework User Guide – INBS

## Introduction

INBS, short for In-Band Service, is a cloud-based solution designed for the management of devices across networks. Currently, INBS is in its initial development phase and is not ready for public deployment.

**Security Notice**: The INBM Cloudadapter agent currently supports only insecure connection modes to INBS. The use of INBS in production environments in this mode is strongly discouraged. Future updates will introduce TLS support to improve security.

## Configuration

Follow these steps to configure INBS as your cloud provider during the provisioning of INBM:

1. During the provisioning process, instruct the system to ignore the default cloud settings by executing:
   ```shell
   sudo NO_CLOUD=x provision-tc
   ```

2. Configure the `adapter.cfg` file for the Cloud Adapter. On Linux systems, this file is typically found at `/etc/intel-manageability/secretcloudadapter-agent/adapter.cfg`.

Below is an example configuration for your cloud settings:

```json
{
  "cloud": "inbs",
  "config": {
    "hostname": "localhost",
    "port": "5678",
    "node-id": "abcdefg",
    "token": "secret_token"
  }
}
```

### Configuration Parameters
- **hostname**: The address of the INBS server, which could be an IP address or a domain name.
- **port**: The port number on which the INBS server is listening.
- **node-id**: A unique identifier for the device within the network. It is strongly recommended to use the SMBIOS UUID as the node ID to ensure uniqueness and correlation with other services. This can be found at `/sys/class/dmi/id/product_uuid` on Linux systems.
- **token**: A confidential authentication token used to verify the device with the INBS server.

**Important Reminder**: Secure mode is not currently supported, and tokens are transmitted in plain text. Therefore, INBS should not be used in any production environment until TLS support is available.