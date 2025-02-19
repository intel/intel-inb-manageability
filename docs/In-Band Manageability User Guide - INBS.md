# In-Band Manageability Framework User Guide – INBS

## Introduction

INBS, short for In-Band Service, is a cloud-based solution designed for the management of devices across networks. Currently, INBS is in its initial development phase and is not ready for public deployment.

## Configuration

Follow these steps to configure INBS as your cloud provider during the provisioning of INBM:

1. During the provisioning process, instruct the system to ignore the default cloud settings by executing:
   ```shell
   sudo NO_CLOUD=x provision-tc
   ```

2. Configure the `adapter.cfg` file for the Cloud Adapter. This file is typically located at `/etc/intel-manageability/secret/cloudadapter-agent/adapter.cfg`.

Below is an example configuration for your cloud settings with TLS enabled:

```json
{
  "cloud": "inbs",
  "config": {
    "hostname": "localhost",
    "port": "5678",
    "node-id": "abcdefg",
    "tls_enabled": true,
    "tls_cert_path": "/path/to/your/certificate.pem",
    "token_path": "/path/to/your/token.txt"
  }
}
```

To disable TLS (for example, for testing), set "tls_enabled" to false. tls_cert_path and token_path will be ignored if TLS is disabled.

3. Restart the cloudadapter agent by running: 
   ```shell
   sudo systemctl restart inbm-cloudadapter
   ```

### Configuration Parameters
- **hostname**: The address of the INBS server, which could be an IP address or a domain name.
- **port**: The port number on which the INBS server is listening.
- **node-id**: A unique identifier for the device within the network. It is strongly recommended to use the SMBIOS UUID as the node ID to ensure uniqueness and correlation with other services. This can be found at `/sys/class/dmi/id/product_uuid` on Linux systems.
- **tls_enabled**: Boolean value to enable or disable TLS. Set to `true` to enable TLS.
- **tls_cert_path**: (ignored if TLS is disabled) The system path to the TLS certificate used for establishing a secure connection to the INBS server. It is recommended that the path be under `/etc/intel-manageability/public/` to ensure the certificate is accessible to the cloudadapter agent.
- **token_path**: (ignored if TLS is disabled) Path to the file containing the confidential authentication token used to verify the device with the INBS server. It is recommended that the path be under `/etc/intel-manageability/secret/` to ensure the token is secure.
