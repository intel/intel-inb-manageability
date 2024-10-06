# Docker Compose Environment for Quick Testing

**WARNING: DO NOT USE IN PRODUCTION; FOR DEV/TEST ONLY**

This directory provides a `docker-compose` setup to run the INBM agents in containers with a rapid build for development testing. The build is quicker because it doesn't use PyInstaller—instead, it simply copies the source files to each container.

Key features of this setup:

- Agents run in insecure mode, so no certificates need to be provisioned.
- No AppArmor rules apply.
- There are no MQTT ACLs.

Cloud configuration is straightforward—simply provide `adapter.cfg` alongside the `docker-compose-dev` files. To access a cloud service (such as INBS) running on `localhost`, use the host named `host.docker.internal` in `adapter.cfg`.

Note: This container setup is designed for development and testing purposes only. It does not replace the need for full native testing and should not be used in production environments.


## To Run

1. Create `adapter.cfg` for cloudadapter. For example, for the Azure cloud:

```json
{
  "cloud": "azure",
  "config": {
    "scope_id": "YOUR_SCOPE_ID",
    "device_id": "YOUR_DEVICE_ID",
    "device_cert": "",
    "device_key": "",
    "device_sas_key": "YOUR_DEVICE_SAS_KEY"
  }
}
```

2. Run these commands:

```bash
docker compose build
docker compose up
```

## To Stop

1. Press Ctrl+C to quit Docker Compose
2. Run the following command:

```bash
docker compose down -v
```
