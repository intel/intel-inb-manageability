# Docker Compose Environment for Quick Testing

**WARNING: DO NOT USE IN PRODUCTION; FOR DEV/TEST ONLY**

This directory provides a `docker-compose` setup to run the INBM agents in containers with a rapid build. The build is quicker because it doesn't use PyInstaller—instead, it simply copies the source files to each container.

The stack will connect and attempt to run a SOTA, but currently fails because there is no `lsb_release` command.

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