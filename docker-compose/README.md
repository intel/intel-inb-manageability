This directory provides a `docker-compose` setup to run the INBM agents in a container, with a rapid build. The build is quicker because it doesn't use pyinstaller--instead it simply copies the source files to each container.

The stack will connect and attempt to run a SOTA, but currently fails because there is no lsb_release command.

## To run

First, create `adapter.cfg` for cloudadapter.  For example,

```
{ "cloud": "azure", "config": { "scope_id": "YOUR_SCOPE_ID", "device_id": "YOUR_DEVICE_ID", "device_cert": "", "device_key": "", "device_sas_key": "YOUR_DEVICE_SAS_KEY" } }
```

Second, run these commands:

```bash
docker compose build
docker compose up
```

## To stop

Press ^C to quit docker compose, and run

```bash
docker compose down -v
```
