# inbm-v5

To generate protobuf:

* Install `buf` tool. See https://buf.build/docs/cli/installation/
* Run: `buf generate`

To run server:

* Run: `go run ./cmd/inbd -s /tmp/inbd.sock`

This will wait for a client connection on `/tmp/inbd.sock`.

To run client:

* Run: `go run ./cmd/inbc -s /tmp/inbd.sock`

This will connect to the server `inbd` via `/tmp/inbd.sock` and send a simple gRPC query.

To run server as a service:
* Build the inbd binary: `make inbd`
* Copy the binary to /usr/bin: `cp output/inbd /usr/bin`
* Copy the service file to systemd folder: `cp configs/systemd/inbd.service /lib/systemd/system/inbd.service'
* Start the service: `systemctl start inbd`
* Check the service's log: `journalctl -fu inbd`
* To start inbd automatically on system boot: `systemctl enable inbd`

# Branching Strategy

## Pre-Release Development
Before the first INBM-v5 release, we will use feature branches against the `inbm-v5` branch. In GitHub, we have set `inbm-v5` as a protected branch, similar to `develop` (which continues to be used for v4 development).

## Post-Release Structure
After the first INBM-v5 release, we will maintain:

- `main`: Production-ready v5 code, used for v5 releases
- `develop`: Development branch for ongoing v5 features and improvements
- `develop-v4`: Development branch for v4 bug fixes and maintenance releases

Feature branches for v5 will branch from and merge to `develop`, while v4 maintenance will work directly with the `develop-v4` branch.
