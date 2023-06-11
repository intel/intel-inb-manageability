# Issues and Troubleshooting


## ISSUE: Error 'Ran into an error retrieving hostname: 401' when connecting INBM to Cloud Provider
This error may be seen in the cloudadapter-agent logs after provision with the cloud.  Make sure the date/time are accurate.  A difference of just a couple of minutes can cause this error.


## ISSUE: Provisioning Unsuccessful or Device Not Connected to Cloud

If the provisioning script is stuck while creating *symlinks* at the
end of provisioning or Device is not connected to the cloud, there is a
chance that another system service is blocking the INB services from starting. In order to fix this issue,
follow the steps:

Check if bootup is complete:

```shell
sudo systemd-analyze critical-chain
```

If the boot-up isn’t complete, list all the jobs:

```shell
sudo systemctl list-jobs
```

Stop all the jobs that in the ‘waiting’ state:

```shell
sudo systemctl stop [job_unit_name]
```

Try provisioning the device again following the steps in the [Azure](In-Band%20Manageability%20User%20Guide%20-%20Azure.md#provisioning-a-device) or [Thingsboard](In-Band%20Manageability%20User%20Guide%20-%20ThingsBoard.md#provisioning-a-device) documentation.

## ISSUE: ERROR '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self signed certificate' when provision to Thingsboard
If you are using self sign certificate and seeing this error, it could be you are behind proxy or DNS not able to resolve your hostname. You will need to fix your DNS issue or try following workaround.

Create self sign certificate. Login to thingsboard host and run following commands.
```shell
sudo openssl ecparam -out server_key.pem -name secp256r1 -genkey
sudo openssl req -x509 -newkey rsa:4096 -keyout server_key.pem -out server.pem -days 365 -subj "/CN=<domain_suffix>" -addext "subjectAltName = DNS:<domain_suffix>,IP:<thingsboard_IP>" -nodes
```

Change all the server.* file permission to 754 and change ownership & group to thingsboard
```shell
sudo chmod 754 server.*
sudo chgrp thingsboard server.*
sudo chown thingsboard server.*
```

Restart thingsboard service
```shell
sudo systemctl restart thingsboard.service
```

Copy file server.pem to your edge device. Provision the device again following the steps in [Thingsboard](In-Band%20Manageability%20User%20Guide%20-%20ThingsBoard.md#provisioning-a-device) documentation. When it prompt for ThingsBoard CA file, enter the path to file server.pem
> If your thingsboard server IP address changed, you need to repeat all these steps again
