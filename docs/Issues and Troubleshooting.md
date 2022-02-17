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