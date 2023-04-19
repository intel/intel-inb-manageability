Set-PSDebug -Trace 1

Stop-Service inbm-cloud-adapter -ErrorAction SilentlyContinue
Stop-Service mosquitto -ErrorAction SilentlyContinue



$ErrorActionPreference = "Stop"


c:\intel-manageability\mosquitto\mosquitto.exe uninstall
c:\intel-manageability\inbm\usr\bin\inbm-cloudadapter.exe remove
Remove-Item -Path c:\intel-manageability -Recurse -ErrorAction Ignore