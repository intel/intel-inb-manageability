Set-PSDebug -Trace 1

Stop-Service inbm-cloudadapter -ErrorAction SilentlyContinue
Stop-Service mosquitto -ErrorAction SilentlyContinue

$ErrorActionPreference = "Stop"

$mosquittoPath = "c:\intel-manageability\mosquitto\mosquitto.exe"
$inbmCloudAdapterPath = "c:\intel-manageability\inbm\usr\bin\inbm-cloudadapter\inbm-cloudadapter.exe"

if (Test-Path $mosquittoPath) {
    & $mosquittoPath uninstall
}

if (Test-Path $inbmCloudAdapterPath) {
    & $inbmCloudAdapterPath remove
}

$directoryPath = "c:\intel-manageability"

if (Test-Path $directoryPath) {
    Remove-Item -Path $directoryPath -Recurse
} else {
    Write-Host "Directory not found. Skipping removal."
}