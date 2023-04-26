$ErrorActionPreference = "Stop"
set-psdebug -trace 1

Stop-Service inbm-cloudadapter -ErrorAction SilentlyContinue
Stop-Service mosquitto -ErrorAction SilentlyContinue

# Create key and cert and move them
$Env:Path += ";c:\program files\openssl-win64\bin"

Set-Location C:\intel-manageability\broker
if (!(Test-Path -Path "etc\secret")) {
    New-Item -ItemType Directory -Path "etc\secret"
}
usr/bin/inb-provision-certs.exe etc\public etc\secret

start-service mosquitto


\intel-manageability\inbm\usr\bin\inbm-cloudadapter.exe install

if (-not $env:NO_CLOUD) {
    C:\intel-manageability\broker\usr\bin\inb-provision-cloud.exe `
         \intel-manageability\inbm\etc\secret\cloudadapter-agent `
         \intel-manageability\inbm\usr\share\cloudadapter-agent\thingsboard `
         \intel-manageability\inbm\usr\share\cloudadapter-agent\ucc `
         \intel-manageability\inbm\usr\share\cloudadapter-agent\config_schema.json
}
start-service mosquitto

start-service inbm-cloudadapter
set-service -name inbm-cloudadapter -startuptype automatic