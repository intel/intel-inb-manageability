$ErrorActionPreference = "Stop"
set-psdebug -trace 1

\intel-manageability\inbm\usr\bin\inbm-cloudadapter.exe install

if (-not $env:NO_CLOUD) {
    C:\intel-manageability\broker\usr\bin\inb-provision-cloud.exe `
         \intel-manageability\inbm\etc\secret\cloudadapter-agent `
         \intel-manageability\inbm\usr\share\cloudadapter-agent\thingsboard `
         \intel-manageability\inbm\usr\share\cloudadapter-agent\ucc `
         \intel-manageability\inbm\usr\share\cloudadapter-agent\config_schema.json
}
start-service inbm-cloudadapter
set-service -name inbm-cloudadapter -startuptype automatic