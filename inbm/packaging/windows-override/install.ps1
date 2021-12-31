stop-service inbm-dispatcher
stop-service inbm-diagnostic
stop-service inbm-telemetry
stop-service inbm-cloud-adapter
stop-service inbm-configuration
stop-service mosquitto

$ErrorActionPreference = "Stop"
set-psdebug -trace 1

remove-item -path c:\intel-manageability -recurse -erroraction ignore
dir C:\inbm-Windows\windows-inbm
copy -path C:\inbm-Windows\windows-inbm\intel-manageability\ -Destination \intel-manageability\ -recurse
if (Test-Path C:\intel-manageability\broker){
Write-Host 'Detected inbm broker already installed.'
}
else
{
Write-Host 'Please install inbm broker.'
}