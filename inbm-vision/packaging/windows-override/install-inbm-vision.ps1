stop-service mosquitto

$ErrorActionPreference = "Stop"
set-psdebug -trace 1

if (Test-Path C:\intel-manageability){
remove-item -path c:\intel-manageability\inbm-vision -recurse -erroraction ignore
copy -path C:\inbm-vision-Windows\windows-inbm-vision\intel-manageability\inbm-vision -Destination \intel-manageability\inbm-vision -recurse
} else
{
copy -path C:\inbm-Windows\windows-inbm\intel-manageability\ -Destination \intel-manageability\ -recurse
copy -path C:\inbm-vision-Windows\windows-inbm-vision\intel-manageability\inbm-vision -Destination \intel-manageability\inbm-vision -recurse
}

if (Test-Path C:\intel-manageability\broker){
Write-Host 'Detected inbm broker already installed. Please start mosquitto with command: start-service mosquitto'
Write-Host 'INBM vision setup complete.'
}
else
{
Write-Host 'Please install inbm broker.'
}