$ErrorActionPreference = "Stop"
set-psdebug -trace 1

C:\inbm-broker-Windows\windows-inbm-broker\intel-manageability\Win64OpenSSL_Light-1_1_1k.msi /qn
C:\inbm-broker-Windows\windows-inbm-broker\intel-manageability\vc_redist.x64.exe /quiet
C:\inbm-broker-Windows\windows-inbm-broker\intel-manageability\mosquitto-1.6.9-install-windows-x64.exe /S /D=C:\mosquitto
start-sleep -seconds 2
copy -path C:\inbm-broker-Windows\windows-inbm-broker\intel-manageability\mosquitto.conf -destination c:\mosquitto\mosquitto.conf
c:\mosquitto\mosquitto.exe install
stop-service mosquitto

# Create key and cert and move them
$Env:Path += ";c:\program files\openssl-win64\bin"
if (Test-Path C:\intel-manageability){
remove-item -path c:\intel-manageability\broker -recurse -erroraction ignore
copy -path C:\inbm-broker-Windows\windows-inbm-broker\intel-manageability\broker -Destination \intel-manageability\ -recurse
} else
{
copy -path C:\inbm-broker-Windows\windows-inbm-broker\intel-manageability\ -Destination \intel-manageability\ -recurse
}

cd C:\intel-manageability\broker
New-Item -ItemType Directory -Force -Path C:\intel-manageability\broker\etc\public\ -erroraction ignore
New-Item -ItemType Directory -Force -Path C:\intel-manageability\broker\etc\secret\ -erroraction ignore
usr\bin\inb-provision-certs.exe etc\public etc\secret

start-service mosquitto
Write-Host 'INBM broker setup complete.'
