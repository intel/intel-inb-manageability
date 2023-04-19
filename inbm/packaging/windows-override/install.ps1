$ErrorActionPreference = "Stop"
Set-PSDebug -Trace 1

if (-not $env:UCC_MODE) {
    Write-Host "Attempted to install in normal (non-UCC) mode."
    Write-Host "This is not yet supported. Exiting."
    exit 1
}

$UCC_FILE = "C:\inb-files\intel-manageability\inbm\etc\public\ucc_flag"
if ($env:UCC_MODE) {
    "TRUE" | Set-Content -Path $UCC_FILE
}


Copy-Item -Path C:\inb-files\intel-manageability\ -Destination \intel-manageability\ -Recurse
Copy-Item -Path C:\inb-files\broker\ -Destination \intel-manageability\broker\ -Recurse

C:\inb-files\Win64OpenSSL_Light-3_1_0.msi /qn
# C:\inb-files\vc_redist.x64.exe /quiet
C:\inb-files\mosquitto-2.0.15-install-windows-x64.exe /S /D=C:\intel-manageability\mosquitto
start-sleep -seconds 1
copy -path C:\inb-files\intel-manageability\mosquitto.conf -destination c:\intel-manageability\mosquitto\mosquitto.conf
c:\intel-manageability\mosquitto\mosquitto.exe install
start-sleep -seconds 1
Stop-Service mosquitto -ErrorAction SilentlyContinue

Write-Host 'INBM setup complete. Next step: provision broker + cloud.'
