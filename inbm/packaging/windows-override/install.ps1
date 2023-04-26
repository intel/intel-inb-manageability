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


$folders = @("\intel-manageability\", "\intel-manageability\broker\")

foreach ($folder in $folders) {
    if (!(Test-Path $folder)) {
        New-Item -ItemType Directory -Force -Path $folder
    }
}

Copy-Item -Path C:\inb-files\intel-manageability\* -Destination "\intel-manageability\" -Recurse
Copy-Item -Path C:\inb-files\broker\* -Destination "\intel-manageability\broker\" -Recurse

C:\inb-files\Win64OpenSSL_Light-3_1_0.msi /qn
C:\inb-files\mosquitto-2.0.15-install-windows-x64.exe /S /D=C:\intel-manageability\mosquitto
start-sleep -seconds 1
copy -path C:\inb-files\intel-manageability\mosquitto.conf -destination c:\intel-manageability\mosquitto\mosquitto.conf
c:\intel-manageability\mosquitto\mosquitto.exe install
start-sleep -seconds 1
Stop-Service mosquitto -ErrorAction SilentlyContinue

# Create key and cert and move them
$Env:Path += ";c:\program files\openssl-win64\bin"

Set-Location C:\intel-manageability\broker
if (!(Test-Path -Path "etc\secret")) {
    New-Item -ItemType Directory -Path "etc\secret"
}
usr/bin/inb-provision-certs.exe etc\public etc\secret

start-service mosquitto

Write-Host 'INBM setup complete. Next step: provision broker + cloud.'
