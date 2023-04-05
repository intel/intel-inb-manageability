#stop-service inbm-dispatcher
#stop-service inbm-diagnostic
#stop-service inbm-telemetry
Stop-Service inbm-cloud-adapter -ErrorAction SilentlyContinue
#stop-service inbm-configuration
Stop-Service mosquitto -ErrorAction SilentlyContinue

$ErrorActionPreference = "Stop"
Set-PSDebug -Trace 1

Remove-Item -Path c:\intel-manageability -Recurse -ErrorAction Ignore
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
