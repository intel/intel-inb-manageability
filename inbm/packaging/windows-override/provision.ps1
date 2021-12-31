Remove-Item C:\intel-manageability\inbm\etc\public\node-agent -RecurseRemove-Item C:\intel-manageability\inbm\etc\public\vision-agent -Recursestop-service inbm-dispatcher
stop-service inbm-diagnostic
stop-service inbm-telemetry
stop-service inbm-cloud-adapter
stop-service inbm-configuration
stop-service mosquitto

$ErrorActionPreference = "Stop"
set-psdebug -trace 1

cd \intel-manageability\inbm
bin\dispatcher.exe install
bin\diagnostic.exe install
bin\telemetry.exe install
bin\cloudadapter.exe install
bin\configuration.exe install
bin\inb-provision-cloud.exe etc\secret\cloudadapter-agent usr\share\cloudadapter-agent\thingsboard usr\share\cloudadapter-agent\config_schema.json
bin\inb-provision-ota-cert.exe
start-service mosquitto

start-service inbm-dispatcher
set-service -name inbm-dispatcher -startuptype automatic
start-service inbm-diagnostic
set-service -name inbm-diagnostic -startuptype automatic
start-service inbm-telemetry
set-service -name inbm-telemetry -startuptype automatic
start-service inbm-cloud-adapter
set-service -name inbm-cloud-adapter -startuptype automatic
start-service inbm-configuration
set-service -name inbm-configuration -startuptype automatic
