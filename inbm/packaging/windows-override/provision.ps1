Stop-Service inbm-cloud-adapter -ErrorAction SilentlyContinue
Stop-Service mosquitto -ErrorAction SilentlyContinue

# Create key and cert and move them
$Env:Path += ";c:\program files\openssl-win64\bin"

cd C:\intel-manageability\broker
mkdir etc\secret
usr/bin/inb-provision-certs.exe etc\public etc\secret

start-service mosquitto

$ErrorActionPreference = "Stop"
set-psdebug -trace 1

\intel-manageability\inbm\usr\bin\inbm-cloudadapter.exe install

$adapterCfg = @'
{ 
    "cloud": "ucc", 
    "config": {
        "mqtt": {
            "client_id": "12345678abcd",
            "username": "",
            "hostname": "localhost",
            "port": 4000
        },
        "tls": {
            "version": "TLSv1.2",
            "certificates": "C:\\intel-manageability\\inbm\\etc\\secret\\cloudadapter-agent\\ucc.ca.pem.crt"
        },
        "x509": {
            "device_cert": "C:\\intel-manageability\\inbm\\etc\\secret\\cloudadapter-agent\\client.crt",
            "device_key": "C:\\intel-manageability\\inbm\\etc\\secret\\cloudadapter-agent\\client.key"
        },
        "event": {
            "pub": "TopicTelemetryInfo/12345678abcd",
            "format": "{ \"ts\": \"{ts}\", \"values\": {\"telemetry\": \"{value}\"}}"
        },
        "telemetry": {
            "pub": "",
            "format": ""
        },
        "attribute": {
            "pub": "",
            "format": ""
        },
        "method": {
            "pub": "TopicRemoteCommands/response/12345678abcd",
            "format": "\"{timestamp}: {message}\"",
            "sub": "TopicRemoteCommands/12345678abcd"
        }
    }
}
'@

Set-Content -Path \intel-manageability\inbm\etc\secret\cloudadapter-agent\adapter.cfg -Value $adapterCfg

# \intel-manageability\broker\usr\bin\inb-provision-cloud.exe `
#     \intel-manageability\broker\etc\secret\cloudadapter-agent `
#     \intel-manageability\inbm\usr\share\cloudadapter-agent\thingsboard `
#     \intel-manageability\inbm\usr\share\cloudadapter-agent\ucc `
#     \intel-manageability\inbm\usr\share\cloudadapter-agent\config_schema.json
start-service mosquitto

start-service inbm-cloud-adapter
set-service -name inbm-cloud-adapter -startuptype automatic
# check if mosquitto restarts on reboot?