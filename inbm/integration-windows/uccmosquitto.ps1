$ErrorActionPreference = "Stop"
set-psdebug -trace 1

# Set paths
$mosquittoConfPath = "c:\intel-manageability\mosquitto\mosquitto.conf"
$caCertPath = "C:\intel-manageability\broker\etc\secret\cloudadapter-agent\ucc-ca.crt"
$caKeyPath = "C:\intel-manageability\broker\etc\secret\cloudadapter-agent\ucc-ca.key"
$serverCertPath = "C:\intel-manageability\broker\etc\secret\cloudadapter-agent\ucc-server.crt"
$serverKeyPath = "C:\intel-manageability\broker\etc\secret\cloudadapter-agent\ucc-server.key"
$clientCertPath = "C:\intel-manageability\broker\etc\secret\cloudadapter-agent\ucc-client.crt"
$clientKeyPath = "C:\intel-manageability\broker\etc\secret\cloudadapter-agent\ucc-client.key"
$opensslPath = "C:\Program Files\OpenSSL-Win64\bin\openssl.exe"

$serverConfig = @"
[ req ]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[ dn ]
CN = server

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
IP.1 = 127.0.0.1
"@

$clientConfig = @"
[ req ]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[ dn ]
CN = cloudadapter-agent

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
IP.1 = 127.0.0.1
"@

Set-Location \tmp

# Create directories if they don't exist
$directories = @(
    (Split-Path -Path $caCertPath),
    (Split-Path -Path $caKeyPath),
    (Split-Path -Path $serverCertPath),
    (Split-Path -Path $serverKeyPath),
    (Split-Path -Path $clientCertPath),
    (Split-Path -Path $clientKeyPath)
)

foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir
    }
}

# Generate CA key and cert
& $opensslPath req -x509 -newkey rsa:4096 -keyout $caKeyPath -out $caCertPath -days 365 -subj "/CN=CA" -nodes

# Generate server key and CSR
Set-Content -Path server.conf -Value $serverConfig
& $opensslPath req -newkey rsa:4096 -keyout $serverKeyPath -out server.csr -config server.conf -nodes

# Generate server cert signed by CA
& $opensslPath x509 -req -in server.csr -CA $caCertPath -CAkey $caKeyPath -CAcreateserial -out $serverCertPath -days 365 -extfile server.conf -extensions req_ext

# Generate client key and CSR
Set-Content -Path client.conf -Value $clientConfig
& $opensslPath req -newkey rsa:4096 -keyout $clientKeyPath -out client.csr -config client.conf -nodes

# Generate client cert signed by CA
& $opensslPath x509 -req -in client.csr -CA $caCertPath -CAkey $caKeyPath -CAcreateserial -out $clientCertPath -days 365 -extfile client.conf -extensions req_ext

# Clean up CSR and config files
Remove-Item server.csr
Remove-Item client.csr
Remove-Item server.conf
Remove-Item client.conf

# Read and update the mosquitto.conf file
$mosquittoConf = Get-Content -Path $mosquittoConfPath

# Append the second listener configuration
$secondListenerConf = @"

listener 4000
cafile $caCertPath
certfile $serverCertPath
keyfile $serverKeyPath
require_certificate true
use_identity_as_username true
tls_version tlsv1.2
"@

$mosquittoConf += $secondListenerConf

# Write the updated mosquitto.conf file
Set-Content -Path $mosquittoConfPath -Value $mosquittoConf