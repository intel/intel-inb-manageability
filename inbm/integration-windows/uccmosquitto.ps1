$ErrorActionPreference = "Stop"
set-psdebug -trace 1

$uccMosquittoPath = "C:\uccmosquitto"

# Set paths
$caCertPath = "C:\intel-manageability\broker\etc\secret\cloudadapter-agent\ucc-ca.crt"
$caKeyPath = "C:\intel-manageability\broker\etc\secret\cloudadapter-agent\ucc-ca.key"
$serverCertPath = "C:\intel-manageability\broker\etc\secret\cloudadapter-agent\ucc-server.crt"
$serverKeyPath = "C:\intel-manageability\broker\etc\secret\cloudadapter-agent\ucc-server.key"
$clientCertPath = "C:\intel-manageability\broker\etc\secret\cloudadapter-agent\ucc-client.crt"
$clientKeyPath = "C:\intel-manageability\broker\etc\secret\cloudadapter-agent\ucc-client.key"
$opensslPath = "C:\Program Files (x86)\OpenSSL-Win32\bin\openssl.exe"

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

# UCC mosquitto configuration
$mosquittoConf = @"

port 4000
cafile $caCertPath
certfile $serverCertPath
keyfile $serverKeyPath
require_certificate true
use_identity_as_username true
tls_version tlsv1.2
"@


C:\inb-files\mosquitto-2.0.15-install-windows-x86.exe /S /D=$uccMosquittoPath
start-sleep -seconds 1

# Variables
$instances = @(
    @{
        Name = "UCCMosquitto"
        Binary = "uccmosquitto.exe"
        Config = "uccmosquitto.conf"
    }
)

# Download NSSM
$nssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
$nssmZipPath = Join-Path $uccMosquittoPath "nssm.zip"
$extractPath = Join-Path $uccMosquittoPath "nssm"

if (-not (Test-Path $extractPath)) {
    Invoke-WebRequest -Uri $nssmUrl -OutFile $nssmZipPath
    Expand-Archive -Path $nssmZipPath -DestinationPath $extractPath
}

$serviceName = "uccmosquitto"
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

if ($service -and $service.Status -eq "Running") {
    Stop-Service -Name $serviceName -PassThru
}


$nssmExe = Join-Path $extractPath "nssm-2.24\win64\nssm.exe"

# Create separate Mosquitto instances and services
foreach ($instance in $instances) {
    $binaryPath = Join-Path $uccMosquittoPath $instance.Binary
    $configPath = Join-Path $uccMosquittoPath $instance.Config

    Copy-Item -Path (Join-Path $uccMosquittoPath "mosquitto.exe") -Destination $binaryPath

    Set-Content -Path $configPath -Value $mosquittoConf

    $service = Get-Service -Name $instance.Name -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        & $nssmExe install $instance.Name $binaryPath "-c $configPath"
    }
}

net start uccmosquitto
