$ErrorActionPreference = "Stop"
Set-PSDebug -Trace 1

function Download-FileIfNotExist {
    param (
        [string]$URL,
        [string]$DestinationPath
    )
    
    $FileName = Split-Path -Path $URL -Leaf
    $DestinationFilePath = Join-Path -Path $DestinationPath -ChildPath $FileName

    if (-not (Test-Path -Path $DestinationFilePath)) {
        try {
            Invoke-WebRequest -Uri $URL -OutFile $DestinationFilePath
            Write-Host "File downloaded successfully to $DestinationFilePath"
        }
        catch {
            Write-Error "Error downloading file: $_"
        }
    }
    else {
        Write-Host "No need to download; file already exists at $DestinationFilePath"
    }
}

if (-not $env:UCC_MODE) {
    Write-Host "Attempted to install in normal (non-UCC) mode."
    Write-Host "This is not yet supported. Exiting."
    exit 1
}

$UCC_FILE = "C:\inb-files\intel-manageability\inbm\etc\public\ucc_flag"
if ($env:UCC_MODE) {
    "TRUE" | Set-Content -Path $UCC_FILE
}

# This loop iterates through a list of folders, creates them if they don't exist,  
# sets their Access Control List (ACL) protections, and adds two access rules, granting FullControl 
# privileges to SYSTEM and Administrators groups on the specified folders.
$folders = @("\intel-manageability\", "\intel-manageability\broker\")
foreach ($folder in $folders) {
    if (!(Test-Path $folder)) {
        New-Item -ItemType Directory -Force -Path $folder
    }

    $acl = Get-Acl -Path $folder
    $acl.SetAccessRuleProtection($true, $false)
    Set-Acl -Path $folder -AclObject $acl

    $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
    $propagationFlags = [System.Security.AccessControl.PropagationFlags]"None"

    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", $inheritanceFlags, $propagationFlags, "Allow")
    $acl.AddAccessRule($rule)

    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", $inheritanceFlags, $propagationFlags, "Allow")
    $acl.AddAccessRule($rule)
    
    Set-Acl -Path $folder -AclObject $acl
}

Copy-Item -Path C:\inb-files\intel-manageability\* -Destination "\intel-manageability\" -Recurse
Copy-Item -Path C:\inb-files\broker\* -Destination "\intel-manageability\broker\" -Recurse

Download-FileIfNotExist -URL "https://slproweb.com/download/Win32OpenSSL_Light-3_1_1.msi" -DestinationPath "C:\inb-files"
Download-FileIfNotExist -URL "https://mosquitto.org/files/binary/win32/mosquitto-2.0.15-install-windows-x86.exe" -DestinationPath "C:\inb-files"

C:\inb-files\Win32OpenSSL_Light-3_1_1.msi /qn
C:\inb-files\mosquitto-2.0.15-install-windows-x86.exe /S /D=C:\intel-manageability\mosquitto
start-sleep -seconds 1
Copy-Item -path C:\inb-files\intel-manageability\mosquitto.conf -destination c:\intel-manageability\mosquitto\mosquitto.conf
c:\intel-manageability\mosquitto\mosquitto.exe install
start-sleep -seconds 1
Stop-Service mosquitto -ErrorAction SilentlyContinue

# Search for openssl install location
# Array of possible openssl locations
$possibleOpensslLocations = @(
    "${env:ProgramFiles(x86)}\OpenSSL*\bin",
    "${env:ProgramFiles}\OpenSSL*\bin"
)

# Hold the found location
$foundOpensslLocation = $null

# Perform a search
foreach($location in $possibleOpensslLocations)
{
    $found = Get-Item -Path $location -ErrorAction SilentlyContinue

    if($null -ne $found)
    {
        $foundOpensslLocation = $found.FullName
        break
    }
}

if($null -eq $foundOpensslLocation)
{
    Write-Output "Could not locate 32-bit OpenSSL binary directory."
    return
}
else
{
    Write-Output "Found 32-bit OpenSSL binary directory at: $foundOpensslLocation"
}

# Update PATH environment variable with the found OpenSSL bin directory
$Env:Path += ";$foundOpensslLocation"

# Create key and cert and move them
Set-Location C:\intel-manageability\broker
if (!(Test-Path -Path "etc\secret")) {
    New-Item -ItemType Directory -Path "etc\secret"
}
usr/bin/inb-provision-certs.exe etc\public etc\secret

start-service mosquitto

Write-Host 'INBM setup complete. Next step: provision broker + cloud.'
