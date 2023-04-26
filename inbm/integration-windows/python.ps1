function Test-PythonInstalled {
    try {
      $pythonVersion = (python --version) 2>&1
      return $pythonVersion -match "^Python"
    }
    catch {
      return $false
    }
  }
  
  if (-not (Test-PythonInstalled)) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $pythonUrl = "https://www.python.org/ftp/python/3.11.3/python-3.11.3-amd64.exe"
    $installerPath = "C:\python-installer.exe"
    Invoke-WebRequest -Uri $pythonUrl -OutFile $installerPath
    Start-Process -FilePath $installerPath -ArgumentList "/passive InstallAllUsers=1 PrependPath=1" -Wait
    Remove-Item $installerPath
  }
  