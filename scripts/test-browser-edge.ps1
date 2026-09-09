<#
.SYNOPSIS
    Runs Microsoft Edge browser automation test for card login.
.DESCRIPTION
    Configures Edge AutoSelectCertificateForUrls policy and runs the Selenium
    Edge WebDriver test script against https://card.refineid.fi.
.PARAMETER Url
    Target URL to test (default: https://card.refineid.fi).
.PARAMETER Headless
    Run Edge headlessly without showing window (default: true).
.PARAMETER Screenshot
    Path to save screenshot (default: artifacts\edge_card_login.png).
#>
[CmdletBinding()]
param(
    [string]$Url = "https://card.refineid.fi",
    [switch]$Visible,
    [string]$Screenshot = "artifacts\edge_card_login.png"
)

$ErrorActionPreference = "Stop"

# Ensure Edge policy for AutoSelectCertificateForUrls exists
$PolicyKey = "HKCU:\SOFTWARE\Policies\Microsoft\Edge\AutoSelectCertificateForUrls"
if (!(Test-Path $PolicyKey)) {
    New-Item -Path $PolicyKey -Force | Out-Null
}
$Pattern = [ordered]@{ pattern = $Url; filter = @{} } | ConvertTo-Json -Compress
Set-ItemProperty -Path $PolicyKey -Name "1" -Value $Pattern -Force

# Locate Python
$PythonCmd = Get-Command python.exe -ErrorAction SilentlyContinue
if ($PythonCmd) {
    $PythonExe = $PythonCmd.Source
} else {
    $PythonExe = "C:\Users\pk\AppData\Local\Programs\Python\Python312-arm64\python.exe"
}
if (!(Test-Path $PythonExe)) {
    Write-Error "Python 3.12 was not found. Please install Python or ensure it is on PATH."
    exit 1
}

# Run script
$ScriptPath = Join-Path $PSScriptRoot "test-browser-edge.py"
$ArgsList = @($ScriptPath, "--url", $Url, "--screenshot", $Screenshot)
if ($Visible) {
    $ArgsList += "--no-headless"
}

Write-Host "Running Edge browser automation test against $Url..." -ForegroundColor Cyan
& $PythonExe @ArgsList
$ExitCode = $LASTEXITCODE

if ($ExitCode -eq 0) {
    Write-Host "Edge browser test completed successfully." -ForegroundColor Green
} else {
    Write-Host "Edge browser test failed with exit code $ExitCode." -ForegroundColor Red
}
exit $ExitCode
