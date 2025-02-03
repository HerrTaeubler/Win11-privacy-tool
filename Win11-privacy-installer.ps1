# Check for admin rights
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script requires administrator rights. Please run as administrator." -ForegroundColor Red
    Exit
}

# Download and execute script from GitHub
$scriptUrl = "https://raw.githubusercontent.com/HerrTauebler/Win11-privacy-tool/main/Win11-privacy-tool.ps1

try {
    $script = (Invoke-RestMethod -Uri $scriptUrl -UseBasicParsing)
    Invoke-Expression $script
} catch {
    Write-Host "Error downloading or executing script: $_" -ForegroundColor Red
}