# Windows 11 Privacy Optimization
# Run as Administrator

# Initialization and Helper Functions
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $logFolder = "C:\Windows\Logs\PrivacyOptimizer"
    $logFile = Join-Path $logFolder "privacy_$(Get-Date -Format 'yyyyMMdd').log"
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    
    if (-not (Test-Path $logFolder)) {
        New-Item -ItemType Directory -Path $logFolder -Force | Out-Null
    }
    
    $logMessage = "[$timestamp] [$Level] $Message"
    Add-Content -Path $logFile -Value $logMessage
    
    # Console output with colors
    switch ($Level) {
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Error' { Write-Host $logMessage -ForegroundColor Red }
        default { Write-Host $logMessage }
    }
}

# System Analysis Function
function Test-SystemCompatibility {
    $osInfo = Get-CimInstance Win32_OperatingSystem
    $edition = $osInfo.Caption
    $version = $osInfo.Version
    $build = $osInfo.BuildNumber
    
    Write-Log "System: $edition (Version: $version, Build: $build)" -Level 'Info'
    
    $compatibility = @{
        IsWindows11 = $build -ge 22000
        IsProEdition = $edition -match "Pro|Enterprise|Education"
        Is24H2 = $build -ge 24000
    }
    
    return $compatibility
}

function Test-PrivacyFeatureAvailability {
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$Compatibility
    )

    if ($Compatibility.Is24H2) {
        Write-Log "Windows 11 24H2 detected - All privacy features are available" -Level 'Info'
        return $true
    } else {
        Write-Log "Some privacy features might not be available on this Windows version" -Level 'Warning'
        return $false
    }
}

# Registry value setter with backup
function Set-RegistryValueWithBackup {
    param (
        [string]$Path,
        [string]$Name,
        $Value,
        [string]$Description = ""
    )
    
    try {
        # Backup old value
        if (Test-Path $Path) {
            $oldValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($oldValue) {
                $backup = @{
                    Path = $Path
                    Name = $Name
                    Value = $oldValue.$Name
                    Description = $Description
                }
                $script:registryBackups += $backup
            }
        }
        
        # Create path if it doesn't exist
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        
        # Set value
        Set-ItemProperty -Path $Path -Name $Name -Value $Value
        Write-Log "Registry value set: $Path\$Name = $Value $(if($Description){" ($Description)"})" -Level 'Info'
        return $true
    }
    catch {
        Write-Log "Error setting $Path\$Name : $($_.Exception.Message)" -Level 'Error'
        return $false
    }
}

# Enhanced Windows Privacy Settings
function Set-WindowsPrivacy {
    Write-Log "Configuring Windows privacy settings..." -Level 'Info'
    
    # Basic Telemetry Settings
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' `
        -Name 'AllowTelemetry' -Value 0 `
        -Description "Disable Windows Telemetry"
    
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' `
        -Name 'AllowTelemetry' -Value 0 `
        -Description "Disable Telemetry Collection"
    
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' `
        -Name 'MaxTelemetryAllowed' -Value 0 `
        -Description "Set Maximum Telemetry Level to Security"

    # 24H2 Specific Telemetry Settings
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' `
        -Name 'DisableEnterpriseAuthProxy' -Value 1 `
        -Description "Disable Enterprise Authentication for Telemetry"

    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' `
        -Name 'DisableOneSettingsDownloads' -Value 1 `
        -Description "Disable Automatic Policy Downloads"

    # Connected User Experiences and Telemetry Service
    Set-RegistryValueWithBackup -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack' `
        -Name 'Start' -Value 4 `
        -Description "Disable Connected User Experiences Service"

    # Diagnostic Data Settings
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack' `
        -Name 'DiagTrackAuthorization' -Value 0 `
        -Description "Disable Diagnostic Tracking Authorization"

    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey' `
        -Name 'EnableEventTranscript' -Value 0 `
        -Description "Disable Event Transcript Collection"

    # Compatibility Telemetry
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' `
        -Name 'DisableInventory' -Value 1 `
        -Description "Disable Application Inventory Collection"

    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' `
        -Name 'DisablePCA' -Value 1 `
        -Description "Disable Program Compatibility Assistant"

    # Advertising ID and Personalization
    Set-RegistryValueWithBackup -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' `
        -Name 'Enabled' -Value 0 `
        -Description "Disable Advertising ID"

    Set-RegistryValueWithBackup -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy' `
        -Name 'TailoredExperiencesWithDiagnosticDataEnabled' -Value 0 `
        -Description "Disable Tailored Experiences"

    # Cloud Content
    Set-RegistryValueWithBackup -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' `
        -Name 'ContentDeliveryAllowed' -Value 0 `
        -Description "Disable Content Delivery"

    Set-RegistryValueWithBackup -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' `
        -Name 'FeatureManagementEnabled' -Value 0 `
        -Description "Disable Feature Management"

    # Activity History and Timeline
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' `
        -Name 'EnableActivityFeed' -Value 0 `
        -Description "Disable Activity Feed"

    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' `
        -Name 'PublishUserActivities' -Value 0 `
        -Description "Disable Activity Publishing"

    # Disable Web Search
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' `
        -Name 'DisableWebSearch' -Value 1 `
        -Description "Disable Web Search"

    # Disable Remote Assistance
    Set-RegistryValueWithBackup -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' `
        -Name 'fAllowToGetHelp' -Value 0 `
        -Description "Disable Remote Assistance"

    # Disable AutoPlay and AutoRun
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
        -Name 'NoDriveTypeAutoRun' -Value 255 `
        -Description "Disable AutoRun for all drives"

    # Disable Storage Sense
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense' `
        -Name 'AllowStorageSenseGlobal' -Value 0 `
        -Description "Disable Storage Sense"

    # Disable Customer Experience Improvement Program
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows' `
        -Name 'CEIPEnable' -Value 0 `
        -Description "Disable CEIP"

    # Disable Windows Feedback Experience
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' `
        -Name 'DoNotShowFeedbackNotifications' -Value 1 `
        -Description "Disable Feedback Notifications"

    # Disable Location Tracking
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' `
        -Name 'Value' -Value 'Deny' `
        -Description "Disable Location Tracking"

    # Disable App Launch Tracking
    Set-RegistryValueWithBackup -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' `
        -Name 'Start_TrackProgs' -Value 0 `
        -Description "Disable App Launch Tracking"

    # Disable Network Location Awareness
    Set-RegistryValueWithBackup -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet' `
        -Name 'EnableActiveProbing' -Value 0 `
        -Description "Disable Network Location Awareness"

    Write-Log "Windows privacy settings configuration completed" -Level 'Info'

    # Disable Windows Tips and Suggestions
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' `
        -Name 'DisableSoftLanding' -Value 1 `
        -Description "Disable Windows Tips"

    # Disable Clipboard History and Sync
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' `
        -Name 'AllowClipboardHistory' -Value 0 `
        -Description "Disable Clipboard History"

    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' `
        -Name 'AllowCrossDeviceClipboard' -Value 0 `
        -Description "Disable Clipboard Sync"

    # Disable Windows Hello Face
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures' `
        -Name 'EnhancedAntiSpoofing' -Value 0 `
        -Description "Disable Windows Hello Face"

    # Disable Timeline
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' `
        -Name 'EnableActivityFeed' -Value 0 `
        -Description "Disable Timeline Feature"

    # Disable Shared Experiences
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' `
        -Name 'EnableCdp' -Value 0 `
        -Description "Disable Shared Experiences"

    # Disable Suggested Content in Settings App
    Set-RegistryValueWithBackup -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' `
        -Name 'SubscribedContent-338393Enabled' -Value 0 `
        -Description "Disable Suggested Content in Settings"

    # Disable Suggested Content in Windows Spotlight
    Set-RegistryValueWithBackup -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' `
        -Name 'SubscribedContent-338387Enabled' -Value 0 `
        -Description "Disable Windows Spotlight Content"
}

# Windows Update Delivery Optimization Configuration
function Set-DeliveryOptimization {
    Write-Log "Configuring Windows Update Delivery Optimization..." -Level 'Info'
    
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' `
        -Name 'DODownloadMode' -Value 1 `
        -Description "Set Delivery Optimization to LAN Only"
    
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' `
        -Name 'DOMaxUploadBandwidth' -Value 1 `
        -Description "Restrict Upload Bandwidth"
       
}

# Hosts File Management
function Update-HostsFile {
    param (
        [string[]]$BlockDomains,
        [switch]$IncludeWildcards = $true
    )
    
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $backupPath = "$env:SystemRoot\System32\drivers\etc\hosts.backup"
    $tempHostsPath = "$env:TEMP\hosts.tmp"
    
    try {
        # Create backup
        Copy-Item -Path $hostsPath -Destination $backupPath -Force
        Write-Log "Hosts file backup created: $backupPath" -Level 'Info'
        
        # Read current content with file lock handling
        try {
            $currentContent = [System.IO.File]::ReadAllText($hostsPath)
        }
        catch {
            Start-Sleep -Seconds 1
            $currentContent = [System.IO.File]::ReadAllText($hostsPath)
        }
        
        if (-not $currentContent) { $currentContent = "" }
        
        # Prepare new entries
        $newEntries = @(
            "# Windows 11 Privacy Optimization - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            "# Last updated: $(Get-Date)"
            ""
            "# localhost entries"
            "127.0.0.1 localhost"
            "::1 localhost"
            ""
            "# Blocked domains for privacy"
        )

        # Process domains
        foreach ($domain in $BlockDomains) {
            if ($domain -match '^\*') {
                if ($IncludeWildcards) {
                    $baseDomain = $domain.TrimStart('*.')
                    $newEntries += "0.0.0.0 $baseDomain"
                    $newEntries += "0.0.0.0 *.$baseDomain"
                }
            } else {
                $newEntries += "0.0.0.0 $domain"
                if ($domain -notmatch '^www\.') {
                    $newEntries += "0.0.0.0 www.$domain"
                }
            }
        }
        
        # Clean existing entries but keep custom ones
        $cleanedContent = $currentContent -split "`n" | Where-Object {
            $_ -notmatch "^0\.0\.0\.0" -and
            $_ -notmatch "# Windows 11 Privacy Optimization" -and
            $_ -match '\S'
        }
        
        # Combine content
        $newContent = @(
            $cleanedContent
            ""
            $newEntries
        ) -join "`n"
        
        # Write to temp file first
        [System.IO.File]::WriteAllText($tempHostsPath, $newContent, [System.Text.Encoding]::ASCII)
        
        # Copy temp file to hosts with elevated privileges
        $argument = "Copy-Item -Path '$tempHostsPath' -Destination '$hostsPath' -Force"
        Start-Process powershell -Verb RunAs -ArgumentList "-Command", $argument -Wait
        
        # Cleanup temp file
        Remove-Item -Path $tempHostsPath -Force -ErrorAction SilentlyContinue
        
        # Flush DNS cache
        ipconfig /flushdns | Out-Null
        Write-Log "DNS cache flushed" -Level 'Info'
        
        Write-Log "Hosts file successfully updated with $(($BlockDomains).Count) domains" -Level 'Info'
        return $true
    }
    catch {
        Write-Log "Error updating hosts file: $($_.Exception.Message)" -Level 'Error'
        Write-Log "Please ensure you have administrator rights and the hosts file is not read-only" -Level 'Warning'
        return $false
    }
}

# Interactive Menu
function Show-Menu {
    $options = @{
        1 = "Restrict Windows Update Delivery Optimization"
        2 = "Enable Hosts File Blocking"
        3 = "Optimize Windows Privacy Settings"
        4 = "Run All Optimizations"
        5 = "Revert Changes"
        6 = "Exit"
    }
    
    Write-Host "`nWindows 11 Privacy Optimization`n" -ForegroundColor Cyan
    foreach ($key in $options.Keys | Sort-Object) {
        Write-Host "[$key] $($options[$key])"
    }
    
    $choice = Read-Host "`nSelect an option (1-6)"
    return $choice
}

# Main Program
$script:registryBackups = @()
$compatibility = Test-SystemCompatibility

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "This script must be run as Administrator!" -Level 'Error'
    exit
}

if (-not $compatibility.IsWindows11) {
    Write-Log "WARNING: This script is optimized for Windows 11. Some features might not work correctly on your system." -Level 'Warning'
}

# List of domains to block
$domains = @(
    'telemetry.microsoft.com',
    'vortex.data.microsoft.com',
    'vortex-win.data.microsoft.com',
    'telecommand.telemetry.microsoft.com',
    'telecommand.telemetry.microsoft.com.nsatc.net',
    'oca.telemetry.microsoft.com',
    'sqm.telemetry.microsoft.com',
    'watson.telemetry.microsoft.com',
    'redir.metaservices.microsoft.com',
    'choice.microsoft.com',
    'choice.microsoft.com.nstac.net',
    'df.telemetry.microsoft.com',
    'reports.wes.df.telemetry.microsoft.com',
    'services.wes.df.telemetry.microsoft.com',
    'sqm.df.telemetry.microsoft.com',
    'telemetry.appex.bing.net',
    'telemetry.urs.microsoft.com',
    'telemetry.appex.bing.net:443',
    'settings-sandbox.data.microsoft.com',
    'vortex-sandbox.data.microsoft.com',
    'survey.watson.microsoft.com',
    'watson.ppe.telemetry.microsoft.com',
    'watson.microsoft.com',
    'connectivitycheck.microsoft.com',
    'customer.microsoft.com',
    'diagnostic.microsoft.com'

    # Additional Microsoft Services
    'activation.sls.microsoft.com',
    'licensing.mp.microsoft.com',
    'activation-v2.sls.microsoft.com',
    'delivery.mp.microsoft.com',
    'dl.delivery.mp.microsoft.com',
    'msedge.api.cdp.microsoft.com',
    
    # Bing Related
    'www.bing.com',
    'bing.com',
    'r.bing.com',
    'bingapis.com',
    
    # Additional Tracking
    'browser.events.data.microsoft.com',
    'browser.events.data.msn.com',
    'activity.windows.com',
    'bingapis.com',
    'data.microsoft.com',
    'edge.activity.windows.com',
    'edge.microsoft.com',
    'in.appcenter.ms',
    'msedge.net',
    
    # Advertising
    'ads.microsoft.com',
    'adserver.bing.com',
    'advertise.bingads.microsoft.com',
    'go.microsoft.com',
    'msn.com',
    'msnbc.com',
    'c.msn.com',
    'ads*.msn.com',
    
    # Analytics
    'analytics.microsoft.com',
    'analytics.msn.com',
    'applicationinsights.microsoft.com',
    'mobile.pipe.aria.microsoft.com'
)

do {
    $choice = Show-Menu
    switch ($choice) {
        1 { Set-DeliveryOptimization }
        2 { Update-HostsFile -BlockDomains $domains }
        3 { 
            $featureAvailability = Test-PrivacyFeatureAvailability -Compatibility $compatibility
            Set-WindowsPrivacy 
        }
        4 {
            Write-Log "Running all optimizations..." -Level 'Info'
            $featureAvailability = Test-PrivacyFeatureAvailability -Compatibility $compatibility
            Set-DeliveryOptimization
            Set-WindowsPrivacy
            Update-HostsFile -BlockDomains $domains
        }
        5 {
            Write-Log "Restoring backup values..." -Level 'Info'
            foreach ($backup in $script:registryBackups) {
                Set-ItemProperty -Path $backup.Path -Name $backup.Name -Value $backup.Value
                Write-Log "Restored: $($backup.Path)\$($backup.Name) = $($backup.Value)" -Level 'Info'
            }
            if (Test-Path "$env:SystemRoot\System32\drivers\etc\hosts.backup") {
                Copy-Item "$env:SystemRoot\System32\drivers\etc\hosts.backup" "$env:SystemRoot\System32\drivers\etc\hosts" -Force
                Write-Log "Hosts file restored from backup" -Level 'Info'
            }
        }
        6 {
            Write-Log "Program terminated" -Level 'Info'
            exit
        }
        default {
            Write-Log "Invalid selection" -Level 'Warning'
        }
    }
    
    if ($choice -ne 6) {
        Write-Host "`nPress any key to continue..."
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
} while ($choice -ne 6)