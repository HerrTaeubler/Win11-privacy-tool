# Windows 11 Privacy Optimization
# Run as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "This script requires administrator privileges. Please run as administrator." -Level 'Error'
    exit 1
}
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
    
    # Console output with colors and symbols
    $symbol = switch ($Level) {
        'Info'    { ">" }
        'Warning' { "!" }
        'Error'   { "x" }
    }
    
    $color = switch ($Level) {
        'Info'    { 'Cyan' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
    }
    
    Write-Host $symbol -ForegroundColor $color -NoNewline
    Write-Host " $Message"
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

    # Windows 11 Check
    if (-not $compatibility.IsWindows11) {
        Write-Log "ERROR: This tool requires Windows 11." -Level 'Error'
        exit 1
    }

    # Home Edition Warning
    if (-not $compatibility.IsProEdition) {
        Write-Host "`n=== Windows Home Edition Notice ===" -ForegroundColor Yellow
        Write-Log "WARNING: You are running Windows Home Edition. Some features might not be available or may require Pro/Enterprise edition." -Level 'Warning'
        Write-Log "Affected features may include:" -Level 'Warning'
        Write-Log "- Group Policy settings" -Level 'Warning'
        Write-Log "- Advanced security features" -Level 'Warning'
        Write-Log "- Enterprise management capabilities" -Level 'Warning'
        Write-Host "==================================`n" -ForegroundColor Yellow
        
        do {
            $continue = Read-Host "Do you want to continue anyway? (Y/N)"
            if ($continue -match '^[YyNn]$') {
                break
            }
            Write-Host "Invalid input. Please enter 'Y' or 'N'" -ForegroundColor Red
        } while ($true)

        if ($continue -notmatch '^[Yy]$') {
            Write-Log "Operation cancelled by user" -Level 'Info'
            exit 0
        }
    }
    
    return $compatibility
}

function Test-PrivacyFeatureAvailability {
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$Compatibility
    )

    if ($Compatibility.Is24H2) {
        Write-Log "Windows 11 detected - All privacy features are available" -Level 'Info'
        return $true
    } else {
        Write-Log "Some privacy features might not be available on this Windows version" -Level 'Warning'
        return $false
    }
}

$script:compatibility = Test-SystemCompatibility

# System Restore Point
function New-SystemRestorePoint {
    Write-Log "Creating System Restore Point..." -Level 'Info'
    
    try {
        # Load the System.Management.Automation.dll assembly
        $null = [System.Reflection.Assembly]::LoadWithPartialName("System.Management.Automation")
        
        # Enable System Restore if not already enabled
        Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue
        
        # Create the restore point
        $restorePoint = @{
            Description = "Windows 11 Privacy Settings Backup"
            RestorePointType = "MODIFY_SETTINGS"
        }
        
        $null = Checkpoint-Computer @restorePoint -ErrorAction Stop
        
        Write-Log "System Restore Point created successfully" -Level 'Info'
        return $true
    }
    catch {
        Write-Log "Error creating System Restore Point: $($_.Exception.Message)" -Level 'Error'
        Write-Log "Please ensure System Restore is enabled in System Properties" -Level 'Warning'
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
        # Validate registry path format
        if (-not ($Path -match '^HKLM:\\|^HKCU:\\')) {
            throw "Invalid registry path format: $Path"
        }

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
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        }
        
        # Set value
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -ErrorAction Stop
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
    
    # Windows Search Privacy Settings
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' `
        -Name 'ConnectedSearchUseWeb' -Value 0 `
        -Description "Disable web search results"

    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' `
        -Name 'DisableWebSearch' -Value 1 `
        -Description "Disable web search capability"

    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' `
        -Name 'AllowSearchToUseLocation' -Value 0 `
        -Description "Disable location in search"

    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' `
        -Name 'AllowCloudSearch' -Value 0 `
        -Description "Disable cloud search"

    Set-RegistryValueWithBackup -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings' `
        -Name 'IsDeviceSearchHistoryEnabled' -Value 0 `
        -Description "Disable search history"

    Set-RegistryValueWithBackup -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings' `
        -Name 'IsAADCloudSearchEnabled' -Value 0 `
        -Description "Disable Cloud Search in AAD"

    # Disable SafeSearch
    Set-RegistryValueWithBackup -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings' `
        -Name 'SafeSearchMode' -Value 0 `
        -Description "Disable SafeSearch"

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

    # Disable Shared Experiences
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' `
        -Name 'EnableCdp' -Value 0 `
        -Description "Disable Shared Experiences"

    # Disable Suggested Content in Settings App
    Set-RegistryValueWithBackup -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' `
        -Name 'SubscribedContent-338393Enabled' -Value 0 `
        -Description "Disable Suggested Content in Settings"    
   
     # Disable Bing Search in Start Menu
    Set-RegistryValueWithBackup -Path 'HKCU:\Software\Policies\Microsoft\Windows\Explorer' `
        -Name 'DisableSearchBoxSuggestions' -Value 1 `
        -Description "Disable Bing Search in Start Menu"

    # Disable Windows Widget Service
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh' `
        -Name 'AllowNewsAndInterests' -Value 0 `
        -Description "Disable Windows Widget Service"

    # Disable Microsoft Account Sign-in Assistant
    Set-RegistryValueWithBackup -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\wlidsvc' `
        -Name 'Start' -Value 4 `
        -Description "Disable Microsoft Account Sign-in Service"

    # Disable Windows Error Reporting
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' `
        -Name 'Disabled' -Value 1 `
        -Description "Disable Windows Error Reporting"
 
    # Disable Device Census
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata' `
        -Name 'PreventDeviceMetadataFromNetwork' -Value 1 `
        -Description "Disable Device Metadata Collection"

    # Disable Microsoft Store Auto Install
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' `
        -Name 'AutoDownload' -Value 2 `
        -Description "Disable Automatic Store Updates"

    # Disable Windows Welcome Experience
    Set-RegistryValueWithBackup -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' `
        -Name 'SubscribedContent-310093Enabled' -Value 0 `
        -Description "Disable Welcome Experience"

    # Disable Windows Spotlight
    Set-RegistryValueWithBackup -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' `
        -Name 'SubscribedContent-338387Enabled' -Value 0 `
        -Description "Disable Windows Spotlight"

    # Disable Inking & Typing Personalization
    Set-RegistryValueWithBackup -Path 'HKCU:\SOFTWARE\Microsoft\InputPersonalization' `
        -Name 'RestrictImplicitInkCollection' -Value 1 `
        -Description "Disable Implicit Ink Collection"
    
    Set-RegistryValueWithBackup -Path 'HKCU:\SOFTWARE\Microsoft\InputPersonalization' `
        -Name 'RestrictImplicitTextCollection' -Value 1 `
        -Description "Disable Implicit Text Collection"

    Set-RegistryValueWithBackup -Path 'HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore' `
        -Name 'HarvestContacts' -Value 0 `
        -Description "Disable Contact Harvesting"

    Set-RegistryValueWithBackup -Path 'HKCU:\SOFTWARE\Microsoft\Personalization\Settings' `
        -Name 'AcceptedPrivacyPolicy' -Value 0 `
        -Description "Disable Personalization Privacy Policy"

    # Disable language list access for websites
    Set-RegistryValueWithBackup -Path 'HKCU:\Control Panel\International\User Profile' `
        -Name 'HttpAcceptLanguageOptOut' -Value 1 `
        -Description "Disable language list access for websites"

    Set-RegistryValueWithBackup -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\LanguageConfiguration' `
        -Name 'DisableLanguageListAccess' -Value 1 `
        -Description "Disable language configuration access"
       
    # Disable suggested content in Settings app
    Set-RegistryValueWithBackup -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' `
        -Name 'SubscribedContent-338393Enabled' -Value 0 `
        -Description "Disable suggested content in Settings app"

    Set-RegistryValueWithBackup -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' `
        -Name 'SubscribedContent-353694Enabled' -Value 0 `
        -Description "Disable suggestions in Settings"

    Set-RegistryValueWithBackup -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' `
        -Name 'SubscribedContent-353696Enabled' -Value 0 `
        -Description "Disable additional suggestions"

    # Disable App Notifications
    Set-RegistryValueWithBackup -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications' `
        -Name 'EnableAccountNotifications' -Value 0 `
        -Description "Disable Settings App Notifications"

    # Disable Copilot
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' `
        -Name 'TurnOffWindowsCopilot' -Value 1 `
        -Description "Disable Windows Copilot"

    # Disable Lock Screen Content
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' `
        -Name 'DisableLogonBackgroundImage' -Value 1 `
        -Description "Disable Dynamic Lock Screen Content"

    # Disable Game DVR and Game Bar
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR' `
        -Name 'AllowGameDVR' -Value 0 `
        -Description "Disable Game DVR"
        
    Write-Log "Windows privacy settings configuration completed" -Level 'Info'        
     
}   

function Set-AppPermissions {
    Write-Log "Configuring Windows App Permissions..." -Level 'Info'

    # App Permissions Privacy Settings
    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone' `
        -Name 'Value' -Value 'Deny' `
        -Description "Disable Microphone Access by Default"

    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam' `
        -Name 'Value' -Value 'Deny' `
        -Description "Disable Camera Access by Default"

    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation' `
        -Name 'Value' -Value 'Deny' `
        -Description "Disable Account Info Access"

    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts' `
        -Name 'Value' -Value 'Deny' `
        -Description "Disable Contacts Access"

    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments' `
        -Name 'Value' -Value 'Deny' `
        -Description "Disable Calendar Access"

    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall' `
        -Name 'Value' -Value 'Deny' `
        -Description "Disable Phone Call Access"

    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios' `
        -Name 'Value' -Value 'Deny' `
        -Description "Disable Radios Access"

    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync' `
        -Name 'Value' -Value 'Deny' `
        -Description "Disable Bluetooth Access"

    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess' `
        -Name 'Value' -Value 'Deny' `
        -Description "Disable Broad File System Access"

    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary' `
        -Name 'Value' -Value 'Deny' `
        -Description "Disable Documents Library Access"

    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary' `
        -Name 'Value' -Value 'Deny' `
        -Description "Disable Pictures Library Access"

    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary' `
        -Name 'Value' -Value 'Deny' `
        -Description "Disable Videos Library Access"

    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary' `
        -Name 'Value' -Value 'Deny' `
        -Description "Disable Music Library Access"

    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email' `
        -Name 'Value' -Value 'Deny' `
        -Description "Disable Email Access by Default"

    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks' `
        -Name 'Value' -Value 'Deny' `
        -Description "Disable Tasks Access by Default"

    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat' `
        -Name 'Value' -Value 'Deny' `
        -Description "Disable Messaging/Chat Access"

    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder' `
        -Name 'Value' -Value 'Deny' `
        -Description "Disable Downloads Folder Access"

    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureProgrammatic' `
        -Name 'Value' -Value 'Deny' `
        -Description "Disable Screen Capture Access"

    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureWithoutBorder' `
        -Name 'Value' -Value 'Deny' `
        -Description "Disable Borderless Screen Capture"

    Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\screenshot' `
        -Name 'Value' -Value 'Deny' `
        -Description "Disable Screenshot Capability"   

    Write-Log "Windows App Permissions configuration completed" -Level 'Info'        
     
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

    Write-Log "Windows Update Delivery Optimization configuration completed" -Level 'Info'   
       
}

# Hosts File Management
function Update-HostsFile {
    param (
        [string]$HageziUrl = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/native.winoffice.txt"
    )
    
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $backupPath = "$env:SystemRoot\System32\drivers\etc\hosts.backup.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    $tempHostsPath = "$env:TEMP\hosts.tmp"
    
    try {
        # Download Hagezi's blocklist first to validate we can get the content
        Write-Log "Downloading Hagezi's blocklist..." -Level 'Info'
        $webClient = New-Object System.Net.WebClient
        $hageziContent = $webClient.DownloadString($HageziUrl)
        
        # Parse domains from Hagezi's list
        $domains = $hageziContent -split "`n" | Where-Object {
            $_ -match '^0\.0\.0\.0\s+(.+)$'
        } | ForEach-Object {
            ($_ -split '\s+')[1]
        }
        
        Write-Log "Downloaded ${domains.Count} domains from Hagezi's list" -Level 'Info'
        
        # Prepare new hosts file content
        $newContent = @(
            "# Windows 11 Privacy Optimization - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            "# Using Hagezi's Windows/Office Tracker Blocklist"
            "# Source: $HageziUrl"
            "# Last updated: $(Get-Date)"
            ""
            "# localhost entries"
            "127.0.0.1 localhost"
            "::1 localhost"
            ""
            "# Blocked domains for privacy"
        )

        # Add domains to hosts file
        $newContent += $domains | ForEach-Object { "0.0.0.0 $_" }
        
        # Create backup if original exists
        if (Test-Path $hostsPath) {
            Write-Log "Creating backup of hosts file..." -Level 'Info'
            $backupScript = @"
                Copy-Item -Path '$hostsPath' -Destination '$backupPath' -Force
                if (`$?) { Write-Host 'Backup created successfully' }
"@
            Start-Process powershell -Verb RunAs -ArgumentList "-Command", $backupScript -Wait
        }

        # Write new content to hosts file using PowerShell with elevated privileges
        Write-Log "Updating hosts file..." -Level 'Info'
        $newContent = $newContent -join "`r`n"
        $updateScript = @"
            Set-Content -Path '$hostsPath' -Value @'
$newContent
'@ -Force -Encoding ASCII
            if (`$?) { 
                Write-Host 'Hosts file updated successfully'
                ipconfig /flushdns | Out-Null
            }
"@
        
        # Execute the update with elevated privileges
        $result = Start-Process powershell -Verb RunAs -ArgumentList "-Command", $updateScript -Wait -PassThru
        
        if ($result.ExitCode -eq 0) {
            Write-Log "Hosts file successfully updated with $($domains.Count) domains" -Level 'Info'
            Write-Log "DNS cache flushed" -Level 'Info'
            return $true
        } else {
            throw "Failed to update hosts file"
        }
    }
    catch {
        Write-Log "Error updating hosts file: $($_.Exception.Message)" -Level 'Error'
        Write-Log "Please ensure you have administrator rights and the hosts file is not read-only" -Level 'Warning'
        return $false
    }
}
function Remove-OldBackups {
    
    Write-Log "Starting cleanup of old backups and logs..." -Level 'Info'
    
    try {
        # Cleanup hosts file backups - keep only 5 most recent
        $hostsBackupPath = "$env:SystemRoot\System32\drivers\etc"
        $hostsBackups = Get-ChildItem -Path $hostsBackupPath -Filter "hosts.backup*" | 
                       Sort-Object LastWriteTime -Descending
        
        if ($hostsBackups.Count -gt 2) {
            $hostsBackups | Select-Object -Skip 2 | ForEach-Object {
                try {
                    Remove-Item $_.FullName -Force
                    Write-Log "Removed old hosts backup: $($_.Name)" -Level 'Info'
                }
                catch {
                    Write-Log "Failed to remove hosts backup $($_.Name): $($_.Exception.Message)" -Level 'Error'
                }
            }
        }
        
        # Cleanup old log files (older than 30 days)
        $logFolder = "C:\Windows\Logs\PrivacyOptimizer"
        if (Test-Path $logFolder) {
            $oldLogs = Get-ChildItem -Path $logFolder -Filter "privacy_*.log" | 
                      Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) }
            
            foreach ($log in $oldLogs) {
                try {
                    Remove-Item $log.FullName -Force
                    Write-Log "Removed old log file: $($log.Name)" -Level 'Info'
                }
                catch {
                    Write-Log "Failed to remove log file $($log.Name): $($_.Exception.Message)" -Level 'Error'
                }
            }
        }
        
        Write-Log "Cleanup completed successfully" -Level 'Info'
        return $true
    }
    catch {
        Write-Log "Error during cleanup: $($_.Exception.Message)" -Level 'Error'
        return $false
    }
}

# Interactive Menu
function Show-Menu {
    Clear-Host
    $border = '==========================================='
    $title = '         Windows 11 Privacy Tool          
                        v 1.2.0 '
    Write-Host $border -ForegroundColor Cyan
    Write-Host $title -ForegroundColor Cyan
    Write-Host $border -ForegroundColor Cyan
    Write-Host
    Write-Host 'Using hagezi Windows/Office blocklist' -ForegroundColor DarkCyan
    Write-Host 'https://github.com/hagezi' -ForegroundColor DarkCyan
    Write-Host
    Write-Host 'Created by minzi90' -ForegroundColor DarkCyan
    Write-Host 'https://github.com/minzi90' -ForegroundColor DarkCyan
    Write-Host $border -ForegroundColor Cyan
    Write-Host
    Write-Host '[1] Restrict Windows Update Delivery Optimization' -ForegroundColor White
    Write-Host '[2] Enable Hosts File Blocking' -ForegroundColor White
    Write-Host '[3] Optimize Windows Privacy Settings' -ForegroundColor White
    Write-Host '[4] Configure App Permissions' -ForegroundColor White
    Write-Host '[5] Run All Optimizations' -ForegroundColor White
    Write-Host '[6] Revert Changes' -ForegroundColor White
    Write-Host '    - Only reverts changes made in this session' -ForegroundColor Yellow
    Write-Host '[7] Cleanup Old Backups and Logs' -ForegroundColor White
    Write-Host '[8] Exit' -ForegroundColor White
    Write-Host
    
    
        do {
            Write-Host "Select an option (1-8): " -ForegroundColor White -NoNewline
            $choice = Read-Host
            if ($choice -match '^[1-8]$') {
                break
            }
            Write-Host "Invalid input. Please enter a number between 1 and 8." -ForegroundColor Red
        } while ($true)
        
        if ($choice -in @('3','4','5')) {
            do {
                $createRestorePoint = Read-Host 'Create system restore point before making changes? (y/N)'
                if ($createRestorePoint -match '^[yYnN]?$') {
                    break
                }
                Write-Host "Invalid input. Please enter 'y' or 'n' (or press Enter for No)." -ForegroundColor Red
            } while ($true)
            
            if ($createRestorePoint -eq 'y') {
                if (-not (New-SystemRestorePoint)) {
                    do {
                        $proceed = Read-Host 'Failed to create restore point. Continue anyway? (y/N)'
                        if ($proceed -match '^[yYnN]?$') {
                            break
                        }
                        Write-Host "Invalid input. Please enter 'y' or 'n' (or press Enter for No)." -ForegroundColor Red
                    } while ($true)
                    
                    if ($proceed -ne 'y') {
                        return $null
                    }
                }
            }
        }
        
        return $choice
    }

# Main Program Loop
$script:registryBackups = @()

do {
    $choice = Show-Menu
    
    if ($null -eq $choice) { 
        continue 
    }
    
    switch ($choice) {
        1 { Set-DeliveryOptimization }
        2 { Update-HostsFile }
        3 { 
            $featureAvailability = Test-PrivacyFeatureAvailability -Compatibility $script:compatibility
            Set-WindowsPrivacy
        }
        4 { Set-AppPermissions }

        5 {
            Write-Log 'Running all optimizations...' -Level Info
            $featureAvailability = Test-PrivacyFeatureAvailability -Compatibility $script:compatibility
            Set-DeliveryOptimization
            Set-WindowsPrivacy
            Set-AppPermissions
            Update-HostsFile 
        }
        6 {
            Write-Log 'Restoring backup values...' -Level Info
            foreach ($backup in $script:registryBackups) {
                Set-ItemProperty -Path $backup.Path -Name $backup.Name -Value $backup.Value
                Write-Log "Restored: $($backup.Path)\$($backup.Name) = $($backup.Value)" -Level 'Info'
            }
            if (Test-Path "$env:SystemRoot\System32\drivers\etc\hosts.backup") {
                Copy-Item "$env:SystemRoot\System32\drivers\etc\hosts.backup" "$env:SystemRoot\System32\drivers\etc\hosts" -Force
                Write-Log 'Hosts file restored from backup' -Level 'Info'
            }
        }
        7 { 
            Write-Log 'Starting cleanup operation...' -Level 'Info'
            if (Remove-OldBackups) {
                Write-Log 'Cleanup completed successfully' -Level 'Info'
            } else {
                Write-Log 'Cleanup operation encountered some errors' -Level 'Warning'
            }
        }
        8 {
            Write-Log 'Program terminated' -Level 'Info'
            exit
        }
        default { Write-Log 'Invalid selection' -Level 'Warning' }
    }
    
    if ($choice -ne 8) {
        Write-Host
        Write-Host '===========================================' -ForegroundColor Yellow
        Write-Host 'Press any key to return to menu...' -ForegroundColor Green
        Write-Host '===========================================' -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
} while ($choice -ne 8)
