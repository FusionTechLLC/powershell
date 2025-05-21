# Install-RSAT-Enhanced.ps1
# Purpose:
#   This PowerShell script installs Remote Server Administration Tools (RSAT) features on Windows systems.
#   RSAT tools enable remote management of Windows servers. The script supports interactive selection of
#   features, JSON configuration, retry logic, and comprehensive logging.
#
# Requirements:
#   - PowerShell 4.0 or later (recommended PowerShell 5.1+)
#   - Windows 10/Server 2016 or later (for newer RSAT feature model)
#   - Administrative privileges
#   - Internet connectivity for downloading components
#
# Steps:
#   1. Define Parameters:
#      - Accepts RSAT feature names, force reinstall, quiet mode, log path, JSON config path, and retry count.
#   2. Check Prerequisites:
#      - Verifies administrative privileges, Windows edition, PowerShell version, and internet connectivity.
#   3. Load Features:
#      - Supports manual input, JSON config, or interactive menu for selecting RSAT features.
#   4. Install Features:
#      - Checks and installs each feature with retry logic and progress bar.
#   5. Logging and Feedback:
#      - Logs actions to a file and console with color-coded output (unless -Quiet is used).
#   6. Post-Installation:
#      - Verifies installations, checks for restart requirements, and lists installed RSAT tools.
#
# Usage Examples:
#   - Default: .\Install-RSAT-Enhanced.ps1
#   - Multiple features: .\Install-RSAT-Enhanced.ps1 -RsatFeatures "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0","Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0"
#   - JSON config: .\Install-RSAT-Enhanced.ps1 -ConfigPath "C:\Temp\rsat-config.json"
#   - Interactive mode: .\Install-RSAT-Enhanced.ps1 -Interactive
#   - Quiet mode: .\Install-RSAT-Enhanced.ps1 -Quiet

param (
    [string[]]$RsatFeatures = @("Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"),
    [switch]$Force,
    [switch]$Quiet,
    [string]$LogPath = "$env:USERPROFILE\Desktop\RSAT_Install_Log.txt",
    [string]$ConfigPath = "",
    [switch]$Interactive,
    [int]$MaxRetries = 2
)

# Check PowerShell version
$psVersion = $PSVersionTable.PSVersion
$minVersion = [version]"4.0"
if ($psVersion -lt $minVersion) {
    Write-Host "WARNING: This script requires PowerShell 4.0 or later. Current version: $psVersion" -ForegroundColor Red
    Write-Host "Some features may not work correctly. Please update PowerShell." -ForegroundColor Red
    $continue = Read-Host "Continue anyway? (y/n)"
    if ($continue -ne 'y') {
        exit 1
    }
}

# Function to ensure log directory exists
function Ensure-LogPathExists {
    param (
        [string]$Path
    )
    try {
        $logDir = Split-Path -Path $Path -Parent
        if (-not (Test-Path -Path $logDir -PathType Container)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            return $true
        }
        return $true
    } catch {
        Write-Host "ERROR: Failed to create log directory: $_" -ForegroundColor Red
        return $false
    }
}

# Ensure log path exists
if (-not (Ensure-LogPathExists -Path $LogPath)) {
    $LogPath = "$env:TEMP\RSAT_Install_Log.txt"
    Write-Host "Using alternative log path: $LogPath" -ForegroundColor Yellow
    if (-not (Ensure-LogPathExists -Path $LogPath)) {
        Write-Host "ERROR: Cannot create log file. Continuing without file logging." -ForegroundColor Red
        $LogPath = $null
    }
}

# Function to write log messages
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    if (-not $Quiet) {
        switch ($Level) {
            "INFO"  { Write-Host $logMessage -ForegroundColor Green }
            "WARN"  { Write-Host $logMessage -ForegroundColor Yellow }
            "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        }
    }
    if ($LogPath) {
        try {
            $logMessage | Out-File -FilePath $LogPath -Append -Encoding UTF8 -ErrorAction Stop
        } catch {
            if (-not $Quiet) {
                Write-Host "Failed to write to log file: $_" -ForegroundColor Red
            }
        }
    }
}

# Function to check if restart is pending
function Test-PendingReboot {
    $rebootPending = $false
    
    # Check for Windows Update reboot flag
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
        $rebootPending = $true
    }
    
    # Check for pending file rename operations
    if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager") {
        $pendingFileRename = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
        if ($pendingFileRename -and $pendingFileRename.PendingFileRenameOperations) {
            $rebootPending = $true
        }
    }
    
    # Check for Component-Based Servicing reboot flag
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
        $rebootPending = $true
    }
    
    return $rebootPending
}

# Function to get available RSAT features
function Get-AvailableRsatFeatures {
    try {
        $features = Get-WindowsCapability -Online -ErrorAction Stop | Where-Object { $_.Name -like "Rsat*" }
        if ($null -eq $features) {
            Write-Log -Message "No RSAT features found. Check Windows version and internet connectivity." -Level "ERROR"
            return @()
        }
        return $features | Select-Object -Property Name, DisplayName, State
    } catch {
        Write-Log -Message "Error retrieving RSAT features: $_" -Level "ERROR"
        return @()
    }
}

# Function to display interactive menu
function Show-RsatMenu {
    $features = Get-AvailableRsatFeatures
    if ($features.Count -eq 0) {
        Write-Log -Message "No RSAT features found to display in menu." -Level "ERROR"
        return @()
    }
    
    Write-Log -Message "Select RSAT features to install (enter numbers, separated by commas, e.g., 1,3):" -Level "INFO"
    Write-Log -Message "Currently installed features are marked with [*]" -Level "INFO"
    
    $index = 1
    $menu = @{}
    foreach ($feature in $features) {
        $status = if ($feature.State -eq "Installed") { "[*]" } else { "[ ]" }
        Write-Log -Message "$index. $status $($feature.DisplayName) ($($feature.Name))" -Level "INFO"
        $menu[$index] = $feature.Name
        $index++
    }
    
    $selection = Read-Host "Enter selection (or 'q' to quit, 'a' for all)"
    if ($selection -eq 'q') { 
        return @() 
    }
    
    if ($selection -eq 'a') {
        return $features | Select-Object -ExpandProperty Name
    }
    
    $selectedFeatures = @()
    $selectedIndices = $selection -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' }
    
    if ($selectedIndices.Count -eq 0) {
        Write-Log -Message "Invalid selection. Please enter numbers separated by commas." -Level "WARN"
        return Show-RsatMenu  # Recursive call to try again
    }
    
    foreach ($i in $selectedIndices) {
        if ($menu.ContainsKey([int]$i)) {
            $selectedFeatures += $menu[[int]$i]
        } else {
            Write-Log -Message "Invalid selection number: $i" -Level "WARN"
        }
    }
    
    if ($selectedFeatures.Count -eq 0) {
        Write-Log -Message "No valid features selected." -Level "WARN"
        return Show-RsatMenu  # Recursive call to try again
    }
    
    return $selectedFeatures
}

# Function to load features from JSON
function Get-FeaturesFromJson {
    param (
        [string]$Path
    )
    if (-not (Test-Path $Path)) {
        Write-Log -Message "JSON config file not found: $Path" -Level "ERROR"
        return @()
    }
    try {
        $json = Get-Content -Path $Path -Raw | ConvertFrom-Json
        if (-not (Get-Member -InputObject $json -Name "RsatFeatures" -MemberType Properties)) {
            Write-Log -Message "JSON file does not contain 'RsatFeatures' property" -Level "ERROR"
            return @()
        }
        
        if ($json.RsatFeatures -isnot [Array]) {
            Write-Log -Message "RsatFeatures in JSON is not an array" -Level "ERROR"
            return @()
        }
        
        return $json.RsatFeatures
    } catch {
        Write-Log -Message "Error parsing JSON config: $_" -Level "ERROR"
        return @()
    }
}

# Function to verify RSAT feature format
function Test-RsatFeatureFormat {
    param (
        [string[]]$Features
    )
    $validFeatures = @()
    $invalidFeatures = @()
    
    foreach ($feature in $Features) {
        if ($feature -match "^Rsat\..+(\~{4}).+$") {
            $validFeatures += $feature
        } else {
            $invalidFeatures += $feature
        }
    }
    
    if ($invalidFeatures.Count -gt 0) {
        Write-Log -Message "The following features have invalid format and will be skipped:" -Level "WARN"
        foreach ($invalid in $invalidFeatures) {
            Write-Log -Message "  - $invalid" -Level "WARN"
        }
    }
    
    return $validFeatures
}

# Log system details and script integrity
Write-Log -Message "System Diagnostics:" -Level "INFO"
Write-Log -Message "PowerShell Version: $($PSVersionTable.PSVersion)" -Level "INFO"
Write-Log -Message "Windows Edition: $((Get-WmiObject Win32_OperatingSystem).Caption)" -Level "INFO"
Write-Log -Message "Script Path: $PSCommandPath" -Level "INFO"

if (Test-Path $PSCommandPath) {
    if ($PSVersionTable.PSVersion.Major -ge 4) {
        $hash = (Get-FileHash -Path $PSCommandPath -Algorithm SHA256).Hash
        Write-Log -Message "Script SHA256 Hash: $hash" -Level "INFO"
    } else {
        Write-Log -Message "Script hash calculation requires PowerShell 4.0+" -Level "INFO"
    }
}

# Check for administrative privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Log -Message "This script requires administrative privileges. Please run as Administrator." -Level "ERROR"
    exit 1
}

# Check Windows edition
$osCaption = (Get-WmiObject Win32_OperatingSystem).Caption
$osVersion = [System.Environment]::OSVersion.Version

if ($osVersion.Major -lt 10) {
    Write-Log -Message "This script requires Windows 10/Server 2016 or later for the DISM-based RSAT feature model." -Level "ERROR"
    Write-Log -Message "Current Windows version: $osCaption (Version $osVersion)" -Level "ERROR"
    Write-Log -Message "For older Windows versions, please use the classic RSAT installer package." -Level "ERROR"
    exit 1
}

if ($osCaption -notlike "*Pro*" -and $osCaption -notlike "*Professional*" -and $osCaption -notlike "*Enterprise*" -and $osCaption -notlike "*Education*" -and $osCaption -notlike "*Server*") {
    Write-Log -Message "RSAT tools require Windows Pro, Professional, Enterprise, Education, or Server editions." -Level "ERROR"
    Write-Log -Message "Current edition: $osCaption" -Level "ERROR"
    exit 1
}

# Check internet connectivity
$internetCheck = Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet
if (-not $internetCheck) {
    Write-Log -Message "No internet connection detected. RSAT installation requires internet access to download components." -Level "WARN"
    $continueOffline = Read-Host "Continue without internet connection? (y/n)"
    if ($continueOffline -ne 'y') {
        exit 1
    }
}

# Parameter consistency check
if ($Interactive -and $ConfigPath) {
    Write-Log -Message "Both -Interactive and -ConfigPath specified. Interactive mode will take precedence." -Level "WARN"
}

# Load features from sources based on parameters
$featuresToInstall = @()

if ($Interactive) {
    Write-Log -Message "Interactive mode selected. Displaying menu..." -Level "INFO"
    $featuresToInstall = Show-RsatMenu
} elseif ($ConfigPath) {
    Write-Log -Message "Loading features from config file: $ConfigPath" -Level "INFO"
    $featuresToInstall = Get-FeaturesFromJson -Path $ConfigPath
} else {
    Write-Log -Message "Using specified features from parameters" -Level "INFO"
    $featuresToInstall = $RsatFeatures
}

# Validate feature formats
$featuresToInstall = Test-RsatFeatureFormat -Features $featuresToInstall

# Exit if no features to install
if ($featuresToInstall.Count -eq 0) {
    Write-Log -Message "No valid RSAT features selected for installation." -Level "WARN"
    exit 0
}

# Log selected features
Write-Log -Message "Features selected for installation ($($featuresToInstall.Count)):" -Level "INFO"
foreach ($feature in $featuresToInstall) {
    Write-Log -Message "  - $feature" -Level "INFO"
}

# Initialize results array
$results = @()

# Process each RSAT feature
$totalFeatures = $featuresToInstall.Count
$currentFeature = 0

foreach ($feature in $featuresToInstall) {
    $currentFeature++
    $percentComplete = ($currentFeature / $totalFeatures) * 100
    
    if (-not $Quiet) {
        Write-Progress -Activity "Installing RSAT Features" -Status "Processing $feature ($currentFeature of $totalFeatures)" -PercentComplete $percentComplete
    }
    
    Write-Log -Message "Checking status of $feature..." -Level "INFO"
    
    $retryCount = 0
    $success = $false
    
    while ($retryCount -le $MaxRetries -and -not $success) {
        try {
            $featureStatus = Get-WindowsCapability -Name $feature -Online -ErrorAction Stop
            
            if ($null -eq $featureStatus) {
                Write-Log -Message "Feature $feature not found in Windows catalog." -Level "ERROR"
                $results += [PSCustomObject]@{ 
                    Feature = $feature
                    Status = "Not Found" 
                    Success = $false 
                }
                $success = $true  # Mark as processed to avoid retries
                continue
            }
            
            $installed = $featureStatus.State
            
            # Handle different feature states
            switch ($installed) {
                "Installed" {
                    if ($Force) {
                        Write-Log -Message "$feature is already installed but will be reinstalled due to -Force parameter." -Level "INFO"
                    } else {
                        Write-Log -Message "$feature is already installed. Use -Force to reinstall." -Level "INFO"
                        $results += [PSCustomObject]@{ 
                            Feature = $feature
                            Status = "Already Installed" 
                            Success = $true 
                        }
                        $success = $true
                        continue
                    }
                }
                "NotPresent" {
                    Write-Log -Message "$feature is not present and will be installed." -Level "INFO"
                }
                "Staged" {
                    Write-Log -Message "$feature is staged and will be completed." -Level "INFO"
                }
                "Removed" {
                    Write-Log -Message "$feature was removed and will be reinstalled." -Level "INFO"
                }
                default {
                    Write-Log -Message "$feature has unknown state: $installed. Will attempt installation." -Level "WARN"
                }
            }
            
            # Proceed with installation if feature needs to be installed/reinstalled
            Write-Log -Message "Installing $feature (Attempt $($retryCount + 1) of $($MaxRetries + 1))..." -Level "INFO"
            
            # Suppress inner progress bars to avoid visual clutter
            $prevProgressPref = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'
            
            Add-WindowsCapability -Name $feature -Online -ErrorAction Stop | Out-Null
            
            # Restore progress preference
            $ProgressPreference = $prevProgressPref
            
            # Verify installation
            $postInstallState = Get-WindowsCapability -Name $feature -Online -ErrorAction Stop
            
            if ($null -eq $postInstallState) {
                Write-Log -Message "Failed to verify installation of $feature - Feature not found after installation." -Level "ERROR"
                $results += [PSCustomObject]@{ 
                    Feature = $feature
                    Status = "Verification Failed - Feature Not Found" 
                    Success = $false 
                }
                $success = $true  # Mark as processed to avoid endless retries
                continue
            }
            
            if ($postInstallState.State -eq "Installed") {
                Write-Log -Message "$feature installed successfully." -Level "INFO"
                $results += [PSCustomObject]@{ 
                    Feature = $feature
                    Status = "Installed" 
                    Success = $true 
                }
                $success = $true
            } else {
                Write-Log -Message "Failed to verify installation of $feature. State: $($postInstallState.State)" -Level "ERROR"
                $results += [PSCustomObject]@{ 
                    Feature = $feature
                    Status = "Verification Failed - State: $($postInstallState.State)" 
                    Success = $false 
                }
                $retryCount++
                
                if ($retryCount -le $MaxRetries) {
                    Write-Log -Message "Retrying $feature in 5 seconds..." -Level "WARN"
                    Start-Sleep -Seconds 5
                } else {
                    $success = $true  # Mark as processed after max retries
                }
            }
        } catch {
            Write-Log -Message "Error processing $feature (Attempt $($retryCount + 1)) - $_" -Level "ERROR"
            
            $results += [PSCustomObject]@{ 
                Feature = $feature
                Status = "Error: $_" 
                Success = $false 
            }
            
            $retryCount++
            
            if ($retryCount -le $MaxRetries) {
                Write-Log -Message "Retrying $feature in 5 seconds..." -Level "WARN"
                Start-Sleep -Seconds 5
            } else {
                $success = $true  # Mark as processed after max retries
            }
        }
    }
}

# Clear progress bar
if (-not $Quiet) {
    Write-Progress -Activity "Installing RSAT Features" -Completed
}

# Check for restart requirement with proper method
$restartNeeded = Test-PendingReboot
if ($restartNeeded -and -not $Quiet) {
    Write-Log -Message "A system restart is required to complete the installation." -Level "WARN"
    $restart = Read-Host "Restart now? (y/n)"
    if ($restart -eq 'y') {
        Write-Log -Message "Initiating system restart..." -Level "INFO"
        Restart-Computer -Force
    }
}

# Display summary
Write-Log -Message "Installation Summary:" -Level "INFO"

# Count successes and failures
$successCount = ($results | Where-Object { $_.Success -eq $true }).Count
$failureCount = ($results | Where-Object { $_.Success -eq $false }).Count

Write-Log -Message "Total features processed: $($results.Count)" -Level "INFO"
Write-Log -Message "Successfully installed/verified: $successCount" -Level "INFO"
Write-Log -Message "Failed: $failureCount" -Level "INFO"

# Detailed results
foreach ($result in $results) {
    $level = if ($result.Success) { "INFO" } else { "ERROR" }
    Write-Log -Message "Feature: $($result.Feature), Status: $($result.Status)" -Level $level
}

# List installed RSAT tools if not in quiet mode
if (-not $Quiet) {
    Write-Log -Message "Listing all installed RSAT tools:" -Level "INFO"
    try {
        $installedFeatures = Get-WindowsCapability -Online | Where-Object { $_.Name -like "Rsat*" -and $_.State -eq "Installed" }
        
        if ($null -eq $installedFeatures -or $installedFeatures.Count -eq 0) {
            Write-Log -Message "No RSAT tools are currently installed." -Level "INFO"
        } else {
            Write-Log -Message "Found $($installedFeatures.Count) installed RSAT tools:" -Level "INFO"
            foreach ($feature in $installedFeatures) {
                Write-Log -Message "  $($feature.DisplayName) ($($feature.Name))" -Level "INFO"
            }
        }
    } catch {
        Write-Log -Message "Error listing installed RSAT tools: $_" -Level "ERROR"
    }
}

# Return success if at least one feature was successfully installed/verified
if ($successCount -gt 0) {
    exit 0
} else {
    exit 1
}