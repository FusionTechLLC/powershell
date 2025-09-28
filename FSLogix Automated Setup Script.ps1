# FSLogix Automated Setup Script
# This script creates the FSLogix share and configures Group Policy settings
# Based on successful home lab configuration

#========================================================================
# CONFIGURATION VARIABLES - EDIT THESE FOR YOUR ENVIRONMENT
#========================================================================

# File Server Configuration
$FileServerName = "YourDomainName"                    # Name of server hosting FSLogix share
$ShareDriveLetter = "C"                     # Drive letter where FSLogix folder will be created
$ShareFolderName = "FSLogix"                # Name of the folder to create (without drive letter)
$ShareName = "FSLogix$"                     # Name of the SMB share ($ makes it hidden)

# Group Policy Configuration  
$GPOName = "FSLogix Profile Containers"     # Name of the Group Policy Object to create
$DomainDN = "DC=YourDomainName,DC=net"        # Domain Distinguished Name for GPO linking

# FSLogix Container Settings
$ContainerSizeGB = 30                       # Default container size in GB (30GB = 30720MB)
$IncludeAllUsers = "S-1-1-0"               # SID for "Everyone" - includes all domain users
$VHDType = "VHDX"                          # Container format (VHDX recommended for performance)

# MIGRATION FROM ROAMING PROFILES (Optional)
# ============================================
# Only use this if you currently have traditional roaming profiles and want to 
# automatically convert them to FSLogix containers.
#
# TO ENABLE MIGRATION:
# Remove the # from the line below and change the path to your roaming profile share
#
# BEFORE (migration disabled):
# $OldProfileShare = "\\OldServer\profiles$"
#
# AFTER (migration enabled):
$OldProfileShare = "\\YourFileServer\YourProfileShare$"
#
# Replace "YourFileServer" and "YourProfileShare$" with your actual server and share names
# Example: $OldProfileShare = "\\FileServer01\UserProfiles$"



#========================================================================
# SCRIPT EXECUTION - DO NOT MODIFY BELOW THIS LINE
#========================================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "FSLogix Automated Setup Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "File Server: $FileServerName" -ForegroundColor White
Write-Host "Share Location: ${ShareDriveLetter}:\$ShareFolderName" -ForegroundColor White
Write-Host "Share Name: $ShareName" -ForegroundColor White
Write-Host "GPO Name: $GPOName" -ForegroundColor White
Write-Host ""

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: This script must be run as Administrator" -ForegroundColor Red
    Write-Host "Please restart PowerShell as Administrator and try again" -ForegroundColor Red
    exit 1
}

#========================================================================
# PART 1: CREATE FSLOGIX SHARE INFRASTRUCTURE
#========================================================================

Write-Host "PART 1: Creating FSLogix Share Infrastructure" -ForegroundColor Yellow
Write-Host "=============================================" -ForegroundColor Yellow

# Create the FSLogix folder on the specified drive
$SharePath = "$ShareDriveLetter" + ":\" + "$ShareFolderName"
Write-Host "Creating folder: $SharePath" -ForegroundColor Green

try {
    if (-not (Test-Path $SharePath)) {
        New-Item -Path $SharePath -ItemType Directory -Force | Out-Null
        Write-Host "SUCCESS: Created folder $SharePath" -ForegroundColor Green
    } else {
        Write-Host "INFO: Folder $SharePath already exists" -ForegroundColor Yellow
    }
} catch {
    Write-Host "ERROR: Failed to create folder $SharePath - $_" -ForegroundColor Red
    exit 1
}

# Set NTFS permissions on the FSLogix folder
Write-Host "Setting NTFS permissions on $SharePath" -ForegroundColor Green

try {
    # Grant Authenticated Users Modify permissions (allows users to create containers)
    icacls $SharePath /grant "Authenticated Users:M" /t | Out-Null
    Write-Host "SUCCESS: Granted Authenticated Users Modify permissions" -ForegroundColor Green
    
    # Grant SYSTEM Full Control (required for FSLogix service operations)
    icacls $SharePath /grant "SYSTEM:F" /t | Out-Null
    Write-Host "SUCCESS: Granted SYSTEM Full Control permissions" -ForegroundColor Green
    
    # Grant Administrators Full Control (for management and troubleshooting)
    icacls $SharePath /grant "Administrators:F" /t | Out-Null
    Write-Host "SUCCESS: Granted Administrators Full Control permissions" -ForegroundColor Green
    
} catch {
    Write-Host "ERROR: Failed to set NTFS permissions - $_" -ForegroundColor Red
    exit 1
}

# Create the SMB network share
Write-Host "Creating SMB share: $ShareName" -ForegroundColor Green

try {
    # Check if share already exists
    $existingShare = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue
    
    if ($existingShare) {
        Write-Host "INFO: Share $ShareName already exists" -ForegroundColor Yellow
    } else {
        # Create new SMB share with Everyone having Full Control at share level
        # (NTFS permissions provide the actual security)
        New-SmbShare -Name $ShareName -Path $SharePath -FullAccess "Everyone" | Out-Null
        Write-Host "SUCCESS: Created SMB share $ShareName" -ForegroundColor Green
    }
} catch {
    Write-Host "ERROR: Failed to create SMB share - $_" -ForegroundColor Red
    exit 1
}

# Verify share accessibility
Write-Host "Verifying share accessibility" -ForegroundColor Green
$ShareUNC = "\\$FileServerName\$ShareName"

try {
    if (Test-Path $ShareUNC) {
        Write-Host "SUCCESS: Share is accessible at $ShareUNC" -ForegroundColor Green
    } else {
        Write-Host "WARNING: Cannot access share at $ShareUNC" -ForegroundColor Yellow
    }
} catch {
    Write-Host "WARNING: Error testing share access - $_" -ForegroundColor Yellow
}

#========================================================================
# PART 2: CREATE AND CONFIGURE GROUP POLICY OBJECT
#========================================================================

Write-Host "`nPART 2: Creating and Configuring Group Policy" -ForegroundColor Yellow
Write-Host "=============================================" -ForegroundColor Yellow

# Import Group Policy PowerShell module
try {
    Import-Module GroupPolicy -ErrorAction Stop
    Write-Host "SUCCESS: Loaded GroupPolicy PowerShell module" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to load GroupPolicy module - $_" -ForegroundColor Red
    Write-Host "Please install Group Policy Management Tools" -ForegroundColor Red
    exit 1
}

# Create or verify Group Policy Object exists
Write-Host "Creating Group Policy Object: $GPOName" -ForegroundColor Green

try {
    # Check if GPO already exists
    $existingGPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
    
    if ($existingGPO) {
        Write-Host "INFO: GPO $GPOName already exists - will update settings" -ForegroundColor Yellow
        $GPO = $existingGPO
    } else {
        # Create new Group Policy Object
        $GPO = New-GPO -Name $GPOName
        Write-Host "SUCCESS: Created new GPO $GPOName" -ForegroundColor Green
    }
} catch {
    Write-Host "ERROR: Failed to create GPO - $_" -ForegroundColor Red
    exit 1
}

#========================================================================
# PART 3: CONFIGURE FSLOGIX REGISTRY SETTINGS IN GPO
#========================================================================

Write-Host "`nPART 3: Configuring FSLogix Registry Settings" -ForegroundColor Yellow
Write-Host "=============================================" -ForegroundColor Yellow

# Registry key path for FSLogix Profile settings
$FSLogixRegKey = "HKEY_LOCAL_MACHINE\SOFTWARE\FSLogix\Profiles"

# Calculate container size in MB for registry setting
$ContainerSizeMB = $ContainerSizeGB * 1024

Write-Host "Configuring FSLogix registry settings in GPO..." -ForegroundColor Green

try {
    # Enable FSLogix Profiles (CRITICAL - without this FSLogix won't activate)
    Set-GPRegistryValue -Name $GPOName -Key $FSLogixRegKey -ValueName "Enabled" -Type DWord -Value 1
    Write-Host "SUCCESS: Set Enabled = 1 (Activates FSLogix Profiles)" -ForegroundColor Green
    
    # Set VHD storage location (tells FSLogix where to store profile containers)
    Set-GPRegistryValue -Name $GPOName -Key $FSLogixRegKey -ValueName "VHDLocations" -Type String -Value $ShareUNC
    Write-Host "SUCCESS: Set VHDLocations = $ShareUNC" -ForegroundColor Green
    
    # Include all users (CRITICAL - S-1-1-0 is SID for "Everyone")
    Set-GPRegistryValue -Name $GPOName -Key $FSLogixRegKey -ValueName "IncludeGroups" -Type String -Value $IncludeAllUsers
    Write-Host "SUCCESS: Set IncludeGroups = $IncludeAllUsers (Everyone)" -ForegroundColor Green
    
    # Enable dynamic VHD expansion (allows containers to grow as needed)
    Set-GPRegistryValue -Name $GPOName -Key $FSLogixRegKey -ValueName "IsDynamic" -Type DWord -Value 1
    Write-Host "SUCCESS: Set IsDynamic = 1 (Dynamic container expansion)" -ForegroundColor Green
    
    # Set default container size in MB
    Set-GPRegistryValue -Name $GPOName -Key $FSLogixRegKey -ValueName "SizeInMBs" -Type DWord -Value $ContainerSizeMB
    Write-Host "SUCCESS: Set SizeInMBs = $ContainerSizeMB ($ContainerSizeGB GB default size)" -ForegroundColor Green
    
    # Set VHD format type (VHDX provides better performance than VHD)
    Set-GPRegistryValue -Name $GPOName -Key $FSLogixRegKey -ValueName "VolumeType" -Type String -Value $VHDType
    Write-Host "SUCCESS: Set VolumeType = $VHDType (Container format)" -ForegroundColor Green
    
} catch {
    Write-Host "ERROR: Failed to configure registry settings - $_" -ForegroundColor Red
    exit 1
}

# Configure migration settings if migrating from roaming profiles
if ($OldProfileShare) {
    Write-Host "Configuring migration settings for roaming profile conversion..." -ForegroundColor Green
    
    try {
        # Tell FSLogix where to find existing roaming profiles for automatic migration
        Set-GPRegistryValue -Name $GPOName -Key $FSLogixRegKey -ValueName "RoamSearch" -Type String -Value $OldProfileShare
        Write-Host "SUCCESS: Set RoamSearch = $OldProfileShare (Migration source)" -ForegroundColor Green
        
        # Enable automatic profile migration on first login
        Set-GPRegistryValue -Name $GPOName -Key $FSLogixRegKey -ValueName "RoamIdentity" -Type DWord -Value 1
        Write-Host "SUCCESS: Set RoamIdentity = 1 (Enable migration)" -ForegroundColor Green
        
        # Keep original roaming profiles after migration (safety measure)
        Set-GPRegistryValue -Name $GPOName -Key $FSLogixRegKey -ValueName "RoamRecycle" -Type DWord -Value 0
        Write-Host "SUCCESS: Set RoamRecycle = 0 (Keep original profiles)" -ForegroundColor Green
        
    } catch {
        Write-Host "ERROR: Failed to configure migration settings - $_" -ForegroundColor Red
    }
} else {
    Write-Host "INFO: Migration not configured - no old profile share specified" -ForegroundColor Yellow
}

#========================================================================
# PART 4: LINK GROUP POLICY TO DOMAIN
#========================================================================

Write-Host "`nPART 4: Linking Group Policy to Domain" -ForegroundColor Yellow
Write-Host "======================================" -ForegroundColor Yellow

try {
    # Attempt to link GPO to domain (applies to all computers in domain)
    Write-Host "Linking GPO $GPOName to domain $DomainDN..." -ForegroundColor Green
    
    # First check if already linked by trying to get existing links
    $domainGPOs = Get-GPInheritance -Target $DomainDN -ErrorAction SilentlyContinue
    $alreadyLinked = $false
    
    if ($domainGPOs) {
        $alreadyLinked = $domainGPOs.GpoLinks | Where-Object {$_.DisplayName -eq $GPOName}
    }
    
    if ($alreadyLinked) {
        Write-Host "INFO: GPO $GPOName is already linked to domain" -ForegroundColor Yellow
    } else {
        # Create the link
        $linkResult = New-GPLink -Name $GPOName -Target $DomainDN -ErrorAction Stop
        Write-Host "SUCCESS: GPO linked to domain successfully" -ForegroundColor Green
        Write-Host "Link Order: $($linkResult.Order)" -ForegroundColor Green
    }
    
    # Verify the link exists by checking domain inheritance again
    Start-Sleep 2  # Give AD time to replicate
    $verifyLinks = Get-GPInheritance -Target $DomainDN -ErrorAction SilentlyContinue
    if ($verifyLinks) {
        $linkedGPO = $verifyLinks.GpoLinks | Where-Object {$_.DisplayName -eq $GPOName}
        if ($linkedGPO) {
            Write-Host "VERIFICATION: GPO is successfully linked and will apply to domain computers" -ForegroundColor Green
        } else {
            Write-Host "WARNING: Could not verify GPO link, check manually" -ForegroundColor Yellow
        }
    }
    
} catch {
    Write-Host "ERROR: Failed to link GPO automatically - $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "MANUAL LINKING REQUIRED:" -ForegroundColor Yellow
    Write-Host "1. Open Group Policy Management Console" -ForegroundColor White
    Write-Host "2. Right-click your domain: linderfusion.net" -ForegroundColor White
    Write-Host "3. Select 'Link an Existing GPO'" -ForegroundColor White
    Write-Host "4. Choose: $GPOName" -ForegroundColor White
    Write-Host "5. Click OK" -ForegroundColor White
}

#========================================================================
# PART 5: GENERATE SETUP SUMMARY AND NEXT STEPS
#========================================================================

Write-Host "`n" + "="*60 -ForegroundColor Cyan
Write-Host "FSLOGIX SETUP COMPLETED SUCCESSFULLY" -ForegroundColor Cyan
Write-Host "="*60 -ForegroundColor Cyan

Write-Host "`nShare Configuration:" -ForegroundColor White
Write-Host "  Local Path: $SharePath"
Write-Host "  Network Path: $ShareUNC"
Write-Host "  Share Name: $ShareName"

Write-Host "`nGroup Policy Configuration:" -ForegroundColor White
Write-Host "  GPO Name: $GPOName"
Write-Host "  Linked to: $DomainDN"
Write-Host "  Registry Path: $FSLogixRegKey"

Write-Host "`nFSLogix Settings Applied:" -ForegroundColor White
Write-Host "  Enabled: 1 (FSLogix activated)"
Write-Host "  VHDLocations: $ShareUNC"
Write-Host "  IncludeGroups: $IncludeAllUsers (Everyone)"
Write-Host "  IsDynamic: 1 (Dynamic expansion)"
Write-Host "  SizeInMBs: $ContainerSizeMB ($ContainerSizeGB GB)"
Write-Host "  VolumeType: $VHDType"

Write-Host "`nNext Steps:" -ForegroundColor Yellow
Write-Host "1. Install FSLogix agent on VDA machines (FSLogixAppsSetup.exe /install /quiet)"
Write-Host "2. Run 'gpupdate /force' on VDA machines to apply policy"
Write-Host "3. Restart FSLogix service on VDAs: Restart-Service frxsvc -Force"
Write-Host "4. Clear any existing AD profile paths: Set-ADUser username -ProfilePath `$null"
Write-Host "5. Test user login to verify container creation"

Write-Host "`nVerification Commands:" -ForegroundColor Cyan
Write-Host "On VDA: Get-ItemProperty 'HKLM:\SOFTWARE\FSLogix\Profiles'"
Write-Host "On VDA: Get-Service frxsvc"
Write-Host "On DC: dir $SharePath"

Write-Host "`nTroubleshooting:" -ForegroundColor Cyan
Write-Host "Event Logs: Get-WinEvent -LogName 'Microsoft-FSLogix-Apps/Operational'"
Write-Host "Debug Logs: C:\ProgramData\FSLogix\Logs\Profile\"

Write-Host "`nScript completed at $(Get-Date)" -ForegroundColor Green
Write-Host "="*60 -ForegroundColor Cyan