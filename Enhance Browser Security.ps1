#requires -RunAsAdministrator

# PowerShell script to enforce browser security settings and delete stored passwords for Chrome, Edge, and Firefox

# Function to check if a registry key exists
function Test-RegistryKey {
    param (
        [string]$Path
    )
    return Test-Path -Path $Path
}

# Function to check and report registry value
function Check-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$ExpectedValue,
        [string]$SettingDescription
    )
    if (Test-RegistryKey $Path) {
        $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($value -and $value.$Name -eq $ExpectedValue) {
            Write-Host "[PASS] $SettingDescription is correctly set to $ExpectedValue"
        } else {
            Write-Host "[FAIL] $SettingDescription is not set correctly. Current value: $($value.$Name)"
        }
    } else {
        Write-Host "[FAIL] $SettingDescription registry key does not exist"
    }
}

# Function to stop browser processes
function Stop-BrowserProcesses {
    param (
        [string]$ProcessName
    )
    Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

# Function to delete stored passwords and verify
function Remove-BrowserPasswords {
    param (
        [string]$BrowserName,
        [string[]]$FilePaths
    )
    Write-Host "Removing stored passwords for $BrowserName..."
    $filesExist = $false
    foreach ($file in $FilePaths) {
        if (Test-Path $file) {
            $filesExist = $true
            try {
                Remove-Item -Path $file -Force -ErrorAction Stop
                Write-Host "[PASS] Deleted $file"
            } catch {
                Write-Host "[FAIL] Error deleting $file : $_"
            }
        }
    }
    if (-not $filesExist) {
        Write-Host "[PASS] No password files found for $BrowserName"
    }
}

# Stop browser processes to avoid file access issues
Stop-BrowserProcesses -ProcessName "chrome"
Stop-BrowserProcesses -ProcessName "msedge"
Stop-BrowserProcesses -ProcessName "firefox"

# Delete stored passwords
# Chrome
$chromeLoginData = "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\Login Data"
$chromeLoginDataJournal = "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\Login Data-journal"
Remove-BrowserPasswords -BrowserName "Chrome" -FilePaths @($chromeLoginData, $chromeLoginDataJournal)

# Edge
$edgeLoginData = "$env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data\Default\Login Data"
$edgeLoginDataJournal = "$env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data\Default\Login Data-journal"
Remove-BrowserPasswords -BrowserName "Edge" -FilePaths @($edgeLoginData, $edgeLoginDataJournal)

# Firefox
$firefoxProfilePath = "$env:USERPROFILE\AppData\Roaming\Mozilla\Firefox\Profiles"
$firefoxProfiles = Get-ChildItem -Path $firefoxProfilePath -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*.default*" }
if ($firefoxProfiles) {
    foreach ($profile in $firefoxProfiles) {
        $profilePath = $profile.FullName
        $firefoxFiles = @("$profilePath\logins.json", "$profilePath\key4.db", "$profilePath\key3.db")
        Remove-BrowserPasswords -BrowserName "Firefox ($($profile.Name))" -FilePaths $firefoxFiles
    }
} else {
    Write-Host "[PASS] No Firefox profiles found"
}

# Create or update registry keys for browser policies
$chromePolicyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
$edgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
$firefoxPolicyPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"

# Ensure policy paths exist
$policyPaths = @($chromePolicyPath, $edgePolicyPath, $firefoxPolicyPath)
foreach ($path in $policyPaths) {
    if (-not (Test-RegistryKey $path)) {
        New-Item -Path $path -Force | Out-Null
    }
}

# 1. Disable Password Saving
New-ItemProperty -Path $chromePolicyPath -Name "PasswordManagerEnabled" -Value 0 -PropertyType DWord -Force | Out-Null
Check-RegistryValue -Path $chromePolicyPath -Name "PasswordManagerEnabled" -ExpectedValue 0 -SettingDescription "Chrome Password Manager"
New-ItemProperty -Path $edgePolicyPath -Name "PasswordManagerEnabled" -Value 0 -PropertyType DWord -Force | Out-Null
Check-RegistryValue -Path $edgePolicyPath -Name "PasswordManagerEnabled" -ExpectedValue 0 -SettingDescription "Edge Password Manager"
New-ItemProperty -Path $firefoxPolicyPath -Name "DisablePasswordManager" -Value 1 -PropertyType DWord -Force | Out-Null
Check-RegistryValue -Path $firefoxPolicyPath -Name "DisablePasswordManager" -ExpectedValue 1 -SettingDescription "Firefox Password Manager"

# 2. Block Risky Downloads (Enable Safe Browsing)
New-ItemProperty -Path $chromePolicyPath -Name "SafeBrowsingProtectionLevel" -Value 2 -PropertyType DWord -Force | Out-Null
Check-RegistryValue -Path $chromePolicyPath -Name "SafeBrowsingProtectionLevel" -ExpectedValue 2 -SettingDescription "Chrome Safe Browsing (Enhanced)"
New-ItemProperty -Path $edgePolicyPath -Name "SmartScreenEnabled" -Value 1 -PropertyType DWord -Force | Out-Null
Check-RegistryValue -Path $edgePolicyPath -Name "SmartScreenEnabled" -ExpectedValue 1 -SettingDescription "Edge SmartScreen"
New-ItemProperty -Path $firefoxPolicyPath -Name "EnableSafeBrowsing" -Value 1 -PropertyType DWord -Force | Out-Null
Check-RegistryValue -Path $firefoxPolicyPath -Name "EnableSafeBrowsing" -ExpectedValue 1 -SettingDescription "Firefox Safe Browsing"

# 3. Enable Phishing and Malware Protection
New-ItemProperty -Path $firefoxPolicyPath -Name "BlockDangerousDownloads" -Value 1 -PropertyType DWord -Force | Out-Null
Check-RegistryValue -Path $firefoxPolicyPath -Name "BlockDangerousDownloads" -ExpectedValue 1 -SettingDescription "Firefox Block Dangerous Downloads"

# 4. Disable JavaScript (Selective use requires manual trusted site configuration)
New-ItemProperty -Path $chromePolicyPath -Name "DefaultJavaScriptSetting" -Value 2 -PropertyType DWord -Force | Out-Null
Check-RegistryValue -Path $chromePolicyPath -Name "DefaultJavaScriptSetting" -ExpectedValue 2 -SettingDescription "Chrome JavaScript Disabled"
New-ItemProperty -Path $edgePolicyPath -Name "DefaultJavaScriptSetting" -Value 2 -PropertyType DWord -Force | Out-Null
Check-RegistryValue -Path $edgePolicyPath -Name "DefaultJavaScriptSetting" -ExpectedValue 2 -SettingDescription "Edge JavaScript Disabled"
New-ItemProperty -Path $firefoxPolicyPath -Name "DisableJavaScript" -Value 1 -PropertyType DWord -Force | Out-Null
Check-RegistryValue -Path $firefoxPolicyPath -Name "DisableJavaScript" -ExpectedValue 1 -SettingDescription "Firefox JavaScript Disabled"

# 5. Enable Pop-up Blocking
New-ItemProperty -Path $chromePolicyPath -Name "DefaultPopupsSetting" -Value 2 -PropertyType DWord -Force | Out-Null
Check-RegistryValue -Path $chromePolicyPath -Name "DefaultPopupsSetting" -ExpectedValue 2 -SettingDescription "Chrome Pop-up Blocker"
New-ItemProperty -Path $edgePolicyPath -Name "DefaultPopupsSetting" -Value 2 -PropertyType DWord -Force | Out-Null
Check-RegistryValue -Path $edgePolicyPath -Name "DefaultPopupsSetting" -ExpectedValue 2 -SettingDescription "Edge Pop-up Blocker"
New-ItemProperty -Path $firefoxPolicyPath -Name "PopupBlocking" -Value 1 -PropertyType DWord -Force | Out-Null
Check-RegistryValue -Path $firefoxPolicyPath -Name "PopupBlocking" -ExpectedValue 1 -SettingDescription "Firefox Pop-up Blocker"

# 6. Clear Browsing Data on Exit
New-ItemProperty -Path $chromePolicyPath -Name "ClearBrowsingDataOnExit" -Value 1 -PropertyType DWord -Force | Out-Null
Check-RegistryValue -Path $chromePolicyPath -Name "ClearBrowsingDataOnExit" -ExpectedValue 1 -SettingDescription "Chrome Clear Data on Exit"
New-ItemProperty -Path $edgePolicyPath -Name "ClearBrowsingDataOnExit" -Value 1 -PropertyType DWord -Force | Out-Null
Check-RegistryValue -Path $edgePolicyPath -Name "ClearBrowsingDataOnExit" -ExpectedValue 1 -SettingDescription "Edge Clear Data on Exit"
New-ItemProperty -Path $firefoxPolicyPath -Name "SanitizeOnShutdown" -Value 1 -PropertyType DWord -Force | Out-Null
Check-RegistryValue -Path $firefoxPolicyPath -Name "SanitizeOnShutdown" -ExpectedValue 1 -SettingDescription "Firefox Sanitize on Shutdown"

# 7. Disable Location Tracking
New-ItemProperty -Path $chromePolicyPath -Name ‘DefaultGeolocationSetting’ -Value 2 -PropertyType DWord -Force | Out-Null
Check-RegistryValue -Path $chromePolicyPath -Name ‘DefaultGeolocationSetting’ -ExpectedValue 2 -SettingDescription ‘Chrome Geolocation Disabled’
New-ItemProperty -Path $edgePolicyPath -Name ‘DefaultGeolocationSetting’ -Value 2 -PropertyType DWord -Force | Out-Null
Check-RegistryValue -Path $edgePolicyPath -Name ‘DefaultGeolocationSetting’ -ExpectedValue 2 -SettingDescription ‘Edge Geolocation Disabled’
New-ItemProperty -Path $firefoxPolicyPath -Name ‘DisableGeolocation’ -Value 1 -PropertyType DWord -Force | Out-Null
Check-RegistryValue -Path $firefoxPolicyPath -Name ‘DisableGeolocation’ -ExpectedValue 1 -SettingDescription ‘Firefox Geolocation Disabled’

# 8. Restrict Extensions
New-ItemProperty -Path $chromePolicyPath -Name "ExtensionInstallBlocklist" -Value "*" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $chromePolicyPath -Name "ExtensionInstallAllowlist" -Value "" -PropertyType String -Force | Out-Null
Check-RegistryValue -Path $chromePolicyPath -Name "ExtensionInstallBlocklist" -ExpectedValue "*" -SettingDescription "Chrome Extension Blocklist"
New-ItemProperty -Path $edgePolicyPath -Name "ExtensionInstallBlocklist" -Value "*" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $edgePolicyPath -Name "ExtensionInstallAllowlist" -Value "" -PropertyType String -Force | Out-Null
Check-RegistryValue -Path $edgePolicyPath -Name "ExtensionInstallBlocklist" -ExpectedValue "*" -SettingDescription "Edge Extension Blocklist"
New-ItemProperty -Path $firefoxPolicyPath -Name "DisableExtensionInstall" -Value 1 -PropertyType DWord -Force | Out-Null
Check-RegistryValue -Path $firefoxPolicyPath -Name "DisableExtensionInstall" -ExpectedValue 1 -SettingDescription "Firefox Extension Install Disabled"

# 9. Enable Automatic Updates
New-ItemProperty -Path $chromePolicyPath -Name "UpdatePolicy" -Value 1 -PropertyType DWord -Force | Out-Null
Check-RegistryValue -Path $chromePolicyPath -Name "UpdatePolicy" -ExpectedValue 1 -SettingDescription "Chrome Automatic Updates"
New-ItemProperty -Path $edgePolicyPath -Name "UpdatePolicy" -Value 1 -PropertyType DWord -Force | Out-Null
Check-RegistryValue -Path $edgePolicyPath -Name "UpdatePolicy" -ExpectedValue 1 -SettingDescription "Edge Automatic Updates"
New-ItemProperty -Path $firefoxPolicyPath -Name "DisableAppUpdate" -Value 0 -PropertyType DWord -Force | Out-Null
Check-RegistryValue -Path $firefoxPolicyPath -Name "DisableAppUpdate" -ExpectedValue 0 -SettingDescription "Firefox Automatic Updates"

# 10. Disable AutoFill for Forms
New-ItemProperty -Path $chromePolicyPath -Name "AutofillAddressEnabled" -Value 0 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $chromePolicyPath -Name "AutofillCreditCardEnabled" -Value 0 -PropertyType DWord -Force | Out-Null
Check-RegistryValue -Path $chromePolicyPath -Name "AutofillAddressEnabled" -ExpectedValue 0 -SettingDescription "Chrome Autofill Address"
Check-RegistryValue -Path $chromePolicyPath -Name "AutofillCreditCardEnabled" -ExpectedValue 0 -SettingDescription "Chrome Autofill Credit Card"
New-ItemProperty -Path $edgePolicyPath -Name "AutofillAddressEnabled" -Value 0 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $edgePolicyPath -Name "AutofillCreditCardEnabled" -Value 0 -PropertyType DWord -Force | Out-Null
Check-RegistryValue -Path $edgePolicyPath -Name "AutofillAddressEnabled" -ExpectedValue 0 -SettingDescription "Edge Autofill Address"
Check-RegistryValue -Path $edgePolicyPath -Name "AutofillCreditCardEnabled" -ExpectedValue 0 -SettingDescription "Edge Autofill Credit Card"
New-ItemProperty -Path $firefoxPolicyPath -Name "DisableFormAutofill" -Value 1 -PropertyType DWord -Force | Out-Null
Check-RegistryValue -Path $firefoxPolicyPath -Name "DisableFormAutofill" -ExpectedValue 1 -SettingDescription "Firefox Form Autofill"

Write-Host "Browser security settings have been applied and stored passwords have been deleted."