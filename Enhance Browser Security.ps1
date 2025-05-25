#requires -RunAsAdministrator
<#
.SYNOPSIS
    Browser Security Configuration and Password Deletion Script

.DESCRIPTION
    This PowerShell script enhances the security of Google Chrome, Microsoft Edge, and Mozilla Firefox browsers on a Windows PC by applying strict security policies and deleting all stored passwords. It is designed to reduce vulnerabilities, protect user data, and enforce safer browsing practices for all users on the system.

.WHAT IT DOES
    The script performs the following actions for Chrome, Edge, and Firefox:
    1. Deletes all stored passwords to prevent unauthorized access to credentials:
       - Chrome: Removes 'Login Data' and 'Login Data-journal' files from the default user profile.
       - Edge: Removes 'Login Data' and 'Login Data-journal' files from the default user profile.
       - Firefox: Removes 'logins.json', 'key4.db', and 'key3.db' from default profiles.
    2. Applies security settings via registry policies (HKLM:\SOFTWARE\Policies):
       - Disables password saving to prevent browsers from storing sensitive credentials.
       - Enables enhanced safe browsing to block risky downloads and protect against malware/phishing.
       - Disables JavaScript by default to reduce exploit risks (manual configuration needed for trusted sites).
       - Enables pop-up blocking to prevent intrusive ads and malicious scripts.
       - Clears browsing data (cookies, cache, history) on exit to minimize data retention.
       - Disables location tracking to protect user privacy.
       - Restricts extensions to block unapproved installations, reducing spyware risks.
       - Ensures automatic updates are enabled for the latest security patches.
       - Disables form autofill to prevent storage of sensitive data like addresses or credit card details.
    3. Verifies each setting and deletion, logging whether the state was changed or already correct:
       - Outputs [PASS] if the setting/file matches the desired state.
       - Outputs [FAIL] if the setting/file could not be applied/deleted, with details for troubleshooting.

.WHY IT IS NEEDED
    Modern browsers are common targets for cyberattacks due to their access to sensitive user data and frequent internet interaction. Key risks include:
    - Stored passwords can be stolen if a device is compromised (e.g., malware, physical access).
    - Risky downloads may introduce malware, compromising system security.
    - JavaScript is a frequent attack vector for exploits like cross-site scripting (XSS).
    - Pop-ups and unapproved extensions can deliver malicious scripts or track user activity.
    - Retained browsing data (cookies, cache) can be exploited for tracking or data theft.
    - Location tracking exposes user privacy to untrusted websites.
    - Outdated browsers may have unpatched vulnerabilities.
    - Autofilled form data can expose personal information if the browser is compromised.

    This script mitigates these risks by:
    - Removing all existing passwords to eliminate legacy credential exposure.
    - Enforcing strict policies to prevent future vulnerabilities.
    - Ensuring browsers are configured for maximum security and privacy, reducing attack surfaces.
    - Logging changes for transparency, helping administrators verify compliance.

.USAGE NOTES
    - Run as Administrator to modify registry and access user profile files.
    - Close all browsers (Chrome, Edge, Firefox) before running to avoid file access errors.
    - Test in a controlled environment first, as settings like JavaScript disabling may break website functionality.
    - Back up registry (e.g., 'reg export HKLM\SOFTWARE\Policies C:\backup.reg') and password files before running, as deletions are irreversible.
    - If [FAIL] is reported, check for running browsers, permissions, or browser installation. Re-run after resolving issues.
    - For enterprise environments, consider Group Policy or MDM for scalable deployment.
    - Users may need to re-enter passwords after deletion; recommend a secure password manager instead of browser storage.

.AUTHOR
    FustionTechLLC
#>

# PowerShell script to enforce browser security settings and delete stored passwords with change logging

# Function to check if a registry key exists
function Test-RegistryKey {
    param (
        [string]$Path
    )
    return Test-Path -Path $Path
}

# Function to check and report registry value with change logging
function Check-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$ExpectedValue,
        [string]$SettingDescription
    )
    Write-Host "Checking $SettingDescription before applying..."
    $before = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($before) {
        Write-Host "Before: $SettingDescription = $($before.$Name)"
    } else {
        Write-Host "Before: $SettingDescription registry key does not exist"
    }

    # Apply the setting
    New-ItemProperty -Path $Path -Name $Name -Value $ExpectedValue -PropertyType DWord -Force | Out-Null

    # Verify
    if (Test-RegistryKey $Path) {
        $after = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($after -and $after.$Name -eq $ExpectedValue) {
            Write-Host "[PASS] $SettingDescription is now set to $ExpectedValue"
        } else {
            Write-Host "[FAIL] $SettingDescription is not set correctly. Current value: $($after.$Name)"
        }
    } else {
        Write-Host "[FAIL] $SettingDescription registry key does not exist"
    }
}

# Function to delete stored passwords and verify with logging
function Remove-BrowserPasswords {
    param (
        [string]$BrowserName,
        [string[]]$FilePaths
    )
    Write-Host "Checking stored passwords for $BrowserName..."
    $filesExist = $false
    foreach ($file in $FilePaths) {
        if (Test-Path $file) {
            $filesExist = $true
            Write-Host "Before: $file exists"
            try {
                Remove-Item -Path $file -Force -ErrorAction Stop
                Write-Host "[PASS] Deleted $file"
            } catch {
                Write-Host "[FAIL] Error deleting $file : $_"
            }
        } else {
            Write-Host "Before: $file does not exist"
        }
    }
    if (-not $filesExist) {
        Write-Host "[PASS] No password files found for $BrowserName"
    }
}

# Function to stop browser processes
function Stop-BrowserProcesses {
    param (
        [string]$ProcessName
    )
    $processes = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
    if ($processes) {
        Write-Host "Stopping $ProcessName processes..."
        $processes | Stop-Process -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "No $ProcessName processes running"
    }
}

# Stop browsers
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
        Write-Host "Creating registry path $path"
        New-Item -Path $path -Force | Out-Null
    }
}

# 1. Disable Password Saving
Check-RegistryValue -Path $chromePolicyPath -Name "PasswordManagerEnabled" -ExpectedValue 0 -SettingDescription "Chrome Password Manager"
Check-RegistryValue -Path $edgePolicyPath -Name "PasswordManagerEnabled" -ExpectedValue 0 -SettingDescription "Edge Password Manager"
Check-RegistryValue -Path $firefoxPolicyPath -Name "DisablePasswordManager" -ExpectedValue 1 -SettingDescription "Firefox Password Manager"

# 2. Block Risky Downloads (Enable Safe Browsing)
Check-RegistryValue -Path $chromePolicyPath -Name "SafeBrowsingProtectionLevel" -ExpectedValue 2 -SettingDescription "Chrome Safe Browsing (Enhanced)"
Check-RegistryValue -Path $edgePolicyPath -Name "SmartScreenEnabled" -ExpectedValue 1 -SettingDescription "Edge SmartScreen"
Check-RegistryValue -Path $firefoxPolicyPath -Name "EnableSafeBrowsing" -ExpectedValue 1 -SettingDescription "Firefox Safe Browsing"

# 3. Enable Phishing and Malware Protection
Check-RegistryValue -Path $firefoxPolicyPath -Name "BlockDangerousDownloads" -ExpectedValue 1 -SettingDescription "Firefox Block Dangerous Downloads"

# 4. Disable JavaScript (Selective use requires manual trusted site configuration)
Check-RegistryValue -Path $chromePolicyPath -Name "DefaultJavaScriptSetting" -ExpectedValue 2 -SettingDescription "Chrome JavaScript Disabled"
Check-RegistryValue -Path $edgePolicyPath -Name "DefaultJavaScriptSetting" -ExpectedValue 2 -SettingDescription "Edge JavaScript Disabled"
Check-RegistryValue -Path $firefoxPolicyPath -Name "DisableJavaScript" -ExpectedValue 1 -SettingDescription "Firefox JavaScript Disabled"

# 5. Enable Pop-up Blocking
Check-RegistryValue -Path $chromePolicyPath -Name "DefaultPopupsSetting" -ExpectedValue 2 -SettingDescription "Chrome Pop-up Blocker"
Check-RegistryValue -Path $edgePolicyPath -Name "DefaultPopupsSetting" -ExpectedValue 2 -SettingDescription "Edge Pop-up Blocker"
Check-RegistryValue -Path $firefoxPolicyPath -Name "PopupBlocking" -ExpectedValue 1 -SettingDescription "Firefox Pop-up Blocker"

# 6. Clear Browsing Data on Exit
Check-RegistryValue -Path $chromePolicyPath -Name "ClearBrowsingDataOnExit" -ExpectedValue 1 -SettingDescription "Chrome Clear Data on Exit"
Check-RegistryValue -Path $edgePolicyPath -Name "ClearBrowsingDataOnExit" -ExpectedValue 1 -SettingDescription "Edge Clear Data on Exit"
Check-RegistryValue -Path $firefoxPolicyPath -Name "SanitizeOnShutdown" -ExpectedValue 1 -SettingDescription "Firefox Sanitize on Shutdown"

# 7. Disable Location Tracking
Check-RegistryValue -Path $chromePolicyPath -Name "DefaultGeolocationSetting" -ExpectedValue 2 -SettingDescription "Chrome Geolocation Disabled"
Check-RegistryValue -Path $edgePolicyPath -Name "DefaultGeolocationSetting" -ExpectedValue 2 -SettingDescription "Edge Geolocation Disabled"
Check-RegistryValue -Path $firefoxPolicyPath -Name "DisableGeolocation" -ExpectedValue 1 -SettingDescription "Firefox Geolocation Disabled"

# 8. Restrict Extensions
New-ItemProperty -Path $chromePolicyPath -Name "ExtensionInstallBlocklist" -Value "*" -PropertyType String -Force | Out-Null
Write-Host "Before: Chrome Extension Blocklist"
$beforeChromeExt = Get-ItemProperty -Path $chromePolicyPath -Name "ExtensionInstallBlocklist" -ErrorAction SilentlyContinue
if ($beforeChromeExt) { Write-Host "Before: Chrome Extension Blocklist = $($beforeChromeExt.ExtensionInstallBlocklist)" } else { Write-Host "Before: Chrome Extension Blocklist does not exist" }
Check-RegistryValue -Path $chromePolicyPath -Name "ExtensionInstallBlocklist" -ExpectedValue "*" -SettingDescription "Chrome Extension Blocklist"
New-ItemProperty -Path $chromePolicyPath -Name "ExtensionInstallAllowlist" -Value "" -PropertyType String -Force | Out-Null
Check-RegistryValue -Path $chromePolicyPath -Name "ExtensionInstallAllowlist" -ExpectedValue "" -SettingDescription "Chrome Extension Allowlist"

New-ItemProperty -Path $edgePolicyPath -Name "ExtensionInstallBlocklist" -Value "*" -PropertyType String -Force | Out-Null
Write-Host "Before: Edge Extension Blocklist"
$beforeEdgeExt = Get-ItemProperty -Path $edgePolicyPath -Name "ExtensionInstallBlocklist" -ErrorAction SilentlyContinue
if ($beforeEdgeExt) { Write-Host "Before: Edge Extension Blocklist = $($beforeEdgeExt.ExtensionInstallBlocklist)" } else { Write-Host "Before: Edge Extension Blocklist does not exist" }
Check-RegistryValue -Path $edgePolicyPath -Name "ExtensionInstallBlocklist" -ExpectedValue "*" -SettingDescription "Edge Extension Blocklist"
New-ItemProperty -Path $edgePolicyPath -Name "ExtensionInstallAllowlist" -Value "" -PropertyType String -Force | Out-Null
Check-RegistryValue -Path $edgePolicyPath -Name "ExtensionInstallAllowlist" -ExpectedValue "" -SettingDescription "Edge Extension Allowlist"

Check-RegistryValue -Path $firefoxPolicyPath -Name "DisableExtensionInstall" -ExpectedValue 1 -SettingDescription "Firefox Extension Install Disabled"

# 9. Enable Automatic Updates
Check-RegistryValue -Path $chromePolicyPath -Name "UpdatePolicy" -ExpectedValue 1 -SettingDescription "Chrome Automatic Updates"
Check-RegistryValue -Path $edgePolicyPath -Name "UpdatePolicy" -ExpectedValue 1 -SettingDescription "Edge Automatic Updates"
Check-RegistryValue -Path $firefoxPolicyPath -Name "DisableAppUpdate" -ExpectedValue 0 -SettingDescription "Firefox Automatic Updates"

# 10. Disable AutoFill for Forms
Check-RegistryValue -Path $chromePolicyPath -Name "AutofillAddressEnabled" -ExpectedValue 0 -SettingDescription "Chrome Autofill Address"
Check-RegistryValue -Path $chromePolicyPath -Name "AutofillCreditCardEnabled" -ExpectedValue 0 -SettingDescription "Chrome Autofill Credit Card"
Check-RegistryValue -Path $edgePolicyPath -Name "AutofillAddressEnabled" -ExpectedValue 0 -SettingDescription "Edge Autofill Address"
Check-RegistryValue -Path $edgePolicyPath -Name "AutofillCreditCardEnabled" -ExpectedValue 0 -SettingDescription "Edge Autofill Credit Card"
Check-RegistryValue -Path $firefoxPolicyPath -Name "DisableFormAutofill" -ExpectedValue 1 -SettingDescription "Firefox Form Autofill"

Write-Host "Browser security settings and password deletions have been applied and verified."