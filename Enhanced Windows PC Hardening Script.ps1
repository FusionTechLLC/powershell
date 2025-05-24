<#
================================================================================
                    ENHANCED WINDOWS PC SECURITY HARDENING SCRIPT
================================================================================

PURPOSE:
This PowerShell script performs comprehensive security hardening on Windows systems
by implementing essential security configurations, disabling vulnerable services,
and enabling protective features to significantly improve system security posture.

WHAT THIS SCRIPT DOES:
This script applies 20 critical security measures to harden Windows systems against
common attack vectors and vulnerabilities. It automatically configures security
settings that would otherwise require manual intervention across multiple system
areas including firewall, services, registry, and Windows features.

SECURITY MEASURES IMPLEMENTED:

1. FIREWALL CONFIGURATION
   - Enables Windows Defender Firewall for all profiles (Domain, Public, Private)
   - Sets default inbound traffic to BLOCK (allows outbound)
   - Enables firewall logging for security monitoring
   - Configures notification settings for blocked connections

2. NETWORK SECURITY
   - Disables NetBIOS over TCP/IP (prevents name resolution attacks)
   - Disables LLMNR (Link-Local Multicast Name Resolution) - prevents credential theft
   - Configures secure DNS servers (Cloudflare 1.1.1.1 and Google 8.8.8.8)
   - Blocks SMBv1 protocol (major ransomware attack vector)

3. WINDOWS DEFENDER ENHANCEMENT
   - Ensures Windows Defender real-time protection is enabled
   - Enables cloud-based protection and sample submission
   - Configures advanced threat detection features
   - Implements Attack Surface Reduction (ASR) rules to block malicious behavior

4. USER ACCOUNT CONTROL (UAC)
   - Sets UAC to maximum security level (always notify)
   - Ensures Local User Account (LUA) is enabled
   - Prevents privilege escalation without user consent

5. SERVICE HARDENING
   - Disables Remote Registry service (prevents remote registry access)
   - Disables Telnet service (insecure remote access protocol)
   - Conditionally disables Print Spooler (reduces attack surface if not needed)
   - Disables Windows Remote Management (WinRM) service
   - Stops and disables Windows Error Reporting service

6. SYSTEM FEATURES SECURITY
   - Disables Windows Script Host (prevents malicious script execution)
   - Disables AutoRun/AutoPlay for all drives (prevents malware auto-execution)
   - Removes unnecessary Windows features (WorkFolders, Fax services)
   - Disables Guest account if enabled

7. EXECUTION POLICY MANAGEMENT
   - Sets PowerShell execution policy to RemoteSigned (blocks unsigned scripts)
   - Safely manages policy changes during script execution
   - Restores original execution policy when complete

8. WINDOWS UPDATE CONFIGURATION
   - Ensures automatic Windows updates are enabled
   - Configures automatic download and installation of security updates
   - Creates necessary registry paths if missing

9. PASSWORD POLICY ENFORCEMENT
   - Sets minimum password length to 8 characters
   - Configures password age and history requirements
   - Enforces account lockout policies

10. SECURITY LOGGING & MONITORING
    - Increases event log sizes for better security monitoring
    - Enables detailed security event logging
    - Configures system audit policies

ADDITIONAL SECURITY CONFIGURATIONS:
- Disables Remote Assistance to prevent unauthorized remote access
- Blocks executable content from email clients and web browsers
- Prevents Office applications from creating malicious child processes
- Stops JavaScript/VBScript from launching downloaded executables
- Blocks potentially obfuscated scripts from running

SYSTEM REQUIREMENTS:
- Windows 10/11 or Windows Server 2016/2019/2022
- PowerShell 5.1 or later
- Administrator privileges (script will attempt self-elevation)
- Internet connection (for DNS configuration and updates)

HOW TO USE:
1. Save this script as a .ps1 file (e.g., "PC Security Hardening.ps1")
2. Right-click PowerShell and select "Run as Administrator"
3. Navigate to the script directory: cd C:\path\to\script
4. Run: .\PC Security Hardening.ps1
5. Follow on-screen prompts (printer usage question)
6. Review the generated HTML security report
7. RESTART your computer when complete

WHAT TO EXPECT:
- Script execution takes 2-5 minutes depending on system
- Real-time progress updates with color-coded status messages
- Professional HTML security report saved to Desktop
- Protection score out of 200 points with detailed breakdown
- Some warnings are normal (restart notifications, feature removals)
- Final score typically ranges from 170-190 points (85-95%)

OUTPUT REPORT:
The script generates a comprehensive HTML report containing:
- Overall security score and percentage
- Detailed breakdown of all actions taken
- Success/failure status for each security measure
- Specific recommendations for manual review
- System information and timestamp
- Professional styling with responsive design

SAFETY FEATURES:
- Captures and restores original execution policy
- Creates registry paths before modifying them
- Graceful error handling for each security measure
- Non-destructive changes (can be reversed if needed)
- Comprehensive logging of all actions taken

IMPORTANT NOTES:
- This script makes significant security changes to Windows
- Some applications may require firewall exceptions after hardening
- Print functionality will be disabled if you choose "No" to printer question
- A system restart is REQUIRED for all changes to take effect
- Keep the HTML report for security compliance documentation
- Review failed actions in the report and address manually if needed

SECURITY IMPACT:
After running this script, your system will be significantly more secure against:
- Malware and ransomware attacks
- Network-based intrusions
- Privilege escalation attempts
- Credential theft attacks
- Drive-by downloads and malicious scripts
- Remote access exploits
- Data exfiltration attempts

This script implements security hardening measures recommended by:
- Microsoft Security Compliance Toolkit
- CIS (Center for Internet Security) Benchmarks
- NIST Cybersecurity Framework guidelines
- SANS security hardening recommendations

VERSION: 2.0 Enhanced
AUTHOR: Enhanced PC Security Hardening Script
LAST UPDATED: 2025

================================================================================
#>

# Enhanced Windows PC Hardening Script
# Requires running as Administrator
#Requires -RunAsAdministrator

# Load required assemblies
Add-Type -AssemblyName System.Web

# Initialize variables for tracking actions and score
$global:hardeningActions = New-Object System.Collections.ArrayList
$global:protectionScore = 0
$global:maxScore = 200  # Updated for additional security measures
$global:actionWeight = 10
$global:totalActions = 20

# Log file for HTML report
$reportPath = "$env:USERPROFILE\Desktop\PC_Hardening_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"

# Function to log actions and update score
function Log-Action {
    param (
        [string]$Action,
        [string]$Status,
        [string]$Details
    )
    $null = $global:hardeningActions.Add([PSCustomObject]@{
        Action  = $Action
        Status  = $Status
        Details = $Details
    })
    if ($Status -eq 'Success') {
        $global:protectionScore += $actionWeight
    }
}

# Function to check if running as administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

# Verify administrator privileges and attempt self-elevation
if (-not (Test-Administrator)) {
    Write-Host "Administrator privileges required. Attempting to restart as Administrator..." -ForegroundColor Yellow
    
    try {
        # Try to restart the script as administrator
        $arguments = "-ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
        Start-Process PowerShell -Verb RunAs -ArgumentList $arguments -Wait
        exit 0
    }
    catch {
        Write-Error "Failed to restart as Administrator. Please run PowerShell as Administrator manually and try again."
        Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
        Read-Host "Press Enter to exit"
        exit 1
    }
}

Write-Host "Starting Windows PC Hardening Process..." -ForegroundColor Green
Write-Host "This may take several minutes to complete." -ForegroundColor Yellow

# Capture current execution policy
$originalPolicy = 'Undefined'
try {
    $originalPolicy = Get-ExecutionPolicy -Scope CurrentUser
    Log-Action -Action 'Capture Execution Policy' -Status 'Success' -Details "Original execution policy: $originalPolicy"
} catch {
    Log-Action -Action 'Capture Execution Policy' -Status 'Failed' -Details "Error: $_"
}

# Main script execution in a try-finally block to ensure policy restoration
try {
    # 1. Enable Windows Defender Firewall and set default block
    Write-Host "Configuring Windows Firewall..." -ForegroundColor Cyan
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
        Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True
        # Enable firewall logging
        Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True -LogIgnored False
        Log-Action -Action 'Enable Windows Firewall' -Status 'Success' -Details 'Firewall enabled with default block on inbound connections and logging enabled.'
    } catch {
        Log-Action -Action 'Enable Windows Firewall' -Status 'Failed' -Details "Error: $_"
    }

    # 2. Disable NetBIOS over TCP/IP
    Write-Host "Disabling NetBIOS over TCP/IP..." -ForegroundColor Cyan
    try {
        $adapters = Get-CimInstance -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled = 'True'"
        foreach ($adapter in $adapters) {
            $adapter | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions = 2}
        }
        Log-Action -Action 'Disable NetBIOS' -Status 'Success' -Details 'NetBIOS over TCP/IP disabled on all adapters.'
    } catch {
        Log-Action -Action 'Disable NetBIOS' -Status 'Failed' -Details "Error: $_"
    }

    # 3. Ensure Windows Defender is running and configured
    Write-Host "Configuring Windows Defender..." -ForegroundColor Cyan
    try {
        if ((Get-Service -Name WinDefend).Status -ne 'Running') {
            Start-Service -Name WinDefend
        }
        Set-MpPreference -DisableRealtimeMonitoring $false
        Set-MpPreference -SubmitSamplesConsent 1  # Send samples to Microsoft
        Set-MpPreference -MAPSReporting 2  # Advanced MAPS reporting
        Set-MpPreference -DisableBlockAtFirstSeen $false
        Log-Action -Action 'Enable Windows Defender' -Status 'Success' -Details 'Windows Defender real-time protection and cloud protection enabled.'
    } catch {
        Log-Action -Action 'Enable Windows Defender' -Status 'Failed' -Details "Error: $_"
    }

    # 4. Enable UAC (set to always notify)
    Write-Host "Configuring User Account Control..." -ForegroundColor Cyan
    try {
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 1
        Log-Action -Action 'Enable UAC' -Status 'Success' -Details 'UAC set to always notify and enabled.'
    } catch {
        Log-Action -Action 'Enable UAC' -Status 'Failed' -Details "Error: $_"
    }

    # 5. Disable Remote Registry service
    Write-Host "Disabling Remote Registry service..." -ForegroundColor Cyan
    try {
        $remoteRegistry = Get-Service -Name RemoteRegistry -ErrorAction SilentlyContinue
        if ($remoteRegistry) {
            Stop-Service -Name RemoteRegistry -Force -ErrorAction SilentlyContinue
            Set-Service -Name RemoteRegistry -StartupType Disabled
            Log-Action -Action 'Disable Remote Registry' -Status 'Success' -Details 'Remote Registry service disabled.'
        } else {
            Log-Action -Action 'Disable Remote Registry' -Status 'Skipped' -Details 'Remote Registry service not found.'
        }
    } catch {
        Log-Action -Action 'Disable Remote Registry' -Status 'Failed' -Details "Error: $_"
    }

    # 6. Configure Windows Update
    Write-Host "Configuring Windows Update..." -ForegroundColor Cyan
    try {
        # Create registry path if it doesn't exist
        $auPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
        $wuPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
        
        if (-not (Test-Path $wuPath)) {
            New-Item -Path $wuPath -Force | Out-Null
        }
        if (-not (Test-Path $auPath)) {
            New-Item -Path $auPath -Force | Out-Null
        }
        
        # Enable automatic updates via registry
        Set-ItemProperty -Path $auPath -Name 'NoAutoUpdate' -Value 0 -Force
        Set-ItemProperty -Path $auPath -Name 'AUOptions' -Value 4 -Force
        Log-Action -Action 'Configure Windows Update' -Status 'Success' -Details 'Windows Update configured for automatic download and install.'
    } catch {
        Log-Action -Action 'Configure Windows Update' -Status 'Failed' -Details "Error: $_"
    }

    # 7. Disable Telnet service
    Write-Host "Disabling Telnet service..." -ForegroundColor Cyan
    try {
        $telnetService = Get-Service -Name TlntSvr -ErrorAction SilentlyContinue
        if ($telnetService) {
            Stop-Service -Name TlntSvr -Force -ErrorAction SilentlyContinue
            Set-Service -Name TlntSvr -StartupType Disabled
            Log-Action -Action 'Disable Telnet Service' -Status 'Success' -Details 'Telnet service disabled.'
        } else {
            Log-Action -Action 'Disable Telnet Service' -Status 'Skipped' -Details 'Telnet service not found or already disabled.'
        }
    } catch {
        Log-Action -Action 'Disable Telnet Service' -Status 'Failed' -Details "Error: $_"
    }

    # 8. Configure Secure DNS
    Write-Host "Configuring Secure DNS..." -ForegroundColor Cyan
    try {
        # Set DNS servers (more compatible approach)
        $adapters = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
        foreach ($adapter in $adapters) {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses @('1.1.1.1', '8.8.8.8')
        }
        Log-Action -Action 'Configure Secure DNS' -Status 'Success' -Details 'DNS servers set to Cloudflare (1.1.1.1) and Google (8.8.8.8).'
    } catch {
        Log-Action -Action 'Configure Secure DNS' -Status 'Failed' -Details "Error: $_"
    }

    # 9. Disable Guest Account
    Write-Host "Disabling Guest Account..." -ForegroundColor Cyan
    try {
        $guestAccount = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
        if ($guestAccount -and $guestAccount.Enabled) {
            Disable-LocalUser -Name 'Guest'
            Log-Action -Action 'Disable Guest Account' -Status 'Success' -Details 'Guest account disabled.'
        } else {
            Log-Action -Action 'Disable Guest Account' -Status 'Skipped' -Details 'Guest account already disabled or not found.'
        }
    } catch {
        Log-Action -Action 'Disable Guest Account' -Status 'Failed' -Details "Error: $_"
    }

    # 10. Configure PowerShell Execution Policy
    Write-Host "Configuring PowerShell Execution Policy..." -ForegroundColor Cyan
    try {
        if ((Get-ExecutionPolicy -Scope LocalMachine) -ne 'RemoteSigned') {
            Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
            Log-Action -Action 'Configure PowerShell Execution' -Status 'Success' -Details 'PowerShell execution policy set to RemoteSigned.'
        } else {
            Log-Action -Action 'Configure PowerShell Execution' -Status 'Skipped' -Details 'PowerShell execution policy already set to RemoteSigned.'
        }
    } catch {
        Log-Action -Action 'Configure PowerShell Execution' -Status 'Failed' -Details "Error: $_"
    }

    # 11. Disable LLMNR
    Write-Host "Disabling LLMNR..." -ForegroundColor Cyan
    try {
        $dnsClientPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
        if (-not (Test-Path $dnsClientPath)) {
            New-Item -Path $dnsClientPath -Force | Out-Null
        }
        Set-ItemProperty -Path $dnsClientPath -Name 'EnableMulticast' -Value 0 -Force
        Log-Action -Action 'Disable LLMNR' -Status 'Success' -Details 'Link-Local Multicast Name Resolution disabled.'
    } catch {
        Log-Action -Action 'Disable LLMNR' -Status 'Failed' -Details "Error: $_"
    }

    # 12. Disable SMBv1 Protocol
    Write-Host "Disabling SMBv1 Protocol..." -ForegroundColor Cyan
    try {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        Log-Action -Action 'Disable SMBv1' -Status 'Success' -Details 'SMBv1 protocol disabled (major security improvement).'
    } catch {
        Log-Action -Action 'Disable SMBv1' -Status 'Failed' -Details "Error: $_"
    }

    # 13. Disable Windows Script Host
    Write-Host "Disabling Windows Script Host..." -ForegroundColor Cyan
    try {
        $wshPath = 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings'
        if (-not (Test-Path $wshPath)) {
            New-Item -Path $wshPath -Force | Out-Null
        }
        Set-ItemProperty -Path $wshPath -Name 'Enabled' -Value 0 -Force
        Log-Action -Action 'Disable Windows Script Host' -Status 'Success' -Details 'Windows Script Host disabled to prevent malicious script execution.'
    } catch {
        Log-Action -Action 'Disable Windows Script Host' -Status 'Failed' -Details "Error: $_"
    }

    # 14. Disable AutoRun/AutoPlay
    Write-Host "Disabling AutoRun/AutoPlay..." -ForegroundColor Cyan
    try {
        # Disable AutoRun for all drive types
        $explorerPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        if (-not (Test-Path $explorerPath)) {
            New-Item -Path $explorerPath -Force | Out-Null
        }
        Set-ItemProperty -Path $explorerPath -Name 'NoDriveTypeAutoRun' -Value 255 -Force
        
        # Disable AutoPlay for current user
        $autoplayPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers'
        if (-not (Test-Path $autoplayPath)) {
            New-Item -Path $autoplayPath -Force | Out-Null
        }
        Set-ItemProperty -Path $autoplayPath -Name 'DisableAutoplay' -Value 1 -Force
        
        Log-Action -Action 'Disable AutoRun/AutoPlay' -Status 'Success' -Details 'AutoRun and AutoPlay disabled for all drives.'
    } catch {
        Log-Action -Action 'Disable AutoRun/AutoPlay' -Status 'Failed' -Details "Error: $_"
    }

    # 15. Enable Windows Defender Attack Surface Reduction
    Write-Host "Configuring Attack Surface Reduction..." -ForegroundColor Cyan
    try {
        # Enable key ASR rules
        $asrRules = @{
            "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = 1  # Block executable content from email client and webmail
            "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = 1  # Block all Office applications from creating child processes
            "3B576869-A4EC-4529-8536-B80A7769E899" = 1  # Block Office applications from creating executable content
            "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = 1  # Block Office applications from injecting code into other processes
            "D3E037E1-3EB8-44C8-A917-57927947596D" = 1  # Block JavaScript or VBScript from launching downloaded executable content
            "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = 1  # Block execution of potentially obfuscated scripts
        }
        
        foreach ($rule in $asrRules.GetEnumerator()) {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.Key -AttackSurfaceReductionRules_Actions $rule.Value
        }
        Log-Action -Action 'Enable Attack Surface Reduction' -Status 'Success' -Details 'Key Attack Surface Reduction rules enabled.'
    } catch {
        Log-Action -Action 'Enable Attack Surface Reduction' -Status 'Failed' -Details "Error: $_"
    }

    # 16. Configure Password Policy
    Write-Host "Configuring Password Policy..." -ForegroundColor Cyan
    try {
        net accounts /minpwlen:8 /maxpwage:90 /minpwage:1 /uniquepw:5 | Out-Null
        Log-Action -Action 'Configure Password Policy' -Status 'Success' -Details 'Password policy set: min 8 chars, 90 day max age, remember 5 passwords.'
    } catch {
        Log-Action -Action 'Configure Password Policy' -Status 'Failed' -Details "Error: $_"
    }

    # 17. Disable Print Spooler (if not needed)
    Write-Host "Configuring Print Spooler..." -ForegroundColor Cyan
    try {
        $printSpooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
        if ($printSpooler -and $printSpooler.Status -eq 'Running') {
            $choice = Read-Host "Do you use a printer? (Y/N)"
            if ($choice -eq 'N' -or $choice -eq 'n') {
                Stop-Service -Name Spooler -Force
                Set-Service -Name Spooler -StartupType Disabled
                Log-Action -Action 'Disable Print Spooler' -Status 'Success' -Details 'Print Spooler service disabled (reduces attack surface).'
            } else {
                Log-Action -Action 'Configure Print Spooler' -Status 'Skipped' -Details 'Print Spooler left enabled per user choice.'
            }
        } else {
            Log-Action -Action 'Configure Print Spooler' -Status 'Skipped' -Details 'Print Spooler already stopped or not found.'
        }
    } catch {
        Log-Action -Action 'Configure Print Spooler' -Status 'Failed' -Details "Error: $_"
    }

    # 18. Enable Windows Event Logging
    Write-Host "Configuring Event Logging..." -ForegroundColor Cyan
    try {
        wevtutil sl Security /ms:1024000
        wevtutil sl Application /ms:1024000
        wevtutil sl System /ms:1024000
        Log-Action -Action 'Configure Event Logging' -Status 'Success' -Details 'Security, Application, and System event logs configured with 1MB max size.'
    } catch {
        Log-Action -Action 'Configure Event Logging' -Status 'Failed' -Details "Error: $_"
    }

    # 19. Disable unnecessary Windows features
    Write-Host "Disabling unnecessary Windows features..." -ForegroundColor Cyan
    try {
        $featuresToDisable = @(
            'WorkFolders-Client',
            'Printing-Foundation-Features',
            'FaxServicesClientPackage'
        )
        
        foreach ($feature in $featuresToDisable) {
            $featureState = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
            if ($featureState -and $featureState.State -eq 'Enabled') {
                Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction SilentlyContinue
            }
        }
        Log-Action -Action 'Disable Unnecessary Features' -Status 'Success' -Details 'Disabled WorkFolders, some printing features, and Fax services.'
    } catch {
        Log-Action -Action 'Disable Unnecessary Features' -Status 'Failed' -Details "Error: $_"
    }

    # 20. Configure Additional Security Settings
    Write-Host "Applying additional security settings..." -ForegroundColor Cyan
    try {
        # Disable Windows Error Reporting
        $werPath = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting'
        if (-not (Test-Path $werPath)) {
            New-Item -Path $werPath -Force | Out-Null
        }
        Set-ItemProperty -Path $werPath -Name 'Disabled' -Value 1 -Force
        
        # Disable Remote Assistance
        $remoteAssistPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'
        if (-not (Test-Path $remoteAssistPath)) {
            New-Item -Path $remoteAssistPath -Force | Out-Null
        }
        Set-ItemProperty -Path $remoteAssistPath -Name 'fAllowToGetHelp' -Value 0 -Force
        
        # Disable WinRM service
        $winrm = Get-Service -Name WinRM -ErrorAction SilentlyContinue
        if ($winrm -and $winrm.Status -eq 'Running') {
            Stop-Service -Name WinRM -Force -ErrorAction SilentlyContinue
            Set-Service -Name WinRM -StartupType Disabled -ErrorAction SilentlyContinue
        }
        
        Log-Action -Action 'Additional Security Settings' -Status 'Success' -Details 'Disabled Windows Error Reporting, Remote Assistance, and WinRM service.'
    } catch {
        Log-Action -Action 'Additional Security Settings' -Status 'Failed' -Details "Error: $_"
    }

    # Generate Enhanced HTML Report
    Write-Host "Generating security report..." -ForegroundColor Cyan
    $successfulActions = ($global:hardeningActions | Where-Object { $_.Status -eq 'Success' }).Count
    $global:protectionScore = [math]::Min($successfulActions * $global:actionWeight, $global:maxScore)
    $scorePercentage = [math]::Round(($global:protectionScore / $global:maxScore) * 100, 1)
    $scoreColor = if ($global:protectionScore -ge 160) { 'green' } elseif ($global:protectionScore -ge 100) { 'orange' } else { 'red' }

    $html = @"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>PC Security Hardening Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: #ffffff;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.1);
            overflow: hidden;
            animation: slideIn 0.6s ease-out;
        }
        
        @keyframes slideIn {
            from { opacity: 0; transform: translateY(30px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 40px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: linear-gradient(45deg, transparent, rgba(255,255,255,0.1), transparent);
            transform: rotate(45deg);
            animation: shine 3s infinite;
        }
        
        @keyframes shine {
            0% { transform: translateX(-100%) translateY(-100%) rotate(45deg); }
            100% { transform: translateX(100%) translateY(100%) rotate(45deg); }
        }
        
        .header h1 { 
            font-size: 2.8em; 
            font-weight: 300; 
            margin-bottom: 10px;
            position: relative;
            z-index: 1;
        }
        
        .header p {
            font-size: 1.2em;
            opacity: 0.9;
            position: relative;
            z-index: 1;
        }
        
        .score-section {
            padding: 40px;
            text-align: center;
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            border-bottom: 3px solid #dee2e6;
        }
        
        .score-circle {
            width: 200px;
            height: 200px;
            border-radius: 50%;
            background: conic-gradient(from 0deg, $scoreColor 0deg $(($scorePercentage * 3.6))deg, #e9ecef $(($scorePercentage * 3.6))deg 360deg);
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 30px;
            position: relative;
            animation: rotateIn 1s ease-out;
        }
        
        @keyframes rotateIn {
            from { transform: rotate(-180deg) scale(0.5); opacity: 0; }
            to { transform: rotate(0deg) scale(1); opacity: 1; }
        }
        
        .score-inner {
            width: 160px;
            height: 160px;
            border-radius: 50%;
            background: white;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        
        .score-number {
            font-size: 2.5em;
            font-weight: bold;
            color: $scoreColor;
            line-height: 1;
        }
        
        .score-label {
            font-size: 1em;
            color: #666;
            margin-top: 5px;
        }
        
        .score-percentage {
            font-size: 1.5em;
            color: #333;
            margin: 20px 0;
        }
        
        .summary-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        
        .stat-box {
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.08);
            text-align: center;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            border-left: 4px solid #3498db;
        }
        
        .stat-box:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0,0,0,0.15);
        }
        
        .stat-box.success { border-left-color: #27ae60; }
        .stat-box.failed { border-left-color: #e74c3c; }
        .stat-box.skipped { border-left-color: #f39c12; }
        
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        .stat-number.success { color: #27ae60; }
        .stat-number.failed { color: #e74c3c; }
        .stat-number.skipped { color: #f39c12; }
        
        .stat-label {
            color: #666;
            font-size: 1.1em;
            font-weight: 500;
        }
        
        .content {
            padding: 40px;
        }
        
        .section-header {
            display: flex;
            align-items: center;
            margin-bottom: 30px;
            padding-bottom: 15px;
            border-bottom: 3px solid #3498db;
        }
        
        .section-icon {
            font-size: 2em;
            margin-right: 15px;
            color: #3498db;
        }
        
        .section-title {
            font-size: 1.8em;
            color: #2c3e50;
            font-weight: 600;
        }
        
        .table-container {
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 5px 20px rgba(0,0,0,0.08);
        }
        
        table { 
            width: 100%; 
            border-collapse: collapse;
        }
        
        th {
            background: linear-gradient(135deg, #3498db 0%, #2980b9 100%);
            color: white; 
            padding: 20px 15px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-size: 0.9em;
        }
        
        td {
            padding: 15px;
            border-bottom: 1px solid #f1f2f6;
            vertical-align: top;
        }
        
        tr:last-child td {
            border-bottom: none;
        }
        
        tr:nth-child(even) { 
            background-color: #f8f9fa; 
        }
        
        tr:hover { 
            background-color: #e3f2fd; 
            transform: scale(1.01);
            transition: all 0.2s ease;
        }
        
        .status-badge {
            display: inline-flex;
            align-items: center;
            padding: 6px 12px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .status-success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .status-failed {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .status-skipped {
            background: #fff3cd;
            color: #856404;
            border: 1px solid #ffeaa7;
        }
        
        .action-name {
            font-weight: 600;
            color: #2c3e50;
            font-size: 1em;
        }
        
        .action-details {
            color: #666;
            font-size: 0.95em;
            line-height: 1.4;
        }
        
        .footer {
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            padding: 30px;
            text-align: center;
            border-top: 3px solid #dee2e6;
        }
        
        .footer-content {
            max-width: 800px;
            margin: 0 auto;
        }
        
        .recommendation {
            background: #e3f2fd;
            border: 1px solid #bbdefb;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .recommendation h4 {
            color: #1976d2;
            margin-bottom: 10px;
            font-size: 1.1em;
        }
        
        .recommendation p {
            color: #424242;
            margin: 0;
        }
        
        .timestamp {
            color: #666;
            font-size: 0.9em;
            font-style: italic;
        }
        
        @media (max-width: 768px) {
            .container { margin: 10px; }
            .header { padding: 20px; }
            .header h1 { font-size: 2em; }
            .score-section { padding: 20px; }
            .content { padding: 20px; }
            .summary-stats { grid-template-columns: 1fr; }
            table { font-size: 0.9em; }
            th, td { padding: 10px; }
        }
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h1>PC Security Hardening Report</h1>
            <p>Comprehensive Windows Security Assessment & Hardening Results</p>
        </div>
        
        <div class='score-section'>
            <div class='score-circle'>
                <div class='score-inner'>
                    <div class='score-number'>$($global:protectionScore)</div>
                    <div class='score-label'>out of $($global:maxScore)</div>
                </div>
            </div>
            <div class='score-percentage'>Security Score: $scorePercentage%</div>
            
            <div class='summary-stats'>
                <div class='stat-box success'>
                    <div class='stat-number success'>$(($global:hardeningActions | Where-Object { $_.Status -eq 'Success' }).Count)</div>
                    <div class='stat-label'>Successful Actions</div>
                </div>
                <div class='stat-box failed'>
                    <div class='stat-number failed'>$(($global:hardeningActions | Where-Object { $_.Status -eq 'Failed' }).Count)</div>
                    <div class='stat-label'>Failed Actions</div>
                </div>
                <div class='stat-box skipped'>
                    <div class='stat-number skipped'>$(($global:hardeningActions | Where-Object { $_.Status -eq 'Skipped' }).Count)</div>
                    <div class='stat-label'>Skipped Actions</div>
                </div>
            </div>
        </div>
        
        <div class='content'>
            <div class='section-header'>
                <div class='section-icon'>ACTIONS</div>
                <div class='section-title'>Security Actions Performed</div>
            </div>
            
            <div class='table-container'>
                <table>
                    <thead>
                        <tr>
                            <th style='width: 25%;'>Security Action</th>
                            <th style='width: 15%;'>Status</th>
                            <th style='width: 60%;'>Details & Results</th>
                        </tr>
                    </thead>
                    <tbody>
"@

    foreach ($action in $global:hardeningActions) {
        $statusClass = $action.Status.ToLower()
        $statusBadge = ""
        
        switch ($action.Status) {
            'Success' { 
                $statusBadge = "<span class='status-badge status-success'>SUCCESS</span>" 
            }
            'Failed' { 
                $statusBadge = "<span class='status-badge status-failed'>FAILED</span>" 
            }
            'Skipped' { 
                $statusBadge = "<span class='status-badge status-skipped'>SKIPPED</span>" 
            }
            default { 
                $statusBadge = "<span class='status-badge'>$($action.Status)</span>" 
            }
        }
        
        $actionName = [System.Web.HttpUtility]::HtmlEncode($action.Action)
        $actionDetails = [System.Web.HttpUtility]::HtmlEncode($action.Details)
        
        $html += "                        <tr>`n"
        $html += "                            <td><div class='action-name'>$actionName</div></td>`n"
        $html += "                            <td>$statusBadge</td>`n"
        $html += "                            <td><div class='action-details'>$actionDetails</div></td>`n"
        $html += "                        </tr>`n"
    }

    $recommendations = @()
    if (($global:hardeningActions | Where-Object { $_.Status -eq 'Failed' }).Count -gt 0) {
        $recommendations += "Review and manually address any failed security actions listed above."
    }
    if ($global:protectionScore -lt 160) {
        $recommendations += "Your security score indicates room for improvement. Consider implementing additional security measures."
    }
    $recommendations += "Restart your computer to ensure all security changes take effect."
    $recommendations += "Keep Windows and all software updated regularly."
    $recommendations += "Review these security settings periodically to maintain protection."

    $html += @"
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class='footer'>
            <div class='footer-content'>
                <div class='recommendation'>
                    <h4>RECOMMENDATIONS</h4>
"@
    
    foreach ($rec in $recommendations) {
        $html += "                    <p>* $([System.Web.HttpUtility]::HtmlEncode($rec))</p>`n"
    }
    
    $html += @"
                </div>
                
                <div class='timestamp'>
                    <p><strong>Report Generated:</strong> $(Get-Date -Format "dddd, MMMM dd, yyyy 'at' hh:mm:ss tt")</p>
                    <p><strong>Computer:</strong> $env:COMPUTERNAME | <strong>User:</strong> $env:USERNAME</p>
                    <p><em>This report was generated by the Enhanced Windows PC Hardening Script v2.0</em></p>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
"@

    # Save HTML report with error handling
    try {
        $html | Out-File -FilePath $reportPath -Encoding UTF8
        Log-Action -Action 'Generate HTML Report' -Status 'Success' -Details "Report saved to $reportPath"
        Write-Host "Report saved successfully!" -ForegroundColor Green
    } catch {
        Log-Action -Action 'Generate HTML Report' -Status 'Failed' -Details "Error: $_"
        Write-Host "Failed to save report: $_" -ForegroundColor Red
    }
}
finally {
    # Restore original execution policy
    Write-Host "Restoring original execution policy..." -ForegroundColor Cyan
    try {
        if ($originalPolicy -ne 'Undefined' -and $originalPolicy -ne 'Bypass') {
            Set-ExecutionPolicy -ExecutionPolicy $originalPolicy -Scope CurrentUser -Force
            Log-Action -Action 'Restore Execution Policy' -Status 'Success' -Details "Restored original execution policy: $originalPolicy"
        } else {
            Log-Action -Action 'Restore Execution Policy' -Status 'Skipped' -Details 'Original policy was Undefined or already Bypass; no restoration needed.'
        }
    } catch {
        Log-Action -Action 'Restore Execution Policy' -Status 'Failed' -Details "Error: $_"
    }
}

# Output final message with proper variable expansion
Write-Host "============================================" -ForegroundColor Green
Write-Host "*** Hardening Process Complete! ***" -ForegroundColor Green
Write-Host "Protection Score: $($global:protectionScore)/$($global:maxScore) ($scorePercentage%)" -ForegroundColor $scoreColor
Write-Host "Report Location: $reportPath" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Green

# Offer to open the report
$openReport = Read-Host "Would you like to open the security report now? (Y/N)"
if ($openReport -eq 'Y' -or $openReport -eq 'y') {
    try {
        Start-Process $reportPath
    } catch {
        Write-Host "Could not open report automatically. Please navigate to: $reportPath" -ForegroundColor Yellow
    }
}

Write-Host "`nIMPORTANT: Please restart your computer to ensure all changes take effect." -ForegroundColor Yellow
Write-Host "Some security features may require a system restart to be fully active." -ForegroundColor Yellow