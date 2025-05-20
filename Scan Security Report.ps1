# Security Scan Report Script
# Purpose: Performs a comprehensive security audit of a Windows system and generates an HTML report.
# Functionality:
# - Scans specified ports (e.g., 21, 80, 3389) to identify open ports and associated services.
# - Analyzes login activity over the past 30 days, reporting successful and failed logins with user, source IP, and logon type.
# - Detects suspicious processes running from non-standard locations (outside Windows/Program Files).
# - Identifies services with unquoted paths vulnerable to privilege escalation.
# - Evaluates system security settings (e.g., firewall, UAC, antivirus, Secure Boot, RDP, etc.) and provides recommendations.
# - Generates a modern HTML report with Tailwind CSS styling and a Chart.js bar chart visualizing port status.
# Output: Saves an HTML report to the user's Documents folder (or TEMP if permissions fail) with a timestamped filename.
# Requirements: Run with administrative privileges for full access to event logs, services, and system settings.
# Usage: Execute in PowerShell as '.\security_scan_report.ps1' or '& ".\security scan report.ps1"'.
# PortScanSecurityReport.ps1
# PowerShell script to scan ports, check login activity, perform security checks, and generate HTML report

function Test-Port {
    param (
        [string]$ComputerName = "localhost",
        [int[]]$Ports,
        [int]$Timeout = 1000
    )
    $results = @()
    foreach ($port in $Ports) {
        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connect = $tcpClient.BeginConnect($ComputerName, $port, $null, $null)
            $wait = $connect.AsyncWaitHandle.WaitOne($Timeout, $false)
            $result = [PSCustomObject]@{
                Port = $port
                Status = if ($wait -and $tcpClient.Connected) { "Open" } else { "Closed" }
                Service = Get-ServiceName -Port $port
            }
            $results += $result
            if ($tcpClient.Connected) { $tcpClient.Close() }
        }
        catch {
            Write-Warning "Error scanning port $port - $($_.Exception.Message)"
        }
    }
    return $results
}

function Get-ServiceName {
    param ([int]$Port)
    $serviceMap = @{
        21 = "FTP"; 22 = "SSH"; 23 = "Telnet"; 25 = "SMTP"; 80 = "HTTP";
        110 = "POP3"; 143 = "IMAP"; 443 = "HTTPS"; 3389 = "RDP"; 445 = "SMB";
        135 = "RPC"; 139 = "NetBIOS"; 1433 = "SQL Server"; 3306 = "MySQL";
        8080 = "HTTP-Proxy"
    }
    if ($serviceMap.ContainsKey($Port)) {
        return $serviceMap[$Port]
    }
    return "Unknown"
}

function Get-LoginActivity {
    $successfulLogins = @()
    $failedLogins = @()
    $timeLimit = (Get-Date).AddDays(-30)

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = 4624, 4625
            StartTime = $timeLimit
        } -MaxEvents 500 -ErrorAction Stop

        foreach ($event in $events) {
            $xml = [xml]$event.ToXml()
            $user = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }) | Select-Object -ExpandProperty '#text'
            $sourceIP = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }) | Select-Object -ExpandProperty '#text'
            $logonType = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' }) | Select-Object -ExpandProperty '#text'
            $logonTypeDesc = switch ($logonType) {
                "2" { "Local (Console)" }
                "10" { "RDP" }
                default { "Other ($logonType)" }
            }

            $login = [PSCustomObject]@{
                Time = $event.TimeCreated
                User = if ($null -eq $user) { "Unknown" } else { $user }
                SourceIP = if ($null -eq $sourceIP) { "N/A" } else { $sourceIP }
                LogonType = $logonTypeDesc
            }

            if ($event.Id -eq 4624) {
                $successfulLogins += $login
            } else {
                $failedLogins += $login
            }
        }
    }
    catch {
        Write-Warning "Error accessing event logs: $($_.Exception.Message)"
    }

    return @{ Successful = $successfulLogins; Failed = $failedLogins }
}

function Get-SuspiciousProcesses {
    try {
        $processes = Get-Process -ErrorAction SilentlyContinue | Where-Object {
            $_.Path -and (
                $_.Path -notlike "*\Windows\*" -and
                $_.Path -notlike "*\Program Files\*" -and
                $_.Path -notlike "*\Program Files (x86)\*"
            )
        }
        $suspicious = @()
        foreach ($proc in $processes) {
            $suspicious += [PSCustomObject]@{
                ProcessName = $proc.ProcessName
                Path = $proc.Path
                CPU = $proc.CPU
                MemoryMB = [math]::Round($proc.WorkingSet64 / 1MB, 2)
            }
        }
        return $suspicious
    }
    catch {
        Write-Warning "Error checking processes: $($_.Exception.Message)"
        return @()
    }
}

function Get-UnquotedServicePaths {
    try {
        $services = Get-WmiObject -Class Win32_Service -ErrorAction SilentlyContinue | Where-Object {
            $_.PathName -and $_.PathName -notlike '"*"' -and $_.PathName -match "\s"
        }
        $vulnerableServices = @()
        foreach ($svc in $services) {
            $vulnerableServices += [PSCustomObject]@{
                ServiceName = $svc.Name
                PathName = $svc.PathName
                State = $svc.State
            }
        }
        return $vulnerableServices
    }
    catch {
        Write-Warning "Error checking service paths: $($_.Exception.Message)"
        return @()
    }
}

function Get-SecurityRecommendations {
    param ($OpenPorts, $LoginActivity, $SuspiciousProcesses, $UnquotedServicePaths)
    $recommendations = @()

    $recommendations += [PSCustomObject]@{
        Issue = "Unnecessary Open Ports"
        Recommendation = "Close unused ports to reduce attack surface."
        Action = "Use 'netstat -an' to identify listening ports and disable services via 'services.msc' or firewall rules."
        Priority = "High"
    }

    if ($OpenPorts | Where-Object { $_.Port -eq 3389 -and $_.Status -eq "Open" }) {
        $recommendations += [PSCustomObject]@{
            Issue = "RDP Port (3389) Open"
            Recommendation = "Restrict RDP to specific IPs, enable NLA, or disable if unused."
            Action = "Configure firewall to allow RDP from trusted IPs. Enable NLA in System Properties > Remote Desktop."
            Priority = "Critical"
        }
    }

    if ($OpenPorts | Where-Object { $_.Port -eq 445 -and $_.Status -eq "Open" }) {
        $recommendations += [PSCustomObject]@{
            Issue = "SMB Port (445) Open"
            Recommendation = "Disable SMBv1 and restrict SMB access."
            Action = "Run 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol'. Block 445 in firewall."
            Priority = "High"
        }
    }

    if ($LoginActivity.Failed.Count -gt 10) {
        $recommendations += [PSCustomObject]@{
            Issue = "Multiple Failed Login Attempts"
            Recommendation = "Enable account lockout policy to prevent brute-force attacks."
            Action = "In 'secpol.msc', set Account Lockout Policy: Threshold to 5, Duration to 15 min."
            Priority = "High"
        }
    }

    if ($LoginActivity.Successful | Where-Object { $_.LogonType -eq "RDP" -and $_.SourceIP -notlike "192.168.*" }) {
        $recommendations += [PSCustomObject]@{
            Issue = "RDP Logins from External IPs"
            Recommendation = "Restrict RDP to internal or trusted IPs."
            Action = "Create inbound firewall rule to allow RDP only from specific IP ranges."
            Priority = "Critical"
        }
    }

    if ($SuspiciousProcesses.Count -gt 0) {
        $recommendations += [PSCustomObject]@{
            Issue = "Suspicious Processes Detected"
            Recommendation = "Review processes running from non-standard locations."
            Action = "Run 'Get-Process' and investigate paths not in 'Windows' or 'Program Files'. Consider AV scanning."
            Priority = "Critical"
        }
    }

    if ($UnquotedServicePaths.Count -gt 0) {
        $recommendations += [PSCustomObject]@{
            Issue = "Unquoted Service Paths Detected"
            Recommendation = "Fix unquoted service paths to prevent privilege escalation."
            Action = "Run 'sc qc <ServiceName>' to verify path, then update via 'sc config <ServiceName> binPath= `"`"<Path>`"`"'."
            Priority = "High"
        }
    }

    try {
        $fwStatus = Get-NetFirewallProfile | Where-Object { $_.Enabled -eq $False }
        if ($fwStatus) {
            $recommendations += [PSCustomObject]@{
                Issue = "Windows Firewall Disabled"
                Recommendation = "Enable Windows Firewall on all profiles."
                Action = "Run 'Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True'."
                Priority = "Critical"
            }
        }
    }
    catch {
        Write-Warning "Error checking firewall status: $($_.Exception.Message)"
    }

    try {
        $transcription = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue).EnableTranscripting
        if ($null -eq $transcription -or $transcription -eq 0) {
            $recommendations += [PSCustomObject]@{
                Issue = "PowerShell Transcription Disabled"
                Recommendation = "Enable PowerShell transcription for auditing."
                Action = "In 'gpedit.msc', enable 'Turn on PowerShell Transcription' under Administrative Templates > Windows Components > PowerShell."
                Priority = "High"
            }
        }
    }
    catch {
        Write-Warning "Error checking PowerShell transcription: $($_.Exception.Message)"
    }

    try {
        $uacStatus = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue).EnableLUA
        if ($uacStatus -eq 0) {
            $recommendations += [PSCustomObject]@{
                Issue = "UAC Disabled"
                Recommendation = "Enable UAC to prevent unauthorized changes."
                Action = "Set 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA' to 1."
                Priority = "High"
            }
        }
    }
    catch {
        Write-Warning "Error checking UAC status: $($_.Exception.Message)"
    }

    try {
        $autoUpdates = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -ErrorAction SilentlyContinue).AUOptions
        if ($autoUpdates -ne 4) {
            $recommendations += [PSCustomObject]@{
                Issue = "Automatic Updates Disabled"
                Recommendation = "Enable automatic updates for patches."
                Action = "Configure via 'gpedit.msc' under Windows Update settings."
                Priority = "High"
            }
        }
    }
    catch {
        Write-Warning "Error checking update status: $($_.Exception.Message)"
    }

    try {
        $avStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($avStatus -and -not $avStatus.AntivirusEnabled) {
            $recommendations += [PSCustomObject]@{
                Issue = "Antivirus Disabled"
                Recommendation = "Enable Windows Defender or third-party antivirus."
                Action = "Run 'Set-MpPreference -DisableRealtimeMonitoring $false' or install antivirus."
                Priority = "Critical"
            }
        }
    }
    catch {
        Write-Warning "Error checking antivirus status: $($_.Exception.Message)"
    }

    try {
        $execPolicy = Get-ExecutionPolicy -ErrorAction SilentlyContinue
        if ($execPolicy -notin @("RemoteSigned", "Restricted")) {
            $recommendations += [PSCustomObject]@{
                Issue = "Insecure PowerShell Execution Policy"
                Recommendation = "Set to RemoteSigned or Restricted."
                Action = "Run 'Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy RemoteSigned'."
                Priority = "High"
            }
        }
    }
    catch {
        Write-Warning "Error checking execution policy: $($_.Exception.Message)"
    }

    try {
        $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($guestAccount -and $guestAccount.Enabled) {
            $recommendations += [PSCustomObject]@{
                Issue = "Guest Account Enabled"
                Recommendation = "Disable Guest account to prevent unauthorized access."
                Action = "Run 'net user Guest /active:no'."
                Priority = "High"
            }
        }
    }
    catch {
        Write-Warning "Error checking Guest account: $($_.Exception.Message)"
    }

    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        if ($secureBoot -eq $false) {
            $recommendations += [PSCustomObject]@{
                Issue = "Secure Boot Disabled"
                Recommendation = "Enable Secure Boot in BIOS/UEFI."
                Action = "Restart system, enter BIOS/UEFI, and enable Secure Boot."
                Priority = "High"
            }
        }
    }
    catch {
        Write-Warning "Error checking Secure Boot: $($_.Exception.Message)"
    }

    try {
        $nlaStatus = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ErrorAction SilentlyContinue).UserAuthentication
        if ($nlaStatus -ne 1) {
            $recommendations += [PSCustomObject]@{
                Issue = "RDP NLA Disabled"
                Recommendation = "Enable Network Level Authentication for RDP."
                Action = "In System Properties > Remote Desktop, check 'Require NLA' or set registry key 'UserAuthentication' to 1."
                Priority = "Critical"
            }
        }
    }
    catch {
        Write-Warning "Error checking RDP NLA: $($_.Exception.Message)"
    }

    try {
        $rdpEncrypt = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ErrorAction SilentlyContinue).MinEncryptionLevel
        if ($rdpEncrypt -lt 3) {
            $recommendations += [PSCustomObject]@{
                Issue = "Weak RDP Encryption"
                Recommendation = "Set RDP encryption to High (level 3 or 4)."
                Action = "Set registry key 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\MinEncryptionLevel' to 3."
                Priority = "High"
            }
        }
    }
    catch {
        Write-Warning "Error checking RDP encryption: $($_.Exception.Message)"
    }

    try {
        $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
        if ($admins.Count -gt 2) {
            $recommendations += [PSCustomObject]@{
                Issue = "Excessive Local Administrators"
                Recommendation = "Limit local administrator accounts to essential users."
                Action = "Run 'net localgroup Administrators' to review and remove unnecessary accounts."
                Priority = "High"
            }
        }
    }
    catch {
        Write-Warning "Error checking local administrators: $($_.Exception.Message)"
    }

    try {
        $lastPatch = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if (-not $lastPatch -or $lastPatch.InstalledOn -lt (Get-Date).AddMonths(-3)) {
            $recommendations += [PSCustomObject]@{
                Issue = "Outdated System Patches"
                Recommendation = "Install recent Windows updates."
                Action = "Run 'wuauclt.exe /detectnow' or check Windows Update settings."
                Priority = "High"
            }
        }
    }
    catch {
        Write-Warning "Error checking patch status: $($_.Exception.Message)"
    }

    try {
        $lockoutThreshold = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ErrorAction SilentlyContinue).MaximumPasswordAge
        if ($null -eq $lockoutThreshold -or $lockoutThreshold -eq 0) {
            $recommendations += [PSCustomObject]@{
                Issue = "No Account Lockout Policy"
                Recommendation = "Configure account lockout to prevent brute-force attacks."
                Action = "In 'secpol.msc', set Account Lockout Threshold to 5 attempts."
                Priority = "High"
            }
        }
    }
    catch {
        Write-Warning "Error checking account lockout policy: $($_.Exception.Message)"
    }

    try {
        $idleTimeout = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction SilentlyContinue).MaxIdleTime
        if ($null -eq $idleTimeout -or $idleTimeout -eq 0) {
            $recommendations += [PSCustomObject]@{
                Issue = "No RDP Session Timeout"
                Recommendation = "Set an idle timeout for RDP sessions."
                Action = "In 'gpedit.msc', set 'Set time limit for active but idle Remote Desktop Services sessions' to 15 minutes."
                Priority = "High"
            }
        }
    }
    catch {
        Write-Warning "Error checking RDP session timeout: $($_.Exception.Message)"
    }

    try {
        $exclusions = Get-MpPreference -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ExclusionPath
        if ($exclusions -and $exclusions.Count -gt 0) {
            $recommendations += [PSCustomObject]@{
                Issue = "Windows Defender Exclusions Detected"
                Recommendation = "Review and remove unnecessary exclusions."
                Action = "Run 'Get-MpPreference | Select-Object ExclusionPath' and use 'Remove-MpPreference -ExclusionPath' for risky paths."
                Priority = "High"
            }
        }
    }
    catch {
        Write-Warning "Error checking Defender exclusions: $($_.Exception.Message)"
    }

    try {
        $rdpPort = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ErrorAction SilentlyContinue).PortNumber
        if ($rdpPort -ne 3389) {
            $recommendations += [PSCustomObject]@{
                Issue = "Non-Standard RDP Port ($rdpPort)"
                Recommendation = "Ensure non-standard RDP port is documented and firewalled."
                Action = "Verify firewall rules allow only trusted IPs to port $rdpPort. Document port change."
                Priority = "High"
            }
        }
    }
    catch {
        Write-Warning "Error checking RDP port: $($_.Exception.Message)"
    }

    try {
        $minPwLength = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ErrorAction SilentlyContinue).MinimumPasswordLength
        $pwComplexity = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ErrorAction SilentlyContinue).PasswordComplexity
        if ($null -eq $minPwLength -or $minPwLength -lt 12 -or $pwComplexity -eq 0) {
            $recommendations += [PSCustomObject]@{
                Issue = "Weak Password Policy"
                Recommendation = "Set minimum password length to 12 and enable complexity."
                Action = "In 'secpol.msc', set Password Policy: Minimum Length to 12, Complexity Enabled."
                Priority = "High"
            }
        }
    }
    catch {
        Write-Warning "Error checking password policy: $($_.Exception.Message)"
    }

    try {
        $rdsNla = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction SilentlyContinue).UserAuthenticationRequired
        if ($null -eq $rdsNla -or $rdsNla -ne 1) {
            $recommendations += [PSCustomObject]@{
                Issue = "RDS NLA Not Enforced via Policy"
                Recommendation = "Enforce NLA for Remote Desktop via Group Policy."
                Action = "In 'gpedit.msc', set 'Require user authentication for remote connections by using NLA' to Enabled."
                Priority = "Critical"
            }
        }
    }
    catch {
        Write-Warning "Error checking RDS configuration: $($_.Exception.Message)"
    }

    try {
        $realTime = Get-MpPreference -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisableRealtimeMonitoring
        if ($realTime -eq $true) {
            $recommendations += [PSCustomObject]@{
                Issue = "Windows Defender Real-Time Protection Disabled"
                Recommendation = "Enable real-time protection for malware defense."
                Action = "Run 'Set-MpPreference -DisableRealtimeMonitoring $false'."
                Priority = "Critical"
            }
        }
    }
    catch {
        Write-Warning "Error checking real-time protection: $($_.Exception.Message)"
    }

    try {
        $riskyServices = Get-Service -Name "Telnet", "FTP" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" }
        if ($riskyServices) {
            $serviceNames = ($riskyServices | Select-Object -ExpandProperty Name) -join ", "
            $recommendations += [PSCustomObject]@{
                Issue = "Risky Services Running ($serviceNames)"
                Recommendation = "Disable unnecessary or insecure services."
                Action = "Stop and disable services via 'services.msc' or run 'Stop-Service -Name <Name>; Set-Service -Name <Name> -StartupType Disabled'."
                Priority = "High"
            }
        }
    }
    catch {
        Write-Warning "Error checking services: $($_.Exception.Message)"
    }

    try {
        $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike "ADMIN$" -and $_.Name -notlike "C$" -and $_.Name -notlike "IPC$" }
        if ($shares) {
            $shareNames = ($shares | Select-Object -ExpandProperty Name) -join ", "
            $recommendations += [PSCustomObject]@{
                Issue = "Open Network Shares Detected ($shareNames)"
                Recommendation = "Review and restrict network shares to authorized users."
                Action = "Run 'Get-SmbShare' and use 'Set-SmbShare' to limit access or remove unnecessary shares."
                Priority = "High"
            }
        }
    }
    catch {
        Write-Warning "Error checking shared folders: $($_.Exception.Message)"
    }

    try {
        $bitLocker = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue | Select-Object -ExpandProperty VolumeStatus
        if ($bitLocker -ne "FullyEncrypted") {
            $recommendations += [PSCustomObject]@{
                Issue = "BitLocker Not Enabled on System Drive"
                Recommendation = "Enable BitLocker to protect data at rest."
                Action = "Run 'manage-bde -on $env:SystemDrive' or enable via Control Panel > BitLocker."
                Priority = "High"
            }
        }
    }
    catch {
        Write-Warning "Error checking BitLocker status: $($_.Exception.Message)"
    }

    try {
        $smbSigning = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ErrorAction SilentlyContinue).RequireSecuritySignature
        if ($null -eq $smbSigning -or $smbSigning -eq 0) {
            $recommendations += [PSCustomObject]@{
                Issue = "SMB Signing Not Enabled"
                Recommendation = "Enable SMB signing to prevent man-in-the-middle attacks."
                Action = "Set registry key 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature' to 1."
                Priority = "High"
            }
        }
    }
    catch {
        Write-Warning "Error checking SMB signing: $($_.Exception.Message)"
    }

    try {
        $credGuard = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue).LsaCfgFlags
        if ($null -eq $credGuard -or $credGuard -eq 0) {
            $recommendations += [PSCustomObject]@{
                Issue = "Windows Credential Guard Disabled"
                Recommendation = "Enable Credential Guard to protect against credential theft."
                Action = "Run 'reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LsaCfgFlags /t REG_DWORD /d 2 /f' and enable via Group Policy."
                Priority = "High"
            }
        }
    }
    catch {
        Write-Warning "Error checking Credential Guard: $($_.Exception.Message)"
    }

    try {
        $psLogging = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging
        $moduleLogging = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue).EnableModuleLogging
        if ($null -eq $psLogging -or $psLogging -eq 0 -or $null -eq $moduleLogging -or $moduleLogging -eq 0) {
            $recommendations += [PSCustomObject]@{
                Issue = "PowerShell Logging Not Fully Enabled"
                Recommendation = "Enable script block and module logging for auditing."
                Action = "In 'gpedit.msc', enable PowerShell Script Block Logging and Module Logging under Administrative Templates > Windows Components > PowerShell."
                Priority = "High"
            }
        }
    }
    catch {
        Write-Warning "Error checking PowerShell logging: $($_.Exception.Message)"
    }

    try {
        $smbv1 = (Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue).State
        $tls10 = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -ErrorAction SilentlyContinue).Enabled
        $tls11 = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -ErrorAction SilentlyContinue).Enabled
        if ($smbv1 -eq "Enabled" -or ($null -ne $tls10 -and $tls10 -eq 1) -or ($null -ne $tls11 -and $tls11 -eq 1)) {
            $recommendations += [PSCustomObject]@{
                Issue = "Deprecated Protocols Enabled"
                Recommendation = "Disable SMBv1, TLS 1.0, and TLS 1.1 to prevent exploits."
                Action = "Run 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol' and set registry keys 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server\Enabled' and 'TLS 1.1\Server\Enabled' to 0."
                Priority = "Critical"
            }
        }
    }
    catch {
        Write-Warning "Error checking deprecated protocols: $($_.Exception.Message)"
    }

    try {
        $autorun = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | Select-Object -Property * | Where-Object { $_ -notlike "*WindowsDefender*" -and $_ -notlike "*SecurityHealth*" }
        if ($autorun.PSObject.Properties.Name.Count -gt 5) {
            $recommendations += [PSCustomObject]@{
                Issue = "Excessive Autorun Entries"
                Recommendation = "Review autorun entries for potential malware persistence."
                Action = "Run 'reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' and remove suspicious entries."
                Priority = "High"
            }
        }
    }
    catch {
        Write-Warning "Error checking autorun entries: $($_.Exception.Message)"
    }

    try {
        $inboundRules = Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction SilentlyContinue
        if ($inboundRules.Count -gt 50) {
            $recommendations += [PSCustomObject]@{
                Issue = "Excessive Inbound Firewall Rules ($($inboundRules.Count))"
                Recommendation = "Review and reduce inbound firewall rules to minimize attack surface."
                Action = "Run 'Get-NetFirewallRule -Direction Inbound -Enabled True' and disable or remove unnecessary rules."
                Priority = "High"
            }
        }
    }
    catch {
        Write-Warning "Error checking firewall rules: $($_.Exception.Message)"
    }

    try {
        $adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
        if ($adminAccount -and $adminAccount.Enabled) {
            $recommendations += [PSCustomObject]@{
                Issue = "Default Administrator Account Enabled"
                Recommendation = "Disable or rename the default Administrator account."
                Action = "Run 'net user Administrator /active:no' or rename via 'wmic useraccount where name=`"Administrator`" call rename NewName'."
                Priority = "High"
            }
        }
    }
    catch {
        Write-Warning "Error checking admin account status: $($_.Exception.Message)"
    }

    try {
        $laps = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -ErrorAction SilentlyContinue).AdmPwdEnabled
        if ($null -eq $laps -or $laps -eq 0) {
            $recommendations += [PSCustomObject]@{
                Issue = "LAPS Not Configured"
                Recommendation = "Implement LAPS to manage local admin passwords."
                Action = "Install LAPS and configure via Group Policy: 'Computer Configuration > Administrative Templates > LAPS'."
                Priority = "High"
            }
        }
    }
    catch {
        Write-Warning "Error checking LAPS configuration: $($_.Exception.Message)"
    }

    try {
        $logSize = (Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue).MaximumSizeInBytes
        if ($null -eq $logSize -or $logSize -lt 20MB) {
            $recommendations += [PSCustomObject]@{
                Issue = "Security Event Log Size Too Small"
                Recommendation = "Increase Security event log size to retain audit data."
                Action = "Run 'wevtutil sl Security /ms:20971520' to set size to 20MB."
                Priority = "High"
            }
        }
    }
    catch {
        Write-Warning "Error checking event log size: $($_.Exception.Message)"
    }

    try {
        $appLocker = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
        if (-not $appLocker.RuleCollections) {
            $recommendations += [PSCustomObject]@{
                Issue = "AppLocker Not Configured"
                Recommendation = "Implement AppLocker to restrict unauthorized applications."
                Action = "Configure AppLocker rules via 'secpol.msc' under Application Control Policies > AppLocker."
                Priority = "High"
            }
        }
    }
    catch {
        Write-Warning "Error checking AppLocker configuration: $($_.Exception.Message)"
    }

    return $recommendations
}

function Generate-HtmlReport {
    param ($ScanResults, $LoginActivity, $SuspiciousProcesses, $UnquotedServicePaths, $Recommendations, $OutputPath)

    $openPorts = $ScanResults | Where-Object { $_.Status -eq "Open" }
    $date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $computerName = $env:COMPUTERNAME
    $openPortCount = $openPorts.Count
    $criticalCount = ($Recommendations | Where-Object { $_.Priority -eq "Critical" }).Count
    $failedLoginCount = $LoginActivity.Failed.Count
    $suspiciousProcessCount = $SuspiciousProcesses.Count
    $unquotedServiceCount = $UnquotedServicePaths.Count

    # Prepare data for Chart.js
    $portLabels = ($ScanResults | ForEach-Object { $_.Port }).ToString() -join ","
    $portStatuses = ($ScanResults | ForEach-Object { if ($_.Status -eq "Open") { 1 } else { 0 } }).ToString() -join ","
    $portServices = ($ScanResults | ForEach-Object { $_.Service }) -join ","

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Threat Hunt Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body class="bg-gray-900 text-white">
    <nav class="bg-gray-800 p-4 sticky top-0 z-50 shadow-md">
        <div class="container mx-auto flex justify-between items-center">
            <div class="text-xl font-bold text-red-500">Security Report</div>
            <div class="space-x-4">
                <a href="#dashboard" class="text-red-500 hover:text-white">Dashboard</a>
                <a href="#ports" class="text-red-500 hover:text-white">Port Scan</a>
                <a href="#logins" class="text-red-500 hover:text-white">Login Activity</a>
                <a href="#processes" class="text-red-500 hover:text-white">Suspicious Processes</a>
                <a href="#services" class="text-red-500 hover:text-white">Service Paths</a>
                <a href="#recommendations" class="text-red-500 hover:text-white">Recommendations</a>
            </div>
        </div>
    </nav>
    <div class="container mx-auto p-6">
        <h1 class="text-3xl font-bold text-center text-red-500 mb-6">Security Threat Hunt Report</h1>
        <p class="text-center mb-2"><strong>Computer:</strong> $computerName</p>
        <p class="text-center mb-6"><strong>Date:</strong> $date</p>

        <section id="dashboard" class="mb-8">
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
                <div class="bg-gray-800 p-4 rounded-lg text-center">
                    <h3 class="text-red-500 font-semibold">Open Ports</h3>
                    <p class="text-2xl">$openPortCount</p>
                </div>
                <div class="bg-gray-800 p-4 rounded-lg text-center">
                    <h3 class="text-red-500 font-semibold">Critical Issues</h3>
                    <p class="text-2xl">$criticalCount</p>
                </div>
                <div class="bg-gray-800 p-4 rounded-lg text-center">
                    <h3 class="text-red-500 font-semibold">Failed Logins (30 Days)</h3>
                    <p class="text-2xl">$failedLoginCount</p>
                </div>
                <div class="bg-gray-800 p-4 rounded-lg text-center">
                    <h3 class="text-red-500 font-semibold">Suspicious Processes</h3>
                    <p class="text-2xl">$suspiciousProcessCount</p>
                </div>
                <div class="bg-gray-800 p-4 rounded-lg text-center">
                    <h3 class="text-red-500 font-semibold">Unquoted Service Paths</h3>
                    <p class="text-2xl">$unquotedServiceCount</p>
                </div>
            </div>
        </section>

        <section id="ports" class="mb-8">
            <details open class="bg-gray-800 p-4 rounded-lg">
                <summary class="text-red-500 font-semibold cursor-pointer">Port Scan Results</summary>
                <canvas id="portChart" class="my-4" height="200"></canvas>
                <table class="w-full border-collapse bg-gray-700 rounded-lg overflow-hidden">
                    <thead>
                        <tr class="bg-red-500 text-black">
                            <th class="p-3 text-left">Port</th>
                            <th class="p-3 text-left">Status</th>
                            <th class="p-3 text-left">Service</th>
                        </tr>
                    </thead>
                    <tbody>
"@
    foreach ($result in $ScanResults) {
        $html += "<tr class='border-b border-gray-600'><td class='p-3'>$($result.Port)</td><td class='p-3'>$($result.Status)</td><td class='p-3'>$($result.Service)</td></tr>"
    }
    $html += @"
                    </tbody>
                </table>
            </details>
        </section>

        <section id="logins" class="mb-8">
            <details open class="bg-gray-800 p-4 rounded-lg">
                <summary class="text-red-500 font-semibold cursor-pointer">Successful Logins (Last 30 Days)</summary>
                <table class="w-full border-collapse bg-gray-700 rounded-lg overflow-hidden">
                    <thead>
                        <tr class="bg-red-500 text-black">
                            <th class="p-3 text-left">Time</th>
                            <th class="p-3 text-left">User</th>
                            <th class="p-3 text-left">Source IP</th>
                            <th class="p-3 text-left">Logon Type</th>
                        </tr>
                    </thead>
                    <tbody>
"@
    if ($LoginActivity.Successful.Count -eq 0) {
        $html += "<tr><td colspan='4' class='p-3 text-center'>No successful logins recorded.</td></tr>"
    } else {
        foreach ($login in $LoginActivity.Successful) {
            $html += "<tr class='border-b border-gray-600'><td class='p-3'>$($login.Time)</td><td class='p-3'>$($login.User)</td><td class='p-3'>$($login.SourceIP)</td><td class='p-3'>$($login.LogonType)</td></tr>"
        }
    }
    $html += @"
                    </tbody>
                </table>
            </details>
            <details open class="bg-gray-800 p-4 rounded-lg">
                <summary class="text-red-500 font-semibold cursor-pointer">Failed Login Attempts (Last 30 Days)</summary>
                <table class="w-full border-collapse bg-gray-700 rounded-lg overflow-hidden">
                    <thead>
                        <tr class="bg-red-500 text-black">
                            <th class="p-3 text-left">Time</th>
                            <th class="p-3 text-left">User</th>
                            <th class="p-3 text-left">Source IP</th>
                            <th class="p-3 text-left">Logon Type</th>
                        </tr>
                    </thead>
                    <tbody>
"@
    if ($LoginActivity.Failed.Count -eq 0) {
        $html += "<tr><td colspan='4' class='p-3 text-center'>No failed login attempts recorded.</td></tr>"
    } else {
        foreach ($login in $LoginActivity.Failed) {
            $html += "<tr class='border-b border-gray-600'><td class='p-3'>$($login.Time)</td><td class='p-3'>$($login.User)</td><td class='p-3'>$($login.SourceIP)</td><td class='p-3'>$($login.LogonType)</td></tr>"
        }
    }
    $html += @"
                    </tbody>
                </table>
            </details>
        </section>

        <section id="processes" class="mb-8">
            <details open class="bg-gray-800 p-4 rounded-lg">
                <summary class="text-red-500 font-semibold cursor-pointer">Suspicious Processes</summary>
                <table class="w-full border-collapse bg-gray-700 rounded-lg overflow-hidden">
                    <thead>
                        <tr class="bg-red-500 text-black">
                            <th class="p-3 text-left">Process Name</th>
                            <th class="p-3 text-left">Path</th>
                            <th class="p-3 text-left">CPU (s)</th>
                            <th class="p-3 text-left">Memory (MB)</th>
                        </tr>
                    </thead>
                    <tbody>
"@
    if ($SuspiciousProcesses.Count -eq 0) {
        $html += "<tr><td colspan='4' class='p-3 text-center'>No suspicious processes detected.</td></tr>"
    } else {
        foreach ($proc in $SuspiciousProcesses) {
            $html += "<tr class='border-b border-gray-600'><td class='p-3'>$($proc.ProcessName)</td><td class='p-3'>$($proc.Path)</td><td class='p-3'>$($proc.CPU)</td><td class='p-3'>$($proc.MemoryMB)</td></tr>"
        }
    }
    $html += @"
                    </tbody>
                </table>
            </details>
        </section>

        <section id="services" class="mb-8">
            <details open class="bg-gray-800 p-4 rounded-lg">
                <summary class="text-red-500 font-semibold cursor-pointer">Unquoted Service Paths</summary>
                <table class="w-full border-collapse bg-gray-700 rounded-lg overflow-hidden">
                    <thead>
                        <tr class="bg-red-500 text-black">
                            <th class="p-3 text-left">Service Name</th>
                            <th class="p-3 text-left">Path</th>
                            <th class="p-3 text-left">State</th>
                        </tr>
                    </thead>
                    <tbody>
"@
    if ($UnquotedServicePaths.Count -eq 0) {
        $html += "<tr><td colspan='3' class='p-3 text-center'>No unquoted service paths detected.</td></tr>"
    } else {
        foreach ($svc in $UnquotedServicePaths) {
            $html += "<tr class='border-b border-gray-600'><td class='p-3'>$($svc.ServiceName)</td><td class='p-3'>$($svc.PathName)</td><td class='p-3'>$($svc.State)</td></tr>"
        }
    }
    $html += @"
                    </tbody>
                </table>
            </details>
        </section>

        <section id="recommendations" class="mb-8">
            <details open class="bg-gray-800 p-4 rounded-lg">
                <summary class="text-red-500 font-semibold cursor-pointer">Security Recommendations</summary>
                <table class="w-full border-collapse bg-gray-700 rounded-lg overflow-hidden">
                    <thead>
                        <tr class="bg-red-500 text-black">
                            <th class="p-3 text-left">Issue</th>
                            <th class="p-3 text-left">Recommendation</th>
                            <th class="p-3 text-left">Action</th>
                            <th class="p-3 text-left">Priority</th>
                        </tr>
                    </thead>
                    <tbody>
"@
    foreach ($rec in $Recommendations) {
        $priorityClass = if ($rec.Priority -eq "Critical") { "text-red-500 font-bold" } else { "text-red-300 font-semibold" }
        $html += "<tr class='border-b border-gray-600'><td class='p-3'>$($rec.Issue)</td><td class='p-3'>$($rec.Recommendation)</td><td class='p-3'>$($rec.Action)</td><td class='$priorityClass p-3'>$($rec.Priority)</td></tr>"
    }
    $html += @"
                    </tbody>
                </table>
            </details>
        </section>
    </div>
    <script>
        const ctx = document.getElementById('portChart').getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: [$portLabels],
                datasets: [{
                    label: 'Port Status',
                    data: [$portStatuses],
                    backgroundColor: [$portServices].map(s => s === 'Unknown' ? 'rgba(255, 99, 132, 0.5)' : 'rgba(75, 192, 192, 0.5)'),
                    borderColor: [$portServices].map(s => s === 'Unknown' ? 'rgba(255, 99, 132, 1)' : 'rgba(75, 192, 192, 1)'),
                    borderWidth: 1
                }]
            },
            options: {
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 1,
                        ticks: {
                            callback: function(value) { return value === 1 ? 'Open' : 'Closed'; },
                            stepSize: 1,
                            color: 'white'
                        },
                        grid: { color: 'rgba(255, 255, 255, 0.1)' }
                    },
                    x: { grid: { color: 'rgba(255, 255, 255, 0.1)' }, ticks: { color: 'white' } }
                },
                plugins: {
                    legend: { labels: { color: 'white' } },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const services = [$portServices];
                                return `Port: ${context.label}, Service: ${services[context.dataIndex]}`;
                            }
                        }
                    }
                }
            }
        });
    </script>
</body>
</html>
"@

    try {
        $parentDir = Split-Path $OutputPath -Parent
        if (-not (Test-Path $parentDir)) {
            New-Item -Path $parentDir -ItemType Directory -Force | Out-Null
        }
        $testFile = Join-Path $parentDir "testwrite.txt"
        "test" | Out-File -FilePath $testFile -ErrorAction Stop
        Remove-Item $testFile -ErrorAction SilentlyContinue
        $html | Out-File -FilePath $OutputPath -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to write to $OutputPath - $($_.Exception.Message)"
        $fallbackPath = Join-Path $env:TEMP "SecurityThreatHuntReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        Write-Host "Attempting to save report to fallback path: $fallbackPath"
        try {
            $html | Out-File -FilePath $fallbackPath -Encoding UTF8 -ErrorAction Stop
            $OutputPath = $fallbackPath
        }
        catch {
            throw "Failed to save report to $fallbackPath - $($_.Exception.Message)"
        }
    }
    return $OutputPath
}

try {
    $portsToScan = @(21, 22, 23, 25, 80, 110, 143, 443, 3389, 445, 135, 139, 1433, 3306, 8080)

    Write-Host "Scanning ports..."
    $scanResults = Test-Port -Ports $portsToScan

    Write-Host "Checking login activity..."
    $loginActivity = Get-LoginActivity

    Write-Host "Checking suspicious processes..."
    $suspiciousProcesses = Get-SuspiciousProcesses

    Write-Host "Checking unquoted service paths..."
    $unquotedServicePaths = Get-UnquotedServicePaths

    Write-Host "Generating security recommendations..."
    $recommendations = Get-SecurityRecommendations -OpenPorts $scanResults -LoginActivity $loginActivity -SuspiciousProcesses $suspiciousProcesses -UnquotedServicePaths $unquotedServicePaths

    Write-Host "Generating HTML report..."
    $outputPath = Join-Path $env:USERPROFILE "Documents\SecurityThreatHuntReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $finalPath = Generate-HtmlReport -ScanResults $scanResults -LoginActivity $loginActivity -SuspiciousProcesses $suspiciousProcesses -UnquotedServicePaths $unquotedServicePaths -Recommendations $recommendations -OutputPath $outputPath

    Write-Host "Report generated at: $finalPath"
}
catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
}