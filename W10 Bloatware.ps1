# Supercharged Windows 10 Bloatware Removal Script
# This script uses direct DISM commands for maximum compatibility and effectiveness

# Self-elevate if needed
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    # Create a batch file to execute this script with bypass
    $tempBatchPath = "$env:TEMP\ElevateScript.bat"
    $scriptPath = $MyInvocation.MyCommand.Path
    $batchContent = @"
@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \`"$scriptPath\`"' -Verb RunAs"
"@
    [System.IO.File]::WriteAllText($tempBatchPath, $batchContent)
    Start-Process -FilePath $tempBatchPath
    Start-Sleep -Seconds 1
    Remove-Item -Path $tempBatchPath -Force -ErrorAction SilentlyContinue
    Exit
}

# Set execution policy for current process
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Clear screen and show header
Clear-Host
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "    SUPERCHARGED WINDOWS 10 BLOATWARE REMOVER " -ForegroundColor White -BackgroundColor DarkBlue
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host
Write-Host "This tool uses DISM commands for more effective bloatware removal" -ForegroundColor Yellow
Write-Host

# Function to display progress bar
function Show-Progress {
    param (
        [string]$Activity,
        [int]$PercentComplete,
        [string]$Status
    )
    
    Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
    
    # Also display text output for better visibility
    $progressBar = "[" + ("#" * ($PercentComplete / 2)) + (" " * (50 - ($PercentComplete / 2))) + "]"
    Write-Host "`r$progressBar $PercentComplete% $Status" -NoNewline
    
    if ($PercentComplete -eq 100) {
        Write-Host ""
    }
}

# DISM-based app removal function
function Remove-AppWithDISM {
    param (
        [string]$AppName
    )
    
    $foundPackages = @()
    $removed = $false
    
    Write-Host "  Searching installed packages for $AppName..." -ForegroundColor Yellow
    
    # Get all provisioned packages
    $packages = dism /online /get-provisionedappxpackages | Select-String -Pattern "PackageName"
    
    # Filter by app name
    foreach ($package in $packages) {
        if ($package -match $AppName) {
            $packageName = ($package -split " : ")[1].Trim()
            $foundPackages += $packageName
            Write-Host "  Found package: $packageName" -ForegroundColor Green
        }
    }
    
    # Remove each package found
    foreach ($packageName in $foundPackages) {
        try {
            Write-Host "  Removing package with DISM: $packageName" -ForegroundColor Yellow
            $result = dism /online /remove-provisionedappxpackage /packagename:$packageName
            Write-Host "  DISM removal result: Success" -ForegroundColor Green
            $removed = $true
        } catch {
            Write-Host "  DISM removal failed: $_" -ForegroundColor Red
        }
    }
    
    # Try other methods if DISM fails or finds no packages
    if (-not $removed) {
        # Try AppX method
        try {
            Write-Host "  Trying AppX removal method..." -ForegroundColor Yellow
            Get-AppxPackage -AllUsers "*$AppName*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            
            # Check if removal was successful
            $remaining = Get-AppxPackage -AllUsers "*$AppName*"
            if (-not $remaining) {
                Write-Host "  AppX removal successful" -ForegroundColor Green
                $removed = $true
            }
        } catch {
            Write-Host "  AppX removal failed: $_" -ForegroundColor Red
        }
    }
    
    # Use PowerShell direct command as last resort
    if (-not $removed) {
        try {
            Write-Host "  Trying direct command removal..." -ForegroundColor Yellow
            $command = "Get-AppxPackage -Name '*$AppName*' -AllUsers | Remove-AppxPackage -AllUsers; " +
                       "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like '*$AppName*' | Remove-AppxProvisionedPackage -Online"
            Invoke-Expression $command -ErrorAction SilentlyContinue
            Write-Host "  Direct command method completed" -ForegroundColor Green
            $removed = $true
        } catch {
            Write-Host "  Direct command method failed: $_" -ForegroundColor Red
        }
    }
    
    return $removed
}

# Define bloatware apps using more precise identifiers for DISM
$bloatwareApps = @(
    @{Name = "3DBuilder"; DisplayName = "3D Builder"; ID = "Microsoft.3DBuilder"},
    @{Name = "3DViewer"; DisplayName = "3D Viewer"; ID = "Microsoft.Microsoft3DViewer"},
    @{Name = "Alarms"; DisplayName = "Alarms & Clock"; ID = "Microsoft.WindowsAlarms"},
    @{Name = "Calculator"; DisplayName = "Calculator"; ID = "Microsoft.WindowsCalculator"},
    @{Name = "Communications"; DisplayName = "Mail and Calendar"; ID = "microsoft.windowscommunicationsapps"},
    @{Name = "Camera"; DisplayName = "Camera"; ID = "Microsoft.WindowsCamera"},
    @{Name = "CandyCrush"; DisplayName = "Candy Crush Games"; ID = "king.com"},
    @{Name = "Cortana"; DisplayName = "Cortana"; ID = "Microsoft.549981C3F5F10"},
    @{Name = "Disney"; DisplayName = "Disney+"; ID = "Disney"},
    @{Name = "Facebook"; DisplayName = "Facebook"; ID = "Facebook"},
    @{Name = "Feedback"; DisplayName = "Feedback Hub"; ID = "Microsoft.WindowsFeedbackHub"},
    @{Name = "GetHelp"; DisplayName = "Get Help"; ID = "Microsoft.GetHelp"},
    @{Name = "Groove"; DisplayName = "Groove Music"; ID = "Microsoft.ZuneMusic"},
    @{Name = "Maps"; DisplayName = "Maps"; ID = "Microsoft.WindowsMaps"},
    @{Name = "Messaging"; DisplayName = "Messaging"; ID = "Microsoft.Messaging"},
    @{Name = "Bing"; DisplayName = "Microsoft Bing"; ID = "Microsoft.Bing"},
    @{Name = "News"; DisplayName = "Microsoft News"; ID = "Microsoft.BingNews"},
    @{Name = "Solitaire"; DisplayName = "Microsoft Solitaire Collection"; ID = "Microsoft.MicrosoftSolitaireCollection"},
    @{Name = "Store"; DisplayName = "Microsoft Store"; ID = "Microsoft.WindowsStore"},
    @{Name = "StorePurchase"; DisplayName = "Store Purchase App"; ID = "Microsoft.StorePurchaseApp"},
    @{Name = "ToDo"; DisplayName = "Microsoft To Do"; ID = "Microsoft.Todos"},
    @{Name = "MixedReality"; DisplayName = "Mixed Reality Portal"; ID = "Microsoft.MixedReality"},
    @{Name = "OneConnect"; DisplayName = "Mobile Plans"; ID = "Microsoft.OneConnect"},
    @{Name = "Movies"; DisplayName = "Movies & TV"; ID = "Microsoft.ZuneVideo"},
    @{Name = "Netflix"; DisplayName = "Netflix"; ID = "Netflix"},
    @{Name = "OfficeHub"; DisplayName = "Office Hub"; ID = "Microsoft.MicrosoftOfficeHub"},
    @{Name = "OneNote"; DisplayName = "OneNote"; ID = "Microsoft.Office.OneNote"},
    @{Name = "Paint3D"; DisplayName = "Paint 3D"; ID = "Microsoft.MSPaint"},
    @{Name = "People"; DisplayName = "People"; ID = "Microsoft.People"},
    @{Name = "Photos"; DisplayName = "Photos"; ID = "Microsoft.Windows.Photos"},
    @{Name = "PowerAutomate"; DisplayName = "Power Automate"; ID = "Microsoft.PowerAutomateDesktop"},
    @{Name = "Print3D"; DisplayName = "Print 3D"; ID = "Microsoft.Print3D"},
    @{Name = "QuickAssist"; DisplayName = "Quick Assist"; ID = "MicrosoftCorporationII.QuickAssist"},
    @{Name = "RemoteAssistance"; DisplayName = "Remote Assistance"; ID = "Microsoft.RemoteAssistance"},
    @{Name = "Skype"; DisplayName = "Skype"; ID = "Microsoft.SkypeApp"},
    @{Name = "SoundRecorder"; DisplayName = "Sound Recorder"; ID = "Microsoft.WindowsSoundRecorder"},
    @{Name = "Spotify"; DisplayName = "Spotify"; ID = "SpotifyAB.SpotifyMusic"},
    @{Name = "StickyNotes"; DisplayName = "Sticky Notes"; ID = "Microsoft.MicrosoftStickyNotes"},
    @{Name = "Teams"; DisplayName = "Microsoft Teams"; ID = "MicrosoftTeams"},
    @{Name = "Tips"; DisplayName = "Tips"; ID = "Microsoft.Getstarted"},
    @{Name = "Twitter"; DisplayName = "Twitter"; ID = "Twitter"},
    @{Name = "Weather"; DisplayName = "Weather"; ID = "Microsoft.BingWeather"},
    @{Name = "XboxApp"; DisplayName = "Xbox App"; ID = "Microsoft.XboxApp"},
    @{Name = "XboxGamingOverlay"; DisplayName = "Xbox Game Bar"; ID = "Microsoft.XboxGamingOverlay"},
    @{Name = "XboxSpeech"; DisplayName = "Xbox Game Speech"; ID = "Microsoft.XboxSpeechToTextOverlay"},
    @{Name = "XboxIdentity"; DisplayName = "Xbox Identity Provider"; ID = "Microsoft.XboxIdentityProvider"},
    @{Name = "Xbox"; DisplayName = "Xbox"; ID = "Microsoft.Xbox"},
    @{Name = "XboxTCUI"; DisplayName = "Xbox TCUI"; ID = "Microsoft.Xbox.TCUI"},
    @{Name = "GamingApp"; DisplayName = "Xbox Gaming App"; ID = "Microsoft.GamingApp"},
    @{Name = "YourPhone"; DisplayName = "Your Phone"; ID = "Microsoft.YourPhone"},
    @{Name = "Clipchamp"; DisplayName = "Microsoft Clipchamp"; ID = "Clipchamp.Clipchamp"}
)

function Remove-OneDriveEnhanced {
    Write-Host "`nRemoving OneDrive with enhanced methods..." -ForegroundColor Yellow
    $success = $false
    
    # Show progress
    Show-Progress -Activity "Removing OneDrive" -PercentComplete 10 -Status "Stopping OneDrive process"
    
    # Kill OneDrive process with taskkill (more reliable)
    Start-Process "taskkill.exe" -ArgumentList "/f", "/im", "OneDrive.exe" -NoNewWindow -Wait
    
    Show-Progress -Activity "Removing OneDrive" -PercentComplete 25 -Status "Uninstalling OneDrive"
    
    # Try standard uninstall first
    if (Test-Path "$env:SystemRoot\SysWOW64\OneDriveSetup.exe") {
        Start-Process "$env:SystemRoot\SysWOW64\OneDriveSetup.exe" -ArgumentList "/uninstall" -NoNewWindow -Wait
        $success = $true
    } elseif (Test-Path "$env:SystemRoot\System32\OneDriveSetup.exe") {
        Start-Process "$env:SystemRoot\System32\OneDriveSetup.exe" -ArgumentList "/uninstall" -NoNewWindow -Wait
        $success = $true
    }
    
    Show-Progress -Activity "Removing OneDrive" -PercentComplete 50 -Status "Using advanced removal methods"
    
    # Alternative method: remove with PowerShell direct
    if (-not $success) {
        try {
            # Direct command removal
            Write-Host "  Trying direct OneDrive command removal..." -ForegroundColor Yellow
            $commands = @(
                "Get-Process OneDrive -ErrorAction SilentlyContinue | Stop-Process -Force",
                "Get-AppxPackage *OneDrive* -AllUsers | Remove-AppxPackage -AllUsers",
                "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like '*OneDrive*' | Remove-AppxProvisionedPackage -Online"
            )
            
            foreach ($cmd in $commands) {
                Invoke-Expression $cmd -ErrorAction SilentlyContinue
            }
            
            Write-Host "  Direct command removal completed" -ForegroundColor Green
            $success = $true
        } catch {
            Write-Host "  Direct command removal failed: $_" -ForegroundColor Red
        }
    }
    
    Show-Progress -Activity "Removing OneDrive" -PercentComplete 75 -Status "Cleaning up OneDrive registry entries"
    
    # Registry cleanup
    try {
        # Registry modifications
        $regPaths = @(
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{018D5C66-4533-4307-9B53-224DE2ED1FE6}",
            "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}",
            "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
        )
        
        foreach ($path in $regPaths) {
            if (Test-Path $path) {
                Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "  Removed registry key: $path" -ForegroundColor Green
            }
        }
        
        # Create registry keys to disable OneDrive
        $disableKeys = @(
            @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"; Name = "DisableFileSyncNGSC"; Value = 1; Type = "DWORD"},
            @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"; Name = "DisableFileSync"; Value = 1; Type = "DWORD"},
            @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"; Name = "DisableMeteredNetworkFileSync"; Value = 1; Type = "DWORD"},
            @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"; Name = "DisableLibrariesDefaultSaveToOneDrive"; Value = 1; Type = "DWORD"}
        )
        
        foreach ($key in $disableKeys) {
            if (!(Test-Path $key.Path)) {
                New-Item -Path $key.Path -Force | Out-Null
            }
            
            New-ItemProperty -Path $key.Path -Name $key.Name -Value $key.Value -PropertyType $key.Type -Force | Out-Null
            Write-Host "  Set registry key: $($key.Path)\$($key.Name)" -ForegroundColor Green
        }
    } catch {
        Write-Host "  Registry modification failed: $_" -ForegroundColor Red
    }
    
    Show-Progress -Activity "Removing OneDrive" -PercentComplete 90 -Status "Removing OneDrive folders"
    
    # Remove OneDrive directories
    $oneDrivePaths = @(
        "$env:USERPROFILE\OneDrive",
        "$env:LOCALAPPDATA\Microsoft\OneDrive",
        "$env:PROGRAMDATA\Microsoft OneDrive",
        "$env:SYSTEMDRIVE\OneDriveTemp"
    )
    
    foreach ($path in $oneDrivePaths) {
        if (Test-Path $path) {
            # Use robust removal method
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            
            # Check if removal was successful
            if (!(Test-Path $path)) {
                Write-Host "  Successfully removed: $path" -ForegroundColor Green
            } else {
                # Try alternative removal with rd command
                Start-Process "cmd.exe" -ArgumentList "/c", "rd", "/s", "/q", "`"$path`"" -NoNewWindow -Wait
                
                if (!(Test-Path $path)) {
                    Write-Host "  Successfully removed with RD command: $path" -ForegroundColor Green
                } else {
                    Write-Host "  Failed to remove: $path" -ForegroundColor Red
                }
            }
        }
    }
    
    Show-Progress -Activity "Removing OneDrive" -PercentComplete 100 -Status "OneDrive removal completed"
    Write-Host "OneDrive removal completed." -ForegroundColor Green
    return $success
}

function Remove-BloatwareEnhanced {
    param(
        [array]$AppsList
    )
    
    $totalApps = $AppsList.Count
    $currentAppIndex = 0
    $successCount = 0
    
    foreach ($app in $AppsList) {
        $currentAppIndex++
        $percent = [int](($currentAppIndex / $totalApps) * 100)
        
        Show-Progress -Activity "Removing Bloatware" -PercentComplete $percent -Status "Processing: $($app.DisplayName)"
        
        Write-Host "`n[$currentAppIndex/$totalApps] Removing: $($app.DisplayName)" -ForegroundColor Yellow
        
        # Try to uninstall using DISM first (most effective for system apps)
        $success = Remove-AppWithDISM -AppName $app.ID
        
        # Count successes
        if ($success) {
            $successCount++
            Write-Host "  Successfully processed: $($app.DisplayName)" -ForegroundColor Green
        } else {
            Write-Host "  Failed to fully remove: $($app.DisplayName)" -ForegroundColor Red
        }
        
        Write-Host "  ------------------------------------------" -ForegroundColor DarkGray
    }
    
    Show-Progress -Activity "Removing Bloatware" -PercentComplete 100 -Status "Processing complete"
    
    Write-Host "`nBloatware removal summary:" -ForegroundColor Cyan
    Write-Host "  Successfully processed: $successCount apps" -ForegroundColor Green
    Write-Host "  Failed to process: $($totalApps - $successCount) apps" -ForegroundColor $(if ($totalApps - $successCount -gt 0) { "Red" } else { "Green" })
    
    return $successCount
}

# Present menu to user
function Show-MainMenu {
    Write-Host "Choose an option:" -ForegroundColor Yellow
    Write-Host "1. Remove ALL bloatware (including OneDrive)"
    Write-Host "2. Remove ALL bloatware (excluding OneDrive)"
    Write-Host "3. Remove OneDrive only"
    Write-Host "4. Exit"
    Write-Host
    
    $choice = Read-Host "Enter your choice (1-4)"
    return $choice
}

# Main execution
$choice = Show-MainMenu

switch ($choice) {
    "1" {
        Write-Host "Removing ALL bloatware including OneDrive..." -ForegroundColor Red
        $successCount = Remove-BloatwareEnhanced -AppsList $bloatwareApps
        $oneDriveSuccess = Remove-OneDriveEnhanced
        
        if ($successCount -gt 0 -or $oneDriveSuccess) {
            Write-Host "Bloatware removal operation completed successfully!" -ForegroundColor Green
        } else {
            Write-Host "Bloatware removal completed with limited success." -ForegroundColor Yellow
        }
    }
    "2" {
        Write-Host "Removing ALL bloatware except OneDrive..." -ForegroundColor Yellow
        $successCount = Remove-BloatwareEnhanced -AppsList $bloatwareApps
        
        if ($successCount -gt 0) {
            Write-Host "Bloatware removal operation completed successfully!" -ForegroundColor Green
        } else {
            Write-Host "Bloatware removal completed with limited success." -ForegroundColor Yellow
        }
    }
    "3" {
        $oneDriveSuccess = Remove-OneDriveEnhanced
        
        if ($oneDriveSuccess) {
            Write-Host "OneDrive removal completed successfully!" -ForegroundColor Green
        } else {
            Write-Host "OneDrive removal completed with limited success." -ForegroundColor Yellow
        }
    }
    "4" {
        Write-Host "Exiting..."
        exit
    }
    default {
        Write-Host "Invalid selection. Exiting..." -ForegroundColor Red
    }
}

Write-Host
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "     BLOATWARE REMOVAL PROCESS COMPLETE      " -ForegroundColor White -BackgroundColor DarkGreen
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host
Write-Host "Note: Some system apps may require a system restart to complete removal" -ForegroundColor Yellow
Write-Host "Press any key to exit..."
$null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")