#############################################################
# Windows Disk Cleanup PowerShell Script
# This script cleans various areas of a Windows system to free up disk space.
# Features:
# - Selective cleanup via parameters
# - Error handling with logging
# - Progress indication
# - Detailed documentation
# - Accurate space calculation
# - Colorful console output
#
# Cleanup Tasks:
# 1. Windows Update cache
# 2. Windows temporary files
# 3. Internet Explorer cache
# 4. Delivery Optimization Files
# 5. Windows Defender logs (older than 7 days)
# 6. Windows Error Reporting files
# 7. Thumbnails cache
# 8. Recycle Bin
# 9. User temporary files
# 10. Downloaded Program Files
# 11. Built-in Disk Cleanup utility (requires prior configuration)
#
# Note: For task 11, run 'cleanmgr /sageset:65535' first to configure cleanup options.
# Security logs, system files, and user data are preserved.
#############################################################

# Requires administrative privileges
#Requires -RunAsAdministrator

# Define parameters for selective cleanup
param (
    [switch]$CleanWindowsUpdate,
    [switch]$CleanTempFiles,
    [switch]$CleanIECache,
    [switch]$CleanDeliveryOptimization,
    [switch]$CleanDefenderLogs,
    [switch]$CleanWER,
    [switch]$CleanThumbnails,
    [switch]$EmptyRecycleBin,
    [switch]$CleanUserTemp,
    [switch]$CleanDownloadedProgramFiles,
    [switch]$RunCleanMgr,
    [switch]$All = $true
)

# Display explanation and countdown
Write-Host "This script will clean up temporary files, caches, and unnecessary data to free up disk space." -ForegroundColor Cyan
Write-Host "Starting in 5 seconds..." -ForegroundColor Yellow
for ($i = 5; $i -ge 1; $i--) {
    Write-Host "$i " -NoNewline -ForegroundColor Yellow
    Start-Sleep -Seconds 1
}
Write-Host "`nStarting cleanup now..." -ForegroundColor Green

# Set up logging
$LogFile = "$env:SystemDrive\DiskCleanupLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
function Write-Log {
    param([string]$Message)
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$TimeStamp - $Message" | Tee-Object -FilePath $LogFile -Append
}

# Function to format file sizes
function Format-FileSize {
    param ([long]$Size)
    if ($Size -ge 1TB) { return "{0:N2} TB" -f ($Size / 1TB) }
    elseif ($Size -ge 1GB) { return "{0:N2} GB" -f ($Size / 1GB) }
    elseif ($Size -ge 1MB) { return "{0:N2} MB" -f ($Size / 1MB) }
    elseif ($Size -ge 1KB) { return "{0:N2} KB" -f ($Size / 1KB) }
    else { return "$Size Bytes" }
}

# Get initial disk space
$InitialDrive = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'" | Select-Object FreeSpace, Size
$InitialFreeSpace = $InitialDrive.FreeSpace
Write-Log "==== Windows Disk Cleanup Script Started ===="
Write-Log "Initial free space on $env:SystemDrive: $(Format-FileSize $InitialFreeSpace) / $(Format-FileSize $InitialDrive.Size)"
Write-Host "================================" -ForegroundColor Cyan
Write-Host " Windows Disk Cleanup Started " -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host "Initial free space on $env:SystemDrive: $(Format-FileSize $InitialFreeSpace) / $(Format-FileSize $InitialDrive.Size)" -ForegroundColor Magenta

# Cleanup Functions
function Clean-WindowsUpdate {
    Write-Log "Cleaning Windows Update cache..."
    try {
        $BeforeSize = (Get-ChildItem "$env:SystemRoot\SoftwareDistribution\Download" -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $BeforeSize) { $BeforeSize = 0 }
        Stop-Service -Name wuauserv -Force -ErrorAction Stop
        Remove-Item "$env:SystemRoot\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction Stop
        Start-Service -Name wuauserv -ErrorAction Stop
        $AfterSize = (Get-ChildItem "$env:SystemRoot\SoftwareDistribution\Download" -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $AfterSize) { $AfterSize = 0 }
        $SpaceFreed = $BeforeSize - $AfterSize
        if ($SpaceFreed -gt 0) {
            Write-Log "Windows Update cleanup complete. Space freed: $(Format-FileSize $SpaceFreed)"
            Write-Host "Windows Update cleanup complete. Space freed: $(Format-FileSize $SpaceFreed)" -ForegroundColor Green
        } else {
            Write-Log "No space freed from Windows Update cleanup."
            Write-Host "No space freed from Windows Update cleanup." -ForegroundColor Yellow
        }
    } catch {
        Write-Log "Error during Windows Update cleanup: $_"
        Write-Host "Error during Windows Update cleanup: $_" -ForegroundColor Red
    }
}

function Clean-WindowsTemp {
    Write-Log "Cleaning Windows temporary files..."
    try {
        $BeforeSize = (Get-ChildItem "$env:SystemRoot\Temp" -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $BeforeSize) { $BeforeSize = 0 }
        Remove-Item "$env:SystemRoot\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
        $AfterSize = (Get-ChildItem "$env:SystemRoot\Temp" -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $AfterSize) { $AfterSize = 0 }
        $SpaceFreed = $BeforeSize - $AfterSize
        if ($SpaceFreed -gt 0) {
            Write-Log "Windows temporary files cleanup complete. Space freed: $(Format-FileSize $SpaceFreed)"
            Write-Host "Windows temporary files cleanup complete. Space freed: $(Format-FileSize $SpaceFreed)" -ForegroundColor Green
        } else {
            Write-Log "No space freed from Windows temporary files cleanup."
            Write-Host "No space freed from Windows temporary files cleanup." -ForegroundColor Yellow
        }
    } catch {
        Write-Log "Error during Windows temporary files cleanup: $_"
        Write-Host "Error during Windows temporary files cleanup: $_" -ForegroundColor Red
    }
}

function Clean-IECache {
    Write-Log "Cleaning Internet Explorer cache..."
    try {
        $BeforeSize = (Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Windows\INetCache" -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $BeforeSize) { $BeforeSize = 0 }
        Remove-Item "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\*" -Recurse -Force -ErrorAction SilentlyContinue
        $AfterSize = (Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Windows\INetCache" -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $AfterSize) { $AfterSize = 0 }
        $SpaceFreed = $BeforeSize - $AfterSize
        if ($SpaceFreed -gt 0) {
            Write-Log "Internet Explorer cache cleanup complete. Space freed: $(Format-FileSize $SpaceFreed)"
            Write-Host "Internet Explorer cache cleanup complete. Space freed: $(Format-FileSize $SpaceFreed)" -ForegroundColor Green
        } else {
            Write-Log "No space freed from Internet Explorer cache cleanup."
            Write-Host "No space freed from Internet Explorer cache cleanup." -ForegroundColor Yellow
        }
    } catch {
        Write-Log "Error during Internet Explorer cache cleanup: $_"
        Write-Host "Error during Internet Explorer cache cleanup: $_" -ForegroundColor Red
    }
}

function Clean-DeliveryOptimization {
    Write-Log "Cleaning Delivery Optimization Files..."
    try {
        $BeforeSize = (Get-ChildItem "$env:SystemRoot\SoftwareDistribution\DeliveryOptimization" -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $BeforeSize) { $BeforeSize = 0 }
        Stop-Service -Name DoSvc -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:SystemRoot\SoftwareDistribution\DeliveryOptimization\*" -Recurse -Force -ErrorAction SilentlyContinue
        Start-Service -Name DoSvc -ErrorAction SilentlyContinue
        $AfterSize = (Get-ChildItem "$env:SystemRoot\SoftwareDistribution\DeliveryOptimization" -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $AfterSize) { $AfterSize = 0 }
        $SpaceFreed = $BeforeSize - $AfterSize
        if ($SpaceFreed -gt 0) {
            Write-Log "Delivery Optimization Files cleanup complete. Space freed: $(Format-FileSize $SpaceFreed)"
            Write-Host "Delivery Optimization Files cleanup complete. Space freed: $(Format-FileSize $SpaceFreed)" -ForegroundColor Green
        } else {
            Write-Log "No space freed from Delivery Optimization Files cleanup."
            Write-Host "No space freed from Delivery Optimization Files cleanup." -ForegroundColor Yellow
        }
    } catch {
        Write-Log "Error during Delivery Optimization Files cleanup: $_"
        Write-Host "Error during Delivery Optimization Files cleanup: $_" -ForegroundColor Red
    }
}

function Clean-DefenderLogs {
    Write-Log "Cleaning Windows Defender old logs..."
    try {
        $DefenderFiles = Get-ChildItem "$env:ProgramData\Microsoft\Windows Defender\Scans\History" -Recurse -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) }
        if ($DefenderFiles) {
            $BeforeSize = ($DefenderFiles | Measure-Object -Property Length -Sum).Sum
            if ($null -eq $BeforeSize) { $BeforeSize = 0 }
            $DefenderFiles | Remove-Item -Force -ErrorAction SilentlyContinue
            $AfterSize = (Get-ChildItem "$env:ProgramData\Microsoft\Windows Defender\Scans\History" -Recurse -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) } | Measure-Object -Property Length -Sum).Sum
            if ($null -eq $AfterSize) { $AfterSize = 0 }
            $SpaceFreed = $BeforeSize - $AfterSize
            Write-Log "Windows Defender logs cleanup complete. Space freed: $(Format-FileSize $SpaceFreed)"
            Write-Host "Windows Defender logs cleanup complete. Space freed: $(Format-FileSize $SpaceFreed)" -ForegroundColor Green
        } else {
            Write-Log "No old Windows Defender logs found."
            Write-Host "No old Windows Defender logs found." -ForegroundColor Yellow
        }
    } catch {
        Write-Log "Error during Windows Defender logs cleanup: $_"
        Write-Host "Error during Windows Defender logs cleanup: $_" -ForegroundColor Red
    }
}

function Clean-WER {
    Write-Log "Cleaning Windows Error Reporting files..."
    try {
        $BeforeSize = (Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Windows\WER" -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $BeforeSize) { $BeforeSize = 0 }
        Remove-Item "$env:LOCALAPPDATA\Microsoft\Windows\WER\*" -Recurse -Force -ErrorAction SilentlyContinue
        $AfterSize = (Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Windows\WER" -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $AfterSize) { $AfterSize = 0 }
        $SpaceFreed = $BeforeSize - $AfterSize
        if ($SpaceFreed -gt 0) {
            Write-Log "Windows Error Reporting files cleanup complete. Space freed: $(Format-FileSize $SpaceFreed)"
            Write-Host "Windows Error Reporting files cleanup complete. Space freed: $(Format-FileSize $SpaceFreed)" -ForegroundColor Green
        } else {
            Write-Log "No space freed from Windows Error Reporting files cleanup."
            Write-Host "No space freed from Windows Error Reporting files cleanup." -ForegroundColor Yellow
        }
    } catch {
        Write-Log "Error during Windows Error Reporting files cleanup: $_"
        Write-Host "Error during Windows Error Reporting files cleanup: $_" -ForegroundColor Red
    }
}

function Clean-Thumbnails {
    Write-Log "Cleaning Thumbnails cache..."
    try {
        $BeforeSize = (Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db" -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $BeforeSize) { $BeforeSize = 0 }
        Remove-Item "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db" -Force -ErrorAction SilentlyContinue
        $AfterSize = (Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db" -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $AfterSize) { $AfterSize = 0 }
        $SpaceFreed = $BeforeSize - $AfterSize
        if ($SpaceFreed -gt 0) {
            Write-Log "Thumbnails cache cleanup complete. Space freed: $(Format-FileSize $SpaceFreed)"
            Write-Host "Thumbnails cache cleanup complete. Space freed: $(Format-FileSize $SpaceFreed)" -ForegroundColor Green
        } else {
            Write-Log "No space freed from Thumbnails cache cleanup."
            Write-Host "No space freed from Thumbnails cache cleanup." -ForegroundColor Yellow
        }
    } catch {
        Write-Log "Error during Thumbnails cache cleanup: $_"
        Write-Host "Error during Thumbnails cache cleanup: $_" -ForegroundColor Red
    }
}

function Empty-RecycleBin {
    Write-Log "Emptying Recycle Bin..."
    try {
        $Shell = New-Object -ComObject Shell.Application
        $RecycleBin = $Shell.Namespace(0xA)
        $RecycleBinSize = 0
        $RecycleBin.Items() | ForEach-Object { $RecycleBinSize += $_.Size }
        if ($RecycleBinSize -gt 0) {
            Clear-RecycleBin -Force -ErrorAction SilentlyContinue
            Write-Log "Recycle Bin emptied. Space freed: $(Format-FileSize $RecycleBinSize)"
            Write-Host "Recycle Bin emptied. Space freed: $(Format-FileSize $RecycleBinSize)" -ForegroundColor Green
        } else {
            Write-Log "Recycle Bin was already empty."
            Write-Host "Recycle Bin was already empty." -ForegroundColor Yellow
        }
    } catch {
        Write-Log "Error emptying Recycle Bin: $_"
        Write-Host "Error emptying Recycle Bin: $_" -ForegroundColor Red
    }
}

function Clean-UserTemp {
    Write-Log "Cleaning user temporary files..."
    try {
        $BeforeSize = (Get-ChildItem "$env:TEMP" -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $BeforeSize) { $BeforeSize = 0 }
        Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
        $AfterSize = (Get-ChildItem "$env:TEMP" -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $AfterSize) { $AfterSize = 0 }
        $SpaceFreed = $BeforeSize - $AfterSize
        if ($SpaceFreed -gt 0) {
            Write-Log "User temporary files cleanup complete. Space freed: $(Format-FileSize $SpaceFreed)"
            Write-Host "User temporary files cleanup complete. Space freed: $(Format-FileSize $SpaceFreed)" -ForegroundColor Green
        } else {
            Write-Log "No space freed from user temporary files cleanup."
            Write-Host "No space freed from user temporary files cleanup." -ForegroundColor Yellow
        }
    } catch {
        Write-Log "Error during user temporary files cleanup: $_"
        Write-Host "Error during user temporary files cleanup: $_" -ForegroundColor Red
    }
}

function Clean-DownloadedProgramFiles {
    Write-Log "Cleaning Downloaded Program Files..."
    try {
        $BeforeSize = (Get-ChildItem "$env:WINDIR\Downloaded Program Files" -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $BeforeSize) { $BeforeSize = 0 }
        Remove-Item "$env:WINDIR\Downloaded Program Files\*" -Recurse -Force -ErrorAction SilentlyContinue
        $AfterSize = (Get-ChildItem "$env:WINDIR\Downloaded Program Files" -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $AfterSize) { $AfterSize = 0 }
        $SpaceFreed = $BeforeSize - $AfterSize
        if ($SpaceFreed -gt 0) {
            Write-Log "Downloaded Program Files cleanup complete. Space freed: $(Format-FileSize $SpaceFreed)"
            Write-Host "Downloaded Program Files cleanup complete. Space freed: $(Format-FileSize $SpaceFreed)" -ForegroundColor Green
        } else {
            Write-Log "No space freed from Downloaded Program Files cleanup."
            Write-Host "No space freed from Downloaded Program Files cleanup." -ForegroundColor Yellow
        }
    } catch {
        Write-Log "Error during Downloaded Program Files cleanup: $_"
        Write-Host "Error during Downloaded Program Files cleanup: $_" -ForegroundColor Red
    }
}

function Run-CleanMgr {
    Write-Log "Running built-in disk cleanup utility..."
    try {
        $sageset = 65535
        Start-Process -FilePath cleanmgr.exe -ArgumentList "/sagerun:$sageset" -Wait -NoNewWindow
        Write-Log "Built-in disk cleanup utility complete."
        Write-Host "Built-in disk cleanup utility complete." -ForegroundColor Green
    } catch {
        Write-Log "Error running cleanmgr.exe: $_"
        Write-Host "Error running cleanmgr.exe: $_" -ForegroundColor Red
    }
}

# Execute cleanup tasks with progress indication
$taskNumber = 0
if ($All -or $CleanWindowsUpdate) {
    Write-Progress -Activity "Disk Cleanup" -Status "Cleaning Windows Update cache..." -PercentComplete ($taskNumber / 11 * 100)
    Clean-WindowsUpdate
    $taskNumber++
}
if ($All -or $CleanTempFiles) {
    Write-Progress -Activity "Disk Cleanup" -Status "Cleaning Windows temporary files..." -PercentComplete ($taskNumber / 11 * 100)
    Clean-WindowsTemp
    $taskNumber++
}
if ($All -or $CleanIECache) {
    Write-Progress -Activity "Disk Cleanup" -Status "Cleaning Internet Explorer cache..." -PercentComplete ($taskNumber / 11 * 100)
    Clean-IECache
    $taskNumber++
}
if ($All -or $CleanDeliveryOptimization) {
    Write-Progress -Activity "Disk Cleanup" -Status "Cleaning Delivery Optimization Files..." -PercentComplete ($taskNumber / 11 * 100)
    Clean-DeliveryOptimization
    $taskNumber++
}
if ($All -or $CleanDefenderLogs) {
    Write-Progress -Activity "Disk Cleanup" -Status "Cleaning Windows Defender logs..." -PercentComplete ($taskNumber / 11 * 100)
    Clean-DefenderLogs
    $taskNumber++
}
if ($All -or $CleanWER) {
    Write-Progress -Activity "Disk Cleanup" -Status "Cleaning Windows Error Reporting files..." -PercentComplete ($taskNumber / 11 * 100)
    Clean-WER
    $taskNumber++
}
if ($All -or $CleanThumbnails) {
    Write-Progress -Activity "Disk Cleanup" -Status "Cleaning Thumbnails cache..." -PercentComplete ($taskNumber / 11 * 100)
    Clean-Thumbnails
    $taskNumber++
}
if ($All -or $EmptyRecycleBin) {
    Write-Progress -Activity "Disk Cleanup" -Status "Emptying Recycle Bin..." -PercentComplete ($taskNumber / 11 * 100)
    Empty-RecycleBin
    $taskNumber++
}
if ($All -or $CleanUserTemp) {
    Write-Progress -Activity "Disk Cleanup" -Status "Cleaning user temporary files..." -PercentComplete ($taskNumber / 11 * 100)
    Clean-UserTemp
    $taskNumber++
}
if ($All -or $CleanDownloadedProgramFiles) {
    Write-Progress -Activity "Disk Cleanup" -Status "Cleaning Downloaded Program Files..." -PercentComplete ($taskNumber / 11 * 100)
    Clean-DownloadedProgramFiles
    $taskNumber++
}
if ($All -or $RunCleanMgr) {
    Write-Progress -Activity "Disk Cleanup" -Status "Running built-in disk cleanup utility..." -PercentComplete ($taskNumber / 11 * 100)
    Run-CleanMgr
    $taskNumber++
}

# Finalize progress and display results
Write-Progress -Activity "Disk Cleanup" -Completed
$FinalDrive = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'" | Select-Object FreeSpace
$FinalFreeSpace = $FinalDrive.FreeSpace
$TotalSpaceFreed = $FinalFreeSpace - $InitialFreeSpace
Write-Log "==== Windows Disk Cleanup Script Completed ===="
Write-Log "Final free space on $env:SystemDrive: $(Format-FileSize $FinalFreeSpace) / $(Format-FileSize $InitialDrive.Size)"
Write-Log "Total space freed: $(Format-FileSize $TotalSpaceFreed)"
Write-Host "================================" -ForegroundColor Green
Write-Host " Disk Cleanup Completed " -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green
Write-Host "Final free space on $env:SystemDrive: $(Format-FileSize $FinalFreeSpace) / $(Format-FileSize $InitialDrive.Size)" -ForegroundColor Magenta
Write-Host "Total space freed: $(Format-FileSize $TotalSpaceFreed)" -ForegroundColor Yellow
Write-Host "Log saved to: $LogFile" -ForegroundColor Cyan
