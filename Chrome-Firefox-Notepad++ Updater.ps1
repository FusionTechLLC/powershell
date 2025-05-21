# Update-Software.ps1
# Hey there! This PowerShell script is your friendly helper for keeping Notepad++, Google Chrome, and Firefox up to date on your Windows PC. Here's the deal:
# It checks the versions of these three programs you have installed by peeking into the Windows registry (don't worry, it’s just reading some version numbers).
# For Notepad++ and Firefox, it goes online to trusted sources—GitHub for Notepad++ and Mozilla for Firefox—to see if there’s a newer version available.
# If a newer version exists, it grabs the 64-bit installer and drops it right on your desktop for you to run whenever you're ready.
# For Chrome, things are a bit trickier since Google retired the API we used to check versions. So, if Chrome is installed, the script plays it safe and downloads the latest installer anyway, while suggesting you check for updates manually at google.com/chrome.
# You’ll need to run this script as an Administrator because it needs special access to the registry and to save files.
# If something goes wrong (like a network hiccup), the script won’t crash—it’ll just let you know what happened and keep going.
# The downloaded installers won’t install themselves; you’ll need to double-click them to update your software. Think of this script as your personal assistant who fetches the updates but leaves the final step to you.
# Files land on your desktop with names like npp.8.8.1.Installer.x64.exe (Notepad++), ChromeStandaloneSetup64.exe (Chrome), or FirefoxSetup.exe (Firefox). Easy peasy!

# Ensure TLS 1.2 is used for web requests
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Define desktop path
$desktopPath = [Environment]::GetFolderPath("Desktop")
$ErrorActionPreference = "Stop"

# Function to check if PowerShell is running as Administrator
function Test-IsElevated {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to get installed software version from registry
function Get-InstalledVersion {
    param (
        [string]$softwareName
    )
    $registryPaths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $software = Get-ItemProperty $registryPaths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*$softwareName*" }
    if ($software) {
        return [version]$software.DisplayVersion
    }
    return $null
}

# Function to download file to desktop
function Download-File {
    param (
        [string]$url,
        [string]$outputPath
    )
    try {
        Write-Host "Downloading from $url to $outputPath..."
        Invoke-WebRequest -Uri $url -OutFile $outputPath -UseBasicParsing
        Write-Host "Download completed."
    } catch {
        Write-Warning "Failed to download from $url. Error: $($_.Exception.Message)"
    }
}

# Check if running as Administrator
if (-not (Test-IsElevated)) {
    Write-Warning "This script requires elevated privileges to access registry and install updates. Please run PowerShell as Administrator."
    exit
}

# Check Notepad++
Write-Host "Checking Notepad++..."
$nppInstalled = Get-InstalledVersion -softwareName "Notepad++"
if ($nppInstalled) {
    Write-Host "Installed Notepad++ version: $nppInstalled"
    try {
        $nppJson = Invoke-WebRequest -Uri 'https://api.github.com/repos/notepad-plus-plus/notepad-plus-plus/releases/latest' -UseBasicParsing | ConvertFrom-Json
        $nppLatestVersion = [version]($nppJson.tag_name -replace '^v', '')
        $nppDownloadUrl = ($nppJson.assets | Where-Object { $_.name -like '*Installer.x64.exe' -and $_.name -notlike '*.sig' }).browser_download_url
        Write-Host "Latest Notepad++ version: $nppLatestVersion"
        if ($nppLatestVersion -gt $nppInstalled) {
            $nppOutputPath = Join-Path $desktopPath ($nppJson.assets | Where-Object { $_.name -like '*Installer.x64.exe' -and $_.name -notlike '*.sig' }).name
            Download-File -url $nppDownloadUrl -outputPath $nppOutputPath
        } else {
            Write-Host "Notepad++ is up to date."
        }
    } catch {
        Write-Warning "Failed to check Notepad++ online version. Error: $($_.Exception.Message)"
    }
} else {
    Write-Host "Notepad++ is not installed."
}

# Check Google Chrome
Write-Host "`nChecking Google Chrome..."
$chromeInstalled = Get-InstalledVersion -softwareName "Google Chrome"
if ($chromeInstalled) {
    Write-Host "Installed Chrome version: $chromeInstalled"
    Write-Warning "Automatic Chrome version checking is currently unavailable due to the retirement of the OmahaProxy API."
    Write-Host "To check for updates manually, visit https://www.google.com/chrome/ or download the latest installer."
    Write-Host "Downloading the latest Chrome installer as a precaution..."
    $chromeDownloadUrl = "https://dl.google.com/chrome/install/ChromeStandaloneSetup64.exe"
    $chromeOutputPath = Join-Path $desktopPath "ChromeStandaloneSetup64.exe"
    Download-File -url $chromeDownloadUrl -outputPath $chromeOutputPath
} else {
    Write-Host "Google Chrome is not installed."
}

# Check Firefox
Write-Host "`nChecking Firefox..."
$firefoxInstalled = Get-InstalledVersion -softwareName "Mozilla Firefox"
if ($firefoxInstalled) {
    Write-Host "Installed Firefox version: $firefoxInstalled"
    try {
        $firefoxJson = Invoke-WebRequest -Uri 'https://product-details.mozilla.org/1.0/firefox_versions.json' -UseBasicParsing | ConvertFrom-Json
        $firefoxLatestVersion = [version]$firefoxJson.LATEST_FIREFOX_VERSION
        Write-Host "Latest Firefox version: $firefoxLatestVersion"
        if ($firefoxLatestVersion -gt $firefoxInstalled) {
            $firefoxDownloadUrl = "https://download.mozilla.org/?product=firefox-latest&os=win64&lang=en-US"
            $firefoxOutputPath = Join-Path $desktopPath "FirefoxSetup.exe"
            Download-File -url $firefoxDownloadUrl -outputPath $firefoxOutputPath
        } else {
            Write-Host "Firefox is up to date."
        }
    } catch {
        Write-Warning "Failed to check Firefox online version. Error: $($_.Exception.Message)"
    }
} else {
    Write-Host "Firefox is not installed."
}

Write-Host "`nScript execution completed."