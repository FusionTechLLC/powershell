# Windows 11 Bloatware Removal Script with Fixed Edge Removal
# This script handles execution policy and admin elevation

# Store the original execution policy to restore it later
$originalExecutionPolicy = Get-ExecutionPolicy

# Self-elevate the script if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Write-Host "This script requires administrator privileges. Attempting to elevate..." -ForegroundColor Yellow
    $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`""
    Start-Process -FilePath PowerShell.exe -Verb RunAs -ArgumentList $CommandLine
    Exit
}

# Set execution policy to Bypass for this process
try {
    Write-Host "Setting execution policy to Bypass for this process..." -ForegroundColor Yellow
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
    Write-Host "Execution policy set to Bypass." -ForegroundColor Green
} catch {
    Write-Host "Failed to set execution policy: $_" -ForegroundColor Red
    Write-Host "Attempting to continue anyway..." -ForegroundColor Yellow
}

# Define bloatware apps array with friendly names and app package names
$bloatwareApps = @(
    @{Name = "Xbox Apps"; PackageName = "Microsoft.XboxApp|Microsoft.XboxGamingOverlay|Microsoft.XboxIdentityProvider|Microsoft.XboxSpeechToTextOverlay|Microsoft.Xbox.TCUI|Microsoft.GamingApp"},
    @{Name = "Xbox Live"; PackageName = "Microsoft.XboxLive|Microsoft.GamingServices"},
    @{Name = "Microsoft Teams"; PackageName = "MicrosoftTeams|Teams"},
    @{Name = "Skype"; PackageName = "Microsoft.SkypeApp"},
    @{Name = "Cortana"; PackageName = "Microsoft.549981C3F5F10"},
    @{Name = "Mixed Reality Portal"; PackageName = "Microsoft.MixedReality.Portal"},
    @{Name = "Mail and Calendar"; PackageName = "microsoft.windowscommunicationsapps"},
    @{Name = "Weather"; PackageName = "Microsoft.BingWeather"},
    @{Name = "Microsoft News"; PackageName = "Microsoft.BingNews"},
    @{Name = "Get Help"; PackageName = "Microsoft.GetHelp"},
    @{Name = "Feedback Hub"; PackageName = "Microsoft.WindowsFeedbackHub"},
    @{Name = "Paint 3D"; PackageName = "Microsoft.MSPaint"},
    @{Name = "3D Viewer"; PackageName = "Microsoft.Microsoft3DViewer"},
    @{Name = "Groove Music"; PackageName = "Microsoft.ZuneMusic"},
    @{Name = "Movies & TV"; PackageName = "Microsoft.ZuneVideo"},
    @{Name = "Microsoft Solitaire Collection"; PackageName = "Microsoft.MicrosoftSolitaireCollection"},
    @{Name = "Candy Crush"; PackageName = "king.com.CandyCrush"},
    @{Name = "OneNote"; PackageName = "Microsoft.Office.OneNote"},
    @{Name = "Office Hub"; PackageName = "Microsoft.MicrosoftOfficeHub"},
    @{Name = "Office Products"; PackageName = "Microsoft.Office|Microsoft.Office365|Microsoft.MicrosoftOffice|Microsoft.MicrosoftWord|Microsoft.MicrosoftExcel|Microsoft.MicrosoftPowerPoint|Microsoft.MicrosoftOutlook|Microsoft.MicrosoftPublisher|Microsoft.MicrosoftAccess"},
    @{Name = "Sticky Notes"; PackageName = "Microsoft.MicrosoftStickyNotes"},
    @{Name = "Microsoft To Do"; PackageName = "Microsoft.Todos"},
    @{Name = "Tips"; PackageName = "Microsoft.Getstarted"},
    @{Name = "Your Phone"; PackageName = "Microsoft.YourPhone"},
    @{Name = "People"; PackageName = "Microsoft.People"},
    @{Name = "Maps"; PackageName = "Microsoft.WindowsMaps"},
    @{Name = "Photos"; PackageName = "Microsoft.Windows.Photos"},
    @{Name = "Power Automate"; PackageName = "Microsoft.PowerAutomateDesktop"},
    @{Name = "Quick Assist"; PackageName = "MicrosoftCorporationII.QuickAssist|Microsoft.RemoteAssistance"},
    @{Name = "Camera"; PackageName = "Microsoft.WindowsCamera"},
    @{Name = "Copilot"; PackageName = "Microsoft.Windows.Copilot|MicrosoftWindows.Client.CBS|Microsoft.Windows.Copilot_8wekyb3d8bbwe|Copilot"},
    @{Name = "Microsoft Bing"; PackageName = "Microsoft.Bing|Microsoft.BingSearch|Microsoft.BingTranslator"},
    @{Name = "Microsoft Clipchamp"; PackageName = "Clipchamp.Clipchamp"},
    @{Name = "OneDrive"; PackageName = "Microsoft.OneDrive|Microsoft.OneDriveSync"},
    @{Name = "Sound Recorder"; PackageName = "Microsoft.WindowsSoundRecorder"},
    @{Name = "Microsoft Store"; PackageName = "Microsoft.WindowsStore|Microsoft.StorePurchaseApp"},
    @{Name = "Microsoft Edge"; PackageName = "Microsoft.MicrosoftEdge"}
)

# Function to remove Microsoft Edge safely
function Remove-MicrosoftEdgeSafely {
    Write-Host "Removing Microsoft Edge..." -ForegroundColor Yellow
    $success = $false
    
    # Stop Edge processes with better error handling
    Write-Host "  Stopping Edge processes..." -ForegroundColor Yellow
    try {
        # Try to get Edge processes
        $edgeProcesses = Get-Process -Name *edge* -ErrorAction SilentlyContinue
        if ($edgeProcesses) {
            foreach ($proc in $edgeProcesses) {
                try {
                    $proc | Stop-Process -Force -ErrorAction SilentlyContinue
                    Write-Host "  Stopped process: $($proc.Name) (PID: $($proc.Id))" -ForegroundColor Green
                } catch {
                    Write-Host "  Could not stop process: $($proc.Name) (PID: $($proc.Id)) - $_" -ForegroundColor Red
                }
            }
        } else {
            Write-Host "  No Edge processes found running" -ForegroundColor Gray
        }
    } catch {
        Write-Host "  Warning when stopping Edge processes - $_" -ForegroundColor Yellow
    }
    
    # Allow time for processes to stop
    Start-Sleep -Seconds 2
    
    # Use direct file system deletion to remove Edge
    Write-Host "  Attempting to remove Edge installation folders..." -ForegroundColor Yellow
    
    # Define Edge folders to check and try to remove
    $edgeFolders = @(
        "$env:PROGRAMFILES\Microsoft\Edge",
        "$env:PROGRAMFILES (x86)\Microsoft\Edge",
        "$env:LOCALAPPDATA\Microsoft\Edge"
    )
    
    foreach ($folder in $edgeFolders) {
        if (Test-Path $folder) {
            Write-Host "  Found Edge folder: $folder" -ForegroundColor Green
            try {
                # Try to remove the folder
                Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
                
                # Check if folder was removed
                if (!(Test-Path $folder)) {
                    Write-Host "  Successfully removed folder: $folder" -ForegroundColor Green
                    $success = $true
                } else {
                    Write-Host "  Could not remove folder: $folder" -ForegroundColor Red
                    
                    # Alternative: try using cmd.exe with rd command
                    try {
                        Start-Process "cmd.exe" -ArgumentList "/c", "rd", "/s", "/q", "`"$folder`"" -Wait -NoNewWindow
                        if (!(Test-Path $folder)) {
                            Write-Host "  Successfully removed folder with RD command: $folder" -ForegroundColor Green
                            $success = $true
                        }
                    } catch {
                        Write-Host "  Failed to remove folder with alternate method: $folder" -ForegroundColor Red
                    }
                }
            } catch {
                Write-Host "  Error removing folder: $folder - $_" -ForegroundColor Red
            }
        }
    }
    
    # Try to modify registry to prevent Edge reinstallation
    Write-Host "  Setting registry keys to prevent Edge reinstallation..." -ForegroundColor Yellow
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate"
        
        # Create the path if it doesn't exist
        if (!(Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        
        # Set values to prevent Edge updates/reinstallation
        New-ItemProperty -Path $regPath -Name "DoNotUpdateToEdgeWithChromium" -Value 1 -PropertyType DWORD -Force | Out-Null
        Write-Host "  Registry keys set to prevent Edge reinstallation" -ForegroundColor Green
    } catch {
        Write-Host "  Failed to set registry keys - $_" -ForegroundColor Red
    }
    
    # Remind user about Edge being a system component
    Write-Host
    Write-Host "NOTE: Microsoft Edge is deeply integrated into Windows 11 and may not be completely removable." -ForegroundColor Yellow
    Write-Host "Some components might persist or be reinstalled during Windows updates." -ForegroundColor Yellow
    Write-Host "The script has attempted to remove Edge as thoroughly as possible." -ForegroundColor Yellow
    
    return $success
}

# Function to display menu for app selection
function Show-AppSelectionMenu {
    Clear-Host
    Write-Host "=== Windows 11 Bloatware Removal Tool ===" -ForegroundColor Cyan
    Write-Host "Select the apps you want to uninstall:" -ForegroundColor Yellow
    Write-Host "0. All Apps" -ForegroundColor Red
    
    for ($i = 0; $i -lt $bloatwareApps.Count; $i++) {
        Write-Host "$($i+1). $($bloatwareApps[$i].Name)" -ForegroundColor Green
    }
    
    Write-Host "A. About this script" -ForegroundColor Magenta
    Write-Host "Q. Quit" -ForegroundColor Magenta
    Write-Host
}

# Function to uninstall selected app
function Uninstall-SelectedApp {
    param (
        [Parameter(Mandatory=$true)]
        [int]$Index
    )
    
    $selectedApp = $bloatwareApps[$Index]
    Write-Host "Uninstalling $($selectedApp.Name)..." -ForegroundColor Yellow
    
    # Special handling for Microsoft Edge
    if ($selectedApp.Name -eq "Microsoft Edge") {
        $edgeSuccess = Remove-MicrosoftEdgeSafely
        if ($edgeSuccess) {
            Write-Host "Successfully removed Microsoft Edge" -ForegroundColor Green
        } else {
            Write-Host "Edge removal attempted with limited success" -ForegroundColor Yellow
        }
        return
    }
    
    # Special handling for Copilot
    if ($selectedApp.Name -eq "Copilot") {
        Write-Host "Detected Copilot removal request - using enhanced removal..." -ForegroundColor Yellow
        try {
            # Try normal package removal first
            Get-AppxPackage -Name *Copilot* -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    Remove-AppxPackage -Package $_.PackageFullName -ErrorAction SilentlyContinue
                    Write-Host "Removed Copilot package: $($_.Name)" -ForegroundColor Green
                } catch {
                    Write-Host "Failed to remove Copilot package: $($_.Name)" -ForegroundColor Red
                }
            }
            
            # Try provisioned package removal
            Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -like "*Copilot*"} | ForEach-Object {
                try {
                    Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction SilentlyContinue
                    Write-Host "Removed Copilot provisioned package: $($_.DisplayName)" -ForegroundColor Green
                } catch {
                    Write-Host "Failed to remove Copilot provisioned package: $($_.DisplayName)" -ForegroundColor Red
                }
            }
            
            # Registry-based disabling
            Write-Host "Attempting registry-based Copilot disabling..." -ForegroundColor Yellow
            $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows"
            if (!(Test-Path "$registryPath\WindowsCopilot")) {
                New-Item -Path "$registryPath\WindowsCopilot" -Force | Out-Null
            }
            New-ItemProperty -Path "$registryPath\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1 -PropertyType DWORD -Force | Out-Null
            Write-Host "Registry-based Copilot disabling complete." -ForegroundColor Green
        } catch {
            Write-Host "Error during Copilot removal: $_" -ForegroundColor Red
        }
        return
    }
    
    # Standard app removal for other apps
    # Split package names on pipe symbol to handle multiple packages per app
    $packageNames = $selectedApp.PackageName -split '\|'
    
    foreach ($packageName in $packageNames) {
        try {
            # Try to get packages matching this name pattern
            $packages = Get-AppxPackage -Name "*$packageName*" -ErrorAction SilentlyContinue
            
            # Handle case where no packages are found
            if ($packages -eq $null -or $packages.Count -eq 0) {
                Write-Host "No packages found matching: $packageName" -ForegroundColor Gray
                continue
            }
            
            # Remove each package found
            foreach ($package in $packages) {
                try {
                    Remove-AppxPackage -Package $package.PackageFullName -ErrorAction SilentlyContinue
                    Write-Host "Successfully uninstalled: $($package.Name)" -ForegroundColor Green
                } catch {
                    Write-Host "Failed to uninstall: $($package.Name) - $_" -ForegroundColor Red
                }
            }
            
            # Try to remove provisioned packages
            $provPackages = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | 
                            Where-Object { $_.DisplayName -like "*$packageName*" }
            
            foreach ($provPackage in $provPackages) {
                try {
                    Remove-AppxProvisionedPackage -Online -PackageName $provPackage.PackageName -ErrorAction SilentlyContinue
                    Write-Host "Successfully removed provisioned package: $($provPackage.DisplayName)" -ForegroundColor Green
                } catch {
                    Write-Host "Failed to remove provisioned package: $($provPackage.DisplayName) - $_" -ForegroundColor Red
                }
            }
        } catch {
            Write-Host "Error processing $packageName : $_" -ForegroundColor Red
        }
    }
    
    # Special handling for OneDrive
    if ($selectedApp.Name -eq "OneDrive") {
        Write-Host "Detected OneDrive removal request - using enhanced removal..." -ForegroundColor Yellow
        try {
            # Kill OneDrive process if running
            Get-Process -Name OneDrive -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            Write-Host "Stopped OneDrive process" -ForegroundColor Green
            
            # Uninstall OneDrive using the built-in uninstaller
            $oneDriveSetupFound = $false
            if (Test-Path "$env:SystemRoot\SysWOW64\OneDriveSetup.exe") {
                Start-Process "$env:SystemRoot\SysWOW64\OneDriveSetup.exe" -ArgumentList "/uninstall" -Wait
                $oneDriveSetupFound = $true
                Write-Host "Ran OneDrive uninstaller (64-bit)" -ForegroundColor Green
            } elseif (Test-Path "$env:SystemRoot\System32\OneDriveSetup.exe") {
                Start-Process "$env:SystemRoot\System32\OneDriveSetup.exe" -ArgumentList "/uninstall" -Wait
                $oneDriveSetupFound = $true
                Write-Host "Ran OneDrive uninstaller (32-bit)" -ForegroundColor Green
            }
            
            if (-not $oneDriveSetupFound) {
                Write-Host "OneDrive setup executable not found" -ForegroundColor Red
            }
            
            # Remove OneDrive folders
            $oneDriveFolders = @(
                "$env:USERPROFILE\OneDrive",
                "$env:LOCALAPPDATA\Microsoft\OneDrive",
                "$env:PROGRAMDATA\Microsoft OneDrive"
            )
            
            foreach ($folder in $oneDriveFolders) {
                if (Test-Path $folder) {
                    try {
                        Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
                        if (!(Test-Path $folder)) {
                            Write-Host "Removed folder: $folder" -ForegroundColor Green
                        } else {
                            Write-Host "Could not completely remove folder: $folder" -ForegroundColor Yellow
                        }
                    } catch {
                        Write-Host "Error removing OneDrive folder: $folder - $_" -ForegroundColor Red
                    }
                }
            }
        } catch {
            Write-Host "Error during OneDrive removal: $_" -ForegroundColor Red
        }
    }
    
    Write-Host "Completed uninstallation of $($selectedApp.Name)" -ForegroundColor Cyan
    Write-Host
}

# Function to uninstall all listed apps
function Uninstall-AllApps {
    Write-Host "Uninstalling all bloatware apps..." -ForegroundColor Red
    for ($i = 0; $i -lt $bloatwareApps.Count; $i++) {
        Uninstall-SelectedApp -Index $i
    }
    Write-Host "Completed uninstallation of all selected bloatware apps" -ForegroundColor Cyan
    Write-Host
}

# Function to display information about the script
function Show-About {
    Clear-Host
    Write-Host "=== About This Script ===" -ForegroundColor Cyan
    Write-Host "This script helps you remove unwanted pre-installed applications from Windows 11." -ForegroundColor White
    Write-Host
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "- Select individual apps to uninstall by entering their number"
    Write-Host "- Select '0' to uninstall all listed bloatware apps"
    Write-Host "- Apps are removed for the current user and from new user profiles"
    Write-Host
    Write-Host "Special Handling:" -ForegroundColor Yellow
    Write-Host "- Copilot: Uses enhanced removal methods including registry modifications"
    Write-Host "- OneDrive: Uses the official uninstaller to properly remove the application"
    Write-Host "- Microsoft Edge: Uses specialized methods for more thorough removal"
    Write-Host "- Microsoft Store: Removing the Store will prevent installing/updating Microsoft Store apps"
    Write-Host
    Write-Host "Warning:" -ForegroundColor Red
    Write-Host "- Some apps may be reinstalled during Windows updates"
    Write-Host "- Some apps may be dependencies for other Windows features"
    Write-Host "- Microsoft Store apps can be reinstalled from the Store if needed"
    Write-Host "- Microsoft Edge is a system component and may not be completely removable"
    Write-Host
    Write-Host "Press any key to return to the main menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Main script execution
try {
    # Main loop
    $running = $true
    while ($running) {
        Show-AppSelectionMenu
        $choice = Read-Host "Enter your choice"
        
        switch ($choice) {
            "0" {
                Uninstall-AllApps
                Write-Host "Press any key to continue..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            "q" {
                $running = $false
            }
            "a" {
                Show-About
            }
            default {
                try {
                    $index = [int]$choice - 1
                    if ($index -ge 0 -and $index -lt $bloatwareApps.Count) {
                        Uninstall-SelectedApp -Index $index
                        Write-Host "Press any key to continue..."
                        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                    } else {
                        Write-Host "Invalid choice. Press any key to continue..."
                        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                    }
                } catch {
                    Write-Host "Invalid input. Press any key to continue..."
                    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                }
            }
        }
    }
}
catch {
    # Log any unexpected errors
    Write-Host "An error occurred: $_" -ForegroundColor Red
    Write-Host "Script execution will continue..." -ForegroundColor Yellow
}
finally {
    # Restore the original execution policy
    try {
        Write-Host "Restoring original execution policy ($originalExecutionPolicy)..." -ForegroundColor Yellow
        Set-ExecutionPolicy -ExecutionPolicy $originalExecutionPolicy -Scope Process -Force
        Write-Host "Execution policy restored." -ForegroundColor Green
    } catch {
        Write-Host "Failed to restore execution policy: $_" -ForegroundColor Red
    }
    
    Write-Host "Thank you for using the Windows 11 Bloatware Removal Tool!" -ForegroundColor Cyan
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}