# Full-screen hacker-style visual effect script with dramatic access messages
while ($true) {
    # Get window width to maximize line usage
    $windowWidth = $Host.UI.RawUI.WindowSize.Width

    # Rarely clear screen for continuity
    if ((Get-Random -Maximum 50) -eq 42) {
        Clear-Host
        Write-Host "SYSTEM REBOOT DETECTED" -ForegroundColor Red
        Start-Sleep -Milliseconds 500
    }

    # Randomly trigger ACCESS ACCEPTED or ACCESS DENIED (1 in 20 chance)
    if ((Get-Random -Maximum 20) -eq 10) {
        Clear-Host
        $accessChoice = Get-Random -Maximum 2
        if ($accessChoice -eq 0) {
            # ACCESS ACCEPTED in "big font" (Green)
            Write-Host " " * [Math]::Floor(($windowWidth - 16) / 2) -NoNewline
            Write-Host "A C C E S S   A C C E P T E D" -ForegroundColor Green
            Write-Host " " * [Math]::Floor(($windowWidth - 16) / 2) -NoNewline
            Write-Host "==============================" -ForegroundColor Green
            Write-Host " " * [Math]::Floor(($windowWidth - 16) / 2) -NoNewline
            Write-Host "||  ACCESS GRANTED 0xFF  ||" -ForegroundColor Green
            Write-Host " " * [Math]::Floor(($windowWidth - 16) / 2) -NoNewline
            Write-Host "==============================" -ForegroundColor Green
        } else {
            # ACCESS DENIED in "big font" (Red)
            Write-Host " " * [Math]::Floor(($windowWidth - 16) / 2) -NoNewline
            Write-Host "A C C E S S   D E N I E D" -ForegroundColor Red
            Write-Host " " * [Math]::Floor(($windowWidth - 16) / 2) -NoNewline
            Write-Host "==========================" -ForegroundColor Red
            Write-Host " " * [Math]::Floor(($windowWidth - 16) / 2) -NoNewline
            Write-Host "||  ERROR CODE 0xA9  ||" -ForegroundColor Red
            Write-Host " " * [Math]::Floor(($windowWidth - 16) / 2) -NoNewline
            Write-Host "==========================" -ForegroundColor Red
        }
        Start-Sleep -Seconds 2  # Pause to let the message sink in
    }

    # Array of hacker-like messages
    $messages = @(
        "Initializing Quantum Encryption Protocol...",
        "Scanning Network Ports Across 256 Subnets...",
        "Decrypting AES-256 Security Layer...",
        "Bypassing Firewall Perimeter [SUCCESS]...",
        "Accessing Mainframe Core [0xFF12A9B3]...",
        "Uploading Polymorphic Payload 0xA9FF...",
        "Executing Remote Code Injection Sequence...",
        "Downloading Terabyte Data Stream...",
        "Crunching 4096-bit Encryption Keys...",
        "Establishing Secure VPN Tunnel Matrix..."
    )

    # Random color selection for regular text
    $colorChoice = Get-Random -Maximum 5
    switch ($colorChoice) {
        0 { $color = "Green" }    # Bright Green
        1 { $color = "Red" }      # Bright Red
        2 { $color = "Cyan" }     # Hacker Cyan
        3 { $color = "Magenta" }  # Neon Magenta
        4 { $color = "Yellow" }   # Warning Yellow
    }

    # Generate random "data" to fill the line
    $randomData = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 20 | % {[char]$_})
    $randomNum = Get-Random -Minimum 10000 -Maximum 99999
    $message = Get-Random -InputObject $messages

    # Create a full-width line
    $baseOutput = "[$randomNum] $message $randomData"
    $padding = " " * [Math]::Max(0, ($windowWidth - $baseOutput.Length - 10))
    $filler = -join ((33..126) | Get-Random -Count 10 | % {[char]$_})  # Random printable chars
    $fullLine = "$baseOutput$padding$filler"

    # Display the regular output
    Write-Host $fullLine -ForegroundColor $color

    # Slower random sleep for better readability and flow
    Start-Sleep -Milliseconds (Get-Random -Minimum 100 -Maximum 400)
}