<#
.SYNOPSIS
    VaultScope - Simple BitLocker / Encryption Status Scanner

.DESCRIPTION
    Reads a list of computers and uses PsExec to remotely
    determine BitLocker / disk encryption status.

    NO CHANGES ARE MADE TO THE REMOTE MACHINE.
    This is report-only, by design.

.REQUIREMENTS
    - Sysinternals PsExec
    - Domain credentials with local admin on targets
    - File/Printer Sharing + Admin$ enabled
#>

# -----------------------------
# CONFIGURATION
# -----------------------------

# Path to PsExec
$PsExecPath = "C:\SAFE\PSTools\PsExec.exe"

# Optional: file containing targets (one per line)
$TargetListFile = "C:\SAFE\VaultScope\targets.txt"

# Or define targets manually here
#$Targets = @("PC-001","PC-002","T-SWSCAN-1")

# Timeout for PsExec (seconds)
$Timeout = 60

# -----------------------------
# GATHER TARGETS
# -----------------------------

if (Test-Path $TargetListFile) {
    $Targets = Get-Content $TargetListFile | Where-Object { $_ -and $_.Trim() -ne "" }
}
elseif (-not $Targets) {
    Write-Host "No targets provided. Add targets to array or create targets.txt" -ForegroundColor Red
    exit
}

# -----------------------------
# REMOTE PROBE SCRIPT
# This runs ON the remote machine
# -----------------------------

$RemoteScript = @'
$result = @{
    Hostname            = $env:COMPUTERNAME
    OSType              = $null
    BitLockerSupported  = $false
    EncryptionStatus    = $null
    EncryptionPercent   = $null
    MethodUsed          = $null
    Error               = $null
}

try {
    # Detect OS type
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop

    switch ($os.ProductType) {
        1 { $result.OSType = "Workstation" }
        2 { $result.OSType = "DomainController" }
        3 { $result.OSType = "Server" }
        default { $result.OSType = "Unknown" }
    }

    # Method 1 - Get-BitLockerVolume
    if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {

        $result.MethodUsed = "Get-BitLockerVolume"

        $vol = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop

        $result.BitLockerSupported = $true
        $result.EncryptionPercent  = $vol.EncryptionPercentage

        if ($vol.ProtectionStatus -eq 1) {
            $result.EncryptionStatus = "Encrypted"
        }
        elseif ($vol.ProtectionStatus -eq 0) {
            $result.EncryptionStatus = "Not Encrypted"
        }
        else {
            $result.EncryptionStatus = "Unknown"
        }
    }

    # Method 2 - manage-bde fallback
    else {
        $result.MethodUsed = "manage-bde"

        $bde = manage-bde -status C: 2>$null

        if ($bde) {
            $result.BitLockerSupported = $true

            if ($bde -match "Percentage Encrypted:\s+(\d+)%") {
                $result.EncryptionPercent = [int]$matches[1]
            }

            if ($bde -match "Protection Status:\s+Protection On") {
                $result.EncryptionStatus = "Encrypted"
            }
            elseif ($bde -match "Protection Status:\s+Protection Off") {
                $result.EncryptionStatus = "Not Encrypted"
            }
            else {
                $result.EncryptionStatus = "Unknown"
            }
        }
        else {
            $result.BitLockerSupported = $false
            $result.EncryptionStatus   = "Not Supported / Not Installed"
        }
    }
}
catch {
    $result.Error = $_.Exception.Message
}

# Output JSON for clean parsing
$result | ConvertTo-Json -Compress
'@

# -----------------------------
# MAIN EXECUTION LOOP
# -----------------------------

$Results = @()

foreach ($Target in $Targets) {

    Write-Host "`nScanning $Target..." -ForegroundColor Cyan

    # Build PsExec command
    $cmd = @(
        "\\$Target",
        "-n", $Timeout,
        "-h",
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-Command", "& { $RemoteScript }"
    )

    try {
        $raw = & $PsExecPath @cmd 2>&1

        # Extract JSON from output (cleaning PsExec banners)
        $json = ($raw | Where-Object { $_ -match "^\{.*\}$" })

        if ($json) {
            $obj = $json | ConvertFrom-Json
            $Results += $obj

            Write-Host "✔ Success" -ForegroundColor Green
        }
        else {
            $Results += [PSCustomObject]@{
                Hostname = $Target
                OSType = "Unknown"
                BitLockerSupported = $false
                EncryptionStatus = "Failed"
                EncryptionPercent = $null
                MethodUsed = $null
                Error = "No JSON returned"
            }

            Write-Host "✖ No JSON response" -ForegroundColor Yellow
        }
    }
    catch {
        $Results += [PSCustomObject]@{
            Hostname = $Target
            OSType = "Unknown"
            BitLockerSupported = $false
            EncryptionStatus = "Offline/Failed"
            EncryptionPercent = $null
            MethodUsed = $null
            Error = $_.Exception.Message
        }

        Write-Host "✖ Connection failed" -ForegroundColor Red
    }
}

# -----------------------------
# FINAL OUTPUT
# -----------------------------

Write-Host "`n============= RESULTS =============" -ForegroundColor Cyan
$Results | Format-Table -AutoSize

# Optional export:
#$Results | Export-Csv "C:\SAFE\VaultScope\VaultScope_Results.csv" -NoTypeInformation
# $Results | ConvertTo-Json | Out-File "C:\SAFE\VaultScope\VaultScope_Results.json"
