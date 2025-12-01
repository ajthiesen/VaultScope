<#
.SYNOPSIS
    VaultScope v1.0 - BitLocker / TPM / Encryption Status Auditor

.DESCRIPTION
    Uses PsExec to remotely determine BitLocker status.
    Returns both:
      - RAW Microsoft-native values
      - HUMAN-readable interpretation

    NO CHANGES ARE MADE.
    Report-only by design.
#>

# -----------------------------
# CONFIGURATION
# -----------------------------

# Path to PsExec
$PsExecPath = "C:\SAFE\PSTools\PsExec.exe"

# Target list file (one host per line)
$TargetListFile = "C:\SAFE\VaultScope\targets.txt"

# Timeout for PsExec
$Timeout = 60

# -----------------------------
# LOAD TARGETS
# -----------------------------

if (Test-Path $TargetListFile) {
    $Targets = Get-Content $TargetListFile | Where-Object { $_ -and $_.Trim() -ne "" }
}
else {
    Write-Host "Target list not found: $TargetListFile" -ForegroundColor Red
    exit
}

# -----------------------------
# REMOTE PROBE
# -----------------------------

$RemoteScript = @'
$result = [ordered]@{
    Hostname              = $env:COMPUTERNAME
    OSType                = $null

    # Method info
    MethodUsed            = $null

    # RAW Microsoft values
    ProtectionStatus      = $null
    VolumeStatus          = $null
    EncryptionPercent     = $null
    NativeExitCode         = $null
    NativeOutput           = $null

    # Human friendly interpretations
    FriendlyStatus         = $null
    BitLockerSupported     = $false
    TPM_Present             = $null

    # Error
    Error                  = $null
}

try {
    # -----------------------------
    # OS DETECTION
    # -----------------------------
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop

    switch ($os.ProductType) {
        1 { $result.OSType = "Workstation" }
        2 { $result.OSType = "DomainController" }
        3 { $result.OSType = "Server" }
        default { $result.OSType = "Unknown" }
    }

    # -----------------------------
    # TPM DETECTION
    # -----------------------------
    try {
        $tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction Stop
        $result.TPM_Present = $true
    }
    catch {
        $result.TPM_Present = $false
    }

    # -----------------------------
    # METHOD 1 — Get-BitLockerVolume
    # -----------------------------
    if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {

        $result.MethodUsed = "Get-BitLockerVolume"

        try {
            $vol = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop

            $result.BitLockerSupported  = $true
            $result.ProtectionStatus    = [int]$vol.ProtectionStatus
            $result.VolumeStatus        = [int]$vol.VolumeStatus
            $result.EncryptionPercent   = [int]$vol.EncryptionPercentage

            # Friendly mapping
            switch ($vol.ProtectionStatus) {
                0 { $result.FriendlyStatus = "Not Encrypted" }
                1 { $result.FriendlyStatus = "Encrypted" }
                default { $result.FriendlyStatus = "Unknown" }
            }
        }
        catch {
            $result.Error = $_.Exception.Message
        }
    }

    # -----------------------------
    # METHOD 2 — manage-bde fallback
    # -----------------------------
    else {
        $result.MethodUsed = "manage-bde"

        $bde = manage-bde -status C: 2>&1
        $result.NativeExitCode  = $LASTEXITCODE
        $result.NativeOutput     = ($bde -join "`n")

        if ($result.NativeExitCode -eq 0) {
            $result.BitLockerSupported = $true

            if ($result.NativeOutput -match "Percentage Encrypted:\s+(\d+)%") {
                $result.EncryptionPercent = [int]$matches[1]
            }

            if ($result.NativeOutput -match "Protection Status:\s+Protection On") {
                $result.FriendlyStatus = "Encrypted"
            }
            elseif ($result.NativeOutput -match "Protection Status:\s+Protection Off") {
                $result.FriendlyStatus = "Not Encrypted"
            }
            else {
                $result.FriendlyStatus = "Unknown"
            }
        }
        else {
            $result.BitLockerSupported = $false
            $result.FriendlyStatus = "Not Supported / Not Installed"
        }
    }
}
catch {
    $result.Error = $_.Exception.Message
}

$result | ConvertTo-Json -Compress -Depth 4
'@

# -----------------------------
# MAIN LOOP
# -----------------------------

$Results = @()

foreach ($Target in $Targets) {

    Write-Host "`nScanning $Target..." -ForegroundColor Cyan

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

        # extract JSON only
        $json = ($raw | Where-Object { $_ -match "^\{.*\}$" })

        if ($json) {
            $obj = $json | ConvertFrom-Json
            $Results += $obj
            Write-Host "✔ Success" -ForegroundColor Green
        }
        else {
            $Results += [PSCustomObject]@{
                Hostname          = $Target
                OSType            = "Unknown"
                BitLockerSupported= $false
                FriendlyStatus    = "Failed"
                NativeExitCode    = $null
                Error             = "No JSON returned"
            }
            Write-Host "⚠ No JSON returned" -ForegroundColor Yellow
        }
    }
    catch {
        $Results += [PSCustomObject]@{
            Hostname           = $Target
            OSType             = "Unknown"
            BitLockerSupported = $false
            FriendlyStatus     = "Connection Failed"
            Error              = $_.Exception.Message
        }

        Write-Host "✖ Connection failed" -ForegroundColor Red
    }
}

# -----------------------------
# OUTPUT
# -----------------------------

Write-Host "`n=========== VAULTSCOPE RESULTS ===========" -ForegroundColor Cyan

$Results | Format-Table `
    Hostname,
    OSType,
    TPM_Present,
    BitLockerSupported,
    FriendlyStatus,
    EncryptionPercent,
    ProtectionStatus,
    VolumeStatus,
    NativeExitCode -AutoSize

# Optional export (recommended)
# $Results | Export-Csv "C:\SAFE\VaultScope\VaultScope_Results.csv" -NoTypeInformation
# $Results | ConvertTo-Json -Depth 4 | Out-File "C:\SAFE\VaultScope\VaultScope_Results.json"
