param(
    [Parameter(Mandatory)]
    [string]$TargetListPath,

    [Parameter(Mandatory)]
    [string]$PsExecPath
)

# -----------------------------
# Load targets
# -----------------------------
if (!(Test-Path $TargetListPath)) {
    Write-Error "Target list not found: $TargetListPath"
    exit 1
}
$Targets = Get-Content $TargetListPath | Where-Object { $_ -and $_.Trim() -ne "" }

# -----------------------------
# Remote script template
# -----------------------------
$RemoteScript = @'
$result = [ordered]@{
    Hostname               = $env:COMPUTERNAME
    OSType                 = $null
    TPM_Present            = $false
    BitLockerSupported     = $false
    ProtectionStatus       = $null
    VolumeStatus           = $null
    EncryptionPercent      = $null
    KeyProtectors          = $null
    ReasonNotEncrypted     = $null
    NativeExitCode         = $null
    StdErr                 = $null
}

try {
    # -----------------------------
    # OS Type
    # -----------------------------
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $result.OSType = switch ($os.ProductType) {1{"Workstation"} 2{"DomainController"} 3{"Server"} default{"Unknown"}}

    # -----------------------------
    # TPM Detection
    # -----------------------------
    try {
        $tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction Stop
        $result.TPM_Present = $true
    } catch {}

    # -----------------------------
    # BitLocker Detection
    # -----------------------------
    if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
        $result.BitLockerSupported = $true
        try {
            $vol = Get-BitLockerVolume -MountPoint "C:"
            $result.ProtectionStatus = [int]$vol.ProtectionStatus
            $result.VolumeStatus = [int]$vol.VolumeStatus
            $result.EncryptionPercent = [int]$vol.EncryptionPercentage
            $result.KeyProtectors = ($vol.KeyProtector | Select-Object KeyProtectorType, KeyProtectorId)

            if ($vol.ProtectionStatus -eq 1) {
                $result.ReasonNotEncrypted = "Volume protected"
            } elseif ($vol.ProtectionStatus -eq 0) {
                if ($result.TPM_Present -eq $false) {
                    $result.ReasonNotEncrypted = "TPM not present"
                } elseif (-not $vol.KeyProtector) {
                    $result.ReasonNotEncrypted = "No key protector configured"
                } else {
                    $result.ReasonNotEncrypted = "Unknown reason"
                }
            } else {
                $result.ReasonNotEncrypted = "Unknown protection status"
            }
        } catch {
            $result.StdErr = $_.Exception.Message
        }
    } else {
        # -----------------------------
        # Fallback: manage-bde
        # -----------------------------
        $output = manage-bde -status C: 2>&1
        $result.NativeExitCode = $LASTEXITCODE
        if ($LASTEXITCODE -eq 0) {
            $result.BitLockerSupported = $true
            if ($output -match "Percentage Encrypted:\s+(\d+)%") {
                $result.EncryptionPercent = [int]$matches[1]
            }
            if ($output -match "Protection Status:\s+Protection On") {
                $result.ProtectionStatus = 1
                $result.ReasonNotEncrypted = "Volume protected"
            } elseif ($output -match "Protection Status:\s+Protection Off") {
                $result.ProtectionStatus = 0
                if ($result.TPM_Present -eq $false) {
                    $result.ReasonNotEncrypted = "TPM not present"
                } else {
                    $result.ReasonNotEncrypted = "No key protector configured"
                }
            } else {
                $result.ReasonNotEncrypted = "Unknown protection status"
            }
        } else {
            $result.BitLockerSupported = $false
            $result.ReasonNotEncrypted = "BitLocker not installed or not supported"
        }
    }
} catch {
    $result.StdErr = $_.Exception.Message
}

$result | ConvertTo-Json -Compress -Depth 5
'@

# -----------------------------
# Scan loop
# -----------------------------
$Results = @()
foreach ($Target in $Targets) {
    Write-Host "`nScanning: $Target"
    $PsExecArgs = "\\$Target -h -n 60 powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command `"& { $RemoteScript }`""

    try {
        $raw = & $PsExecPath $PsExecArgs 2>&1
        $json = ($raw | Where-Object { $_ -match "^\{.*\}$" })
        if ($json) {
            $obj = $json | ConvertFrom-Json
            $Results += $obj
            Write-Host "✔ Success"
        } else {
            $Results += [PSCustomObject]@{
                Hostname = $Target
                ReasonNotEncrypted = "No JSON returned"
                BitLockerSupported = $false
                ProtectionStatus = $null
                VolumeStatus = $null
                EncryptionPercent = $null
                KeyProtectors = $null
                TPM_Present = $false
                StdErr = ($raw -join "`n")
                NativeExitCode = $null
            }
            Write-Host "⚠ No JSON returned"
        }
    } catch {
        $Results += [PSCustomObject]@{
            Hostname = $Target
            ReasonNotEncrypted = "Connection failed"
            BitLockerSupported = $false
            ProtectionStatus = $null
            VolumeStatus = $null
            EncryptionPercent = $null
            KeyProtectors = $null
            TPM_Present = $false
            StdErr = $_.Exception.Message
            NativeExitCode = -1
        }
        Write-Host "✖ Connection failed"
    }
}

# -----------------------------
# Output
# -----------------------------
$Results | Format-Table `
    Hostname,
    OSType,
    TPM_Present,
    BitLockerSupported,
    ProtectionStatus,
    VolumeStatus,
    EncryptionPercent,
    KeyProtectors,
    ReasonNotEncrypted,
    NativeExitCode,
    StdErr -AutoSize

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Results | ConvertTo-Json -Depth 5 | Out-File "VaultScope_$Timestamp.json"
Write-Host "`nScan complete. Results saved to VaultScope_$Timestamp.json"
