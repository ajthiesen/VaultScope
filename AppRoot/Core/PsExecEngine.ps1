<#
.SYNOPSIS
  PsExec wrapper + remote BitLocker/TPM probe.

.DESCRIPTION
  This file exposes two main functions:
    - ConvertTo-EncodedCommand: Helper to encode a PowerShell script as base64 UTF-16LE for -EncodedCommand
    - Invoke-RemoteProbeWithPsExec: Invoke PsExec against a single host, run the probe, capture and parse result.

  The remote payload uses native Windows cmdlets:
    Get-BitLockerVolume, Get-Tpm, Confirm-SecureBootUEFI, Get-Disk, Get-ComputerInfo

  The remote payload ALWAYS returns a single JSON object (or an Error field) to stdout.
  The local caller extracts JSON from stdout (robust against extra PsExec lines) and returns a parsed object.

.NOTES
  - PsExec must be supplied by the user (you chose to browse to it earlier).
  - Running PsExec requires appropriate admin rights on the remote machine.
  - Run tests in a controlled environment first (EDR/AV can flag PsExec).
#>

function ConvertTo-EncodedCommand {
    <#
    .SYNOPSIS
      Convert a script block or string to an EncodedCommand safe for powershell.exe -EncodedCommand

    .PARAMETER Script
      Script text to encode.

    .OUTPUTS
      String - base64-encoded UTF-16LE representation
    #>
    param([Parameter(Mandatory=$true)][string]$Script)

    # PowerShell's -EncodedCommand expects base64 of the UTF-16LE bytes
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($Script)
    $b64 = [Convert]::ToBase64String($bytes)
    return $b64
}

function Invoke-RemoteProbeWithPsExec {
    <#
    .SYNOPSIS
      Run a remote probe via PsExec and return a structured result.

    .PARAMETER Target
      Hostname or IP of the remote machine.

    .PARAMETER PsExecPath
      Full path to PsExec.exe (user-browsed).

    .PARAMETER TimeoutSeconds
      How many seconds to wait for the PsExec process before killing it.

    .PARAMETER RunAsSystem
      If $true, include -s to run under SYSTEM on the remote side. Default $true.

    .EXAMPLE
      Invoke-RemoteProbeWithPsExec -Target "pc01" -PsExecPath "C:\tools\PsExec.exe" -TimeoutSeconds 45
    #>
    param(
        [Parameter(Mandatory=$true)] [string]$Target,
        [Parameter(Mandatory=$true)] [string]$PsExecPath,
        [int]$TimeoutSeconds = 60,
        [bool]$RunAsSystem = $true
    )

    # ---- Basic validation ----
    if (-not (Test-Path -Path $PsExecPath -PathType Leaf)) {
        throw "PsExec: path '$PsExecPath' not found."
    }

    # ---- Remote payload: compact, safe, returns single JSON object ----
    # Keep this payload minimal and resilient. It must always emit a JSON string to stdout.
    $remoteScript = @'
# Remote probe script - runs on the target machine.
try {
    $out = [ordered]@{}
    $out.Machine = $env:COMPUTERNAME

    # BitLocker
    try {
        $bl = Get-BitLockerVolume -MountPoint C: -ErrorAction Stop | Select-Object -First 1 -Property MountPoint,VolumeStatus,PercentageEncrypted
        if ($null -ne $bl) {
            $out.BitLocker = @{
                Present = $true;
                VolumeStatus = $bl.VolumeStatus;
                PercentageEncrypted = $bl.PercentageEncrypted
            }
        } else {
            $out.BitLocker = @{ Present = $false }
        }
    } catch {
        $out.BitLocker = @{ Present = $false; Error = $_.Exception.Message }
    }

    # TPM
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        $out.Tpm = @{
            Present = $tpm.TpmPresent;
            Enabled = $tpm.TpmEnabled;
            Owned = $tpm.TpmOwned;
            ManufacturerId = $tpm.ManufacturerId
        }
    } catch {
        $out.Tpm = @{ Present = $false; Error = $_.Exception.Message }
    }

    # Secure Boot (only available on UEFI systems; Confirm-SecureBootUEFI returns boolean or throws)
    try {
        $sb = $false
        if (Get-Command -Name Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
            $sb = Confirm-SecureBootUEFI -ErrorAction Stop
            $out.SecureBoot = $sb
        } else {
            $out.SecureBoot = $null
        }
    } catch {
        $out.SecureBoot = $false
        $out.SecureBootError = $_.Exception.Message
    }

    # Disk layout - find OS disk (closest heuristic: non-USB, system partition)
    try {
        $osDisk = Get-Disk | Where-Object { $_.IsSystem -eq $true -or $_.BootFromDisk -eq $true } | Select-Object -First 1
        if (-not $osDisk) { $osDisk = Get-Disk | Where-Object { $_.BusType -ne 'USB' } | Select-Object -First 1 }
        if ($osDisk) {
            $out.Disk = @{
                Number = $osDisk.Number;
                PartitionStyle = $osDisk.PartitionStyle;
                Size = $osDisk.Size
            }
        } else {
            $out.Disk = $null
        }
    } catch {
        $out.Disk = @{ Error = $_.Exception.Message }
    }

    # Domain + OS info
    try {
        $ci = Get-ComputerInfo -Property CsDomain, OsName, OsDisplayVersion -ErrorAction Stop
        $out.Domain = $ci.CsDomain
        $out.OS = ($ci.OsName + ' ' + $ci.OsDisplayVersion)
    } catch {
        $out.Domain = $null
        $out.OS = $env:OS
    }

    $out.Timestamp = (Get-Date).ToString("o")
    $out.Error = $null
    $out | ConvertTo-Json -Depth 6 -Compress
}
catch {
    # Ensure we always output JSON, even on catastrophic failure.
    $err = @{
        Machine = $env:COMPUTERNAME;
        Error = $_.Exception.Message;
        Timestamp = (Get-Date).ToString("o")
    }
    $err | ConvertTo-Json -Compress
}
'@

    # ---- Encode payload for -EncodedCommand (UTF-16LE base64) ----
    $encoded = ConvertTo-EncodedCommand -Script $remoteScript

    # Build PsExec arguments. We'll use:
    #   \\<target> -accepteula -nobanner [-s] powershell.exe -NoProfile -NonInteractive -EncodedCommand <b64>
    # -s runs under SYSTEM; some operations (BitLocker/Tpm) may require elevated/system context.
    $psexecArgs = "\\$Target -accepteula -nobanner"
    if ($RunAsSystem) { $psexecArgs += " -s" }
    # Use powershell.exe with EncodedCommand to avoid escaping issues
    $psexecArgs += " powershell.exe -NoProfile -NonInteractive -EncodedCommand $encoded"

    # Start PsExec process
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $PsExecPath
    $psi.Arguments = $psexecArgs
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    $started = $proc.Start()

    # Wait with timeout; if the process doesn't exit, try graceful kill
    $finished = $proc.WaitForExit($TimeoutSeconds * 1000)
    if (-not $finished) {
        try {
            $proc.Kill()
        } catch {}
        return @{
            Success = $false;
            Error = "Timeout";
            ExitCode = $null;
            StdOut = $null;
            StdErr = "PsExec timed out after $TimeoutSeconds seconds"
        }
    }

    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $exitCode = $proc.ExitCode

    # PsExec sometimes outputs extra lines: "PsExec v2.4 Copyright..." and
    # "Starting \\host ..." and "Finished ..." — extract the JSON object by searching for the first '{' and last '}'.
    $jsonCandidate = $null
    if ($stdout) {
        $firstBrace = $stdout.IndexOf('{')
        $lastBrace  = $stdout.LastIndexOf('}')
        if ($firstBrace -ge 0 -and $lastBrace -ge $firstBrace) {
            $jsonCandidate = $stdout.Substring($firstBrace, $lastBrace - $firstBrace + 1).Trim()
        } else {
            # fallback: try last line only
            $lines = $stdout -split "`r?`n"
            $lastNonEmpty = ($lines | Where-Object { $_.Trim() -ne '' } | Select-Object -Last 1)
            $jsonCandidate = $lastNonEmpty
        }
    }

    # Try parse JSON; if fails, return raw stdout so caller can debug.
    $parsed = $null
    if ($jsonCandidate) {
        try {
            $parsed = ConvertFrom-Json -InputObject $jsonCandidate -ErrorAction Stop
        } catch {
            # malformed JSON
            $parsed = $null
        }
    }

    return @{
        Success = ($exitCode -eq 0 -and $parsed -ne $null);
        ExitCode = $exitCode;
        StdOut = $stdout;
        StdErr = $stderr;
        ParsedPayload = $parsed;
        JsonCandidate = $jsonCandidate;
    }
}
