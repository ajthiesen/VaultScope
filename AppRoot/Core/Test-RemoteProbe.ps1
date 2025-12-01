<#
Test-RemoteProbe.ps1
Usage:
  - Run PowerShell (x64) as Administrator.
  - Update $PsExecPath if you know static path; otherwise the script will prompt to browse.
  - Run: .\Test-RemoteProbe.ps1 -Target "REMOTEHOST"

This will call Invoke-RemoteProbeWithPsExec and print the structured response and a pretty JSON.
#>

param(
    [Parameter(Mandatory=$true)][string]$Target,
    [string]$PsExecPath
)

# If PsExec path not provided, prompt to pick it
if (-not $PsExecPath) {
    Add-Type -AssemblyName System.Windows.Forms
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Filter = 'PsExec.exe|PsExec.exe|All Files|*.*'
    $ofd.Title = 'Select PsExec.exe'
    if ($ofd.ShowDialog() -ne 'OK') {
        Write-Error "PsExec path not selected; aborting."
        return
    }
    $PsExecPath = $ofd.FileName
}

# Import the core function (assumes same folder)
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
. (Join-Path $scriptDir 'PsExecEngine.ps1')

Write-Host "Testing remote probe to $Target using PsExec at $PsExecPath" -ForegroundColor Cyan

try {
    $res = Invoke-RemoteProbeWithPsExec -Target $Target -PsExecPath $PsExecPath -TimeoutSeconds 60 -RunAsSystem $true
} catch {
    Write-Error "Invoke-RemoteProbeWithPsExec threw an exception: $($_.Exception.Message)"
    return
}

# Print top-level result
Write-Host "Success: $($res.Success); ExitCode: $($res.ExitCode)" -ForegroundColor Green
if ($res.StdErr) {
    Write-Host "`n---- STDERR ----" -ForegroundColor Yellow
    Write-Host $res.StdErr
}
if ($res.StdOut) {
    Write-Host "`n---- RAW STDOUT ----" -ForegroundColor Gray
    Write-Host $res.StdOut
}

# If ParsedPayload exists, pretty-print it
if ($res.ParsedPayload) {
    Write-Host "`n---- Parsed Payload (pretty JSON) ----" -ForegroundColor Cyan
    $res.ParsedPayload | ConvertTo-Json -Depth 6 | Out-String | Write-Host
} else {
    Write-Host "`nNo JSON payload parsed. Inspect StdOut/StdErr and JsonCandidate for debugging." -ForegroundColor Red
    if ($res.JsonCandidate) {
        Write-Host "`n---- JSON Candidate ----" -ForegroundColor Yellow
        Write-Host $res.JsonCandidate
    }
}

# Return the full result object for further scripting
return $res
