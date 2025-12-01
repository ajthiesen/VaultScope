# MainWindow.xaml.ps1 - PowerShell code-behind (light MVVM-style)
$global:ScanCancellation = $false
$global:Results = [System.Collections.ObjectModel.ObservableCollection[object]]::new()


# Bind the results collection to the DataGrid's ItemsSource
$resultsDataGrid.ItemsSource = $global:Results


# Event handlers
$browsePsExecButton.Add_Click({
Add-Type -AssemblyName System.Windows.Forms
$ofd = New-Object System.Windows.Forms.OpenFileDialog
$ofd.Filter = 'PsExec.exe|PsExec.exe|All Files|*.*'
$ofd.InitialDirectory = [Environment]::GetFolderPath('Desktop')
if ($ofd.ShowDialog() -eq 'OK') {
$global:PsExecPath = $ofd.FileName
$psExecPathText.Text = $global:PsExecPath
}
})


$scanButton.Add_Click({
# Disable Scan button, enable Stop
$scanButton.IsEnabled = $false
$stopButton.IsEnabled = $true
$statusText.Text = 'Scanning...'


# Read machines from text box
$machines = $machineListTextBox.Text -split "[\r\n]+" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' } | Select-Object -Unique
$progressSummary.Text = "0 / $($machines.Count)"


# Call the orchestrator (non-blocking)
Start-Job -ScriptBlock {
param($machines, $psExecPath)
# Import modules from script folder (Orchestrator.ps1, PsExecEngine.ps1, etc.)
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
. (Join-Path $scriptDir '..\Core\Orchestrator.ps1')
. (Join-Path $scriptDir '..\Core\PsExecEngine.ps1')
. (Join-Path $scriptDir '..\Core\AssessmentEngine.ps1')
. (Join-Path $scriptDir '..\Models\MachineResult.ps1')


# Run the orchestrator (synchronous within the job)
$orchestratorResults = Start-Orchestration -MachineList $machines -PsExecPath $psExecPath -MaxWorkers 5 -TimeoutSeconds 60


# Output results as JSON to the job output
$orchestratorResults | ConvertTo-Json -Depth 4
} -ArgumentList ($machines, $global:PsExecPath) | Out-Null


# Poll job for completion and update UI (simple skeleton polling)
Start-Job -ScriptBlock {
param($job)
while ($job.State -eq 'Running') { Start-Sleep -Seconds 1 }
} -ArgumentList (Get-Job | Select-Object -Last 1) | Out-Null


# Note: a proper implementation will use events or runspace pools to stream results back to UI.
})


$stopButton.Add_Click({
# Signal cancellation (skeleton)
$global:ScanCancellation = $true
$statusText.Text = 'Cancellation requested'
$stopButton.IsEnabled = $false
})


# Show the window
$window.ShowDialog() | Out-Null