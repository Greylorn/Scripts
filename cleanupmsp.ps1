<#
    Cleanup-MSP-Drive.ps1

    Simple non-interactive cleanup for Datto RMM.
    Deletes every .msp file found on the system drive (default C:\) and writes progress to STDOUT.

    WARNING:
        Removing .msp patch files can break uninstall/repair for MSI-based applications.
        Use only if absolutely necessary.

    Usage:
        powershell.exe -ExecutionPolicy Bypass -File .\cleanup-msp-drive.ps1
#>

$startTime = Get-Date
Write-Output "Cleanup start: $startTime"

# Prepare log structure
$logEntries = @()

# Ensure we are elevated
$admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    Write-Output 'ERROR: Script must be run as Administrator.'
    exit 1
}

$root = $env:SystemDrive + '\'
Write-Output "Scanning drive $root for *.msp files ..."

try {
    $files = Get-ChildItem -Path $root -Filter '*.msp' -Recurse -ErrorAction SilentlyContinue -File
} catch {
    Write-Output "ERROR: Failed during scan: $_"
    exit 1
}

if (-not $files) {
    Write-Output 'No .msp files found. Nothing to delete.'
    exit 0
}

$totalSizeBytes = ($files | Measure-Object -Sum Length).Sum
$totalSizeMB    = [math]::Round($totalSizeBytes / 1MB, 2)
Write-Output "Found $($files.Count) .msp file(s) using $totalSizeMB MB. Deleting ..."

$deletedBytes = 0
foreach ($file in $files) {
    try {
        $deletedBytes += $file.Length
        Remove-Item -Path $file.FullName -Force -ErrorAction Stop
        Write-Output "DELETED: $($file.FullName)"
        $logEntries += [PSCustomObject]@{
            FilePath  = $file.FullName
            SizeBytes = $file.Length
            Result    = 'Deleted'
            Error     = $null
        }
    } catch {
        $deletedBytes -= $file.Length
        Write-Output "FAILED : $($file.FullName) - $_"
        $logEntries += [PSCustomObject]@{
            FilePath  = $file.FullName
            SizeBytes = $file.Length
            Result    = 'Failed'
            Error     = $_.Exception.Message
        }
    }
}

$freedMB = [math]::Round($deletedBytes / 1MB, 2)
$endTime = Get-Date
Write-Output "Cleanup complete. Freed approximately $freedMB MB."
Write-Output "Cleanup end: $endTime"

# Write JSON log
$summary = [PSCustomObject]@{
    StartTime    = $startTime
    EndTime      = $endTime
    TotalFiles   = $files.Count
    DeletedFiles = ($logEntries | Where-Object { $_.Result -eq 'Deleted' }).Count
    FailedFiles  = ($logEntries | Where-Object { $_.Result -eq 'Failed' }).Count
    FreedMB      = $freedMB
    Entries      = $logEntries
}

$logDir  = 'C:\Temp'
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
$logPath = Join-Path $logDir ("cleanup-msp-drive-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json')
$summary | ConvertTo-Json -Depth 5 | Out-File -FilePath $logPath -Encoding UTF8

Write-Output "JSON log written to $logPath" 