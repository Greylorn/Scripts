function Get-LnkFiles {
    $lnkFiles = @()
    $totalSize = 0

    Get-ChildItem -Path . -Recurse -Filter "*.lnk" -ErrorAction SilentlyContinue | ForEach-Object {
        $lnkFiles += [PSCustomObject]@{
            Path = $_.FullName
            Size = $_.Length
            RelativePath = Resolve-Path -Path $_.FullName -Relative
        }
        $totalSize += $_.Length
    }

    return @{
        Files = $lnkFiles
        TotalSize = $totalSize
    }
}

function Start-DryRun {
    Write-Host "`n=== DRY RUN - Scanning for .lnk files ===" -ForegroundColor Cyan
    Write-Host "Scanning from: $(Get-Location)`n"

    $result = Get-LnkFiles
    $lnkFiles = $result.Files
    $totalSize = $result.TotalSize

    if ($lnkFiles.Count -eq 0) {
        Write-Host "No .lnk files found." -ForegroundColor Green
        return $false
    }

    Write-Host "Found $($lnkFiles.Count) .lnk file(s) to delete:`n" -ForegroundColor Yellow

    foreach ($file in $lnkFiles) {
        $sizeKB = [math]::Round($file.Size / 1KB, 2)
        Write-Host "  $($file.RelativePath) ($sizeKB KB)"
    }

    $totalMB = [math]::Round($totalSize / 1MB, 2)
    Write-Host "`nTotal: $($lnkFiles.Count) files, $totalMB MB" -ForegroundColor Yellow

    # Generate report
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "lnk_deletion_report_$timestamp.txt"

    $reportContent = @"
LNK Files Deletion Report - $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
============================================================

Scan Location: $(Get-Location)
Total files to delete: $($lnkFiles.Count)
Total size: $totalMB MB

Files to be deleted:
----------------------------------------
"@

    foreach ($file in $lnkFiles) {
        $reportContent += "`n$($file.Path) ($($file.Size) bytes)"
    }

    $reportContent | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Host "`nReport saved to: $reportFile" -ForegroundColor Green

    return $true
}

function Remove-LnkFiles {
    $result = Get-LnkFiles
    $lnkFiles = $result.Files
    $deletedCount = 0
    $failedCount = 0
    $failedFiles = @()

    if ($lnkFiles.Count -eq 0) {
        Write-Host "No .lnk files found to delete." -ForegroundColor Green
        return
    }

    Write-Host "`nDeleting $($lnkFiles.Count) .lnk file(s)..." -ForegroundColor Yellow

    foreach ($file in $lnkFiles) {
        try {
            Remove-Item -Path $file.Path -Force -ErrorAction Stop
            Write-Host "Deleted: $($file.RelativePath)" -ForegroundColor Green
            $deletedCount++
        }
        catch {
            Write-Host "Error deleting $($file.RelativePath): $_" -ForegroundColor Red
            $failedCount++
            $failedFiles += $file.RelativePath
        }
    }

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Total .lnk files deleted: $deletedCount" -ForegroundColor Green

    if ($failedCount -gt 0) {
        Write-Host "Failed to delete: $failedCount" -ForegroundColor Red
        Write-Host "Failed files:" -ForegroundColor Red
        foreach ($failedFile in $failedFiles) {
            Write-Host "  - $failedFile" -ForegroundColor Red
        }
    }
}

function Show-Menu {
    Write-Host "`nLNK File Deletion Tool" -ForegroundColor Cyan
    Write-Host "Current Directory: $(Get-Location)" -ForegroundColor Gray
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "1. Dry run (scan and report)" -ForegroundColor White
    Write-Host "2. Delete all .lnk files" -ForegroundColor White
    Write-Host "3. Exit" -ForegroundColor White
    Write-Host ""
}

# Main execution
Clear-Host

do {
    Show-Menu
    $choice = Read-Host "Select option (1-3)"

    switch ($choice) {
        '1' {
            $hasFiles = Start-DryRun
            if ($hasFiles) {
                Write-Host "`nDo you want to delete these files now? (y/n): " -NoNewline -ForegroundColor Yellow
                $proceed = Read-Host
                if ($proceed -eq 'y' -or $proceed -eq 'Y') {
                    Remove-LnkFiles
                }
            }
            Write-Host "`nPress any key to continue..."
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        '2' {
            Write-Host "`nThis will delete all .lnk files without preview. Continue? (y/n): " -NoNewline -ForegroundColor Red
            $response = Read-Host
            if ($response -eq 'y' -or $response -eq 'Y') {
                Remove-LnkFiles
            } else {
                Write-Host "Operation cancelled." -ForegroundColor Yellow
            }
            Write-Host "`nPress any key to continue..."
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        '3' {
            Write-Host "Exiting..." -ForegroundColor Green
            break
        }
        default {
            Write-Host "Invalid option. Please select 1-3." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
} while ($choice -ne '3')