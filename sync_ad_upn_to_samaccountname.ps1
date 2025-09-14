# AD UPN to sAMAccountName Sync Script
# This script updates users' sAMAccountName to match their UPN prefix

function Test-ADModule {
    if (!(Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Host "ERROR: Active Directory PowerShell module is not installed." -ForegroundColor Red
        Write-Host "Please install RSAT or run this on a Domain Controller." -ForegroundColor Yellow
        return $false
    }

    Import-Module ActiveDirectory
    return $true
}

function Get-ProtectedAccounts {
    # Define protected/system accounts that should never be modified
    return @(
        'Administrator',
        'Guest',
        'DefaultAccount',
        'krbtgt',
        'SUPPORT_*',
        'IUSR_*',
        'IWAM_*',
        'ASPNET',
        'TsInternetUser',
        'SQLDebugger',
        'MSOL_*',
        'HealthMailbox*',
        'SystemMailbox*',
        'DiscoverySearchMailbox*',
        'Migration.*',
        'FederatedEmail.*',
        'Exchange*',
        'SM_*',
        'AAD_*',
        'MSSQL*',
        'svc_*',
        'service_*'
    )
}

function Test-IsProtectedAccount {
    param(
        [string]$SamAccountName,
        [string]$DistinguishedName
    )

    $protectedPatterns = Get-ProtectedAccounts

    # Check against protected patterns
    foreach ($pattern in $protectedPatterns) {
        if ($SamAccountName -like $pattern) {
            return $true
        }
    }

    # Check if in protected OUs
    $protectedOUs = @(
        '*CN=Builtin,*',
        '*CN=Users,DC=*',  # Default Users container often contains system accounts
        '*OU=Domain Controllers,*',
        '*OU=Microsoft Exchange*',
        '*OU=Service Accounts*'
    )

    foreach ($ouPattern in $protectedOUs) {
        if ($DistinguishedName -like $ouPattern) {
            return $true
        }
    }

    # Check for well-known SIDs (system accounts)
    try {
        $user = Get-ADUser -Identity $SamAccountName -Properties SID -ErrorAction SilentlyContinue
        if ($user) {
            $sid = $user.SID.Value
            # Check for well-known RIDs (last part of SID)
            $rid = $sid.Split('-')[-1]
            $protectedRIDs = @(500, 501, 502, 503, 504, 505) # Administrator, Guest, KRBTGT, etc.
            if ($rid -in $protectedRIDs) {
                return $true
            }
        }
    }
    catch {
        # If we can't check, err on the side of caution
        return $true
    }

    return $false
}

function Get-UsersToUpdate {
    param(
        [string]$SearchBase = "",
        [string]$Filter = "*",
        [switch]$IncludeProtected,
        [switch]$Debug
    )

    $updateableUsers = @()
    $protectedAccounts = @()
    $noUPNUsers = @()
    $skippedAlreadyMatching = 0

    try {
        Write-Host "Retrieving AD users..." -ForegroundColor Cyan

        $adParams = @{
            Filter = $Filter
            Properties = @('UserPrincipalName', 'sAMAccountName', 'DisplayName', 'DistinguishedName', 'Enabled', 'Description', 'whenCreated', 'SID')
        }

        if ($SearchBase) {
            $adParams.SearchBase = $SearchBase
            Write-Host "Searching in: $SearchBase" -ForegroundColor Gray
        }

        $allUsers = Get-ADUser @adParams -ErrorAction Stop
        $totalUsers = $allUsers.Count
        Write-Host "Found $totalUsers total user(s) in AD" -ForegroundColor Gray

        foreach ($user in $allUsers) {
            # Process users without UPN
            if ([string]::IsNullOrWhiteSpace($user.UserPrincipalName)) {
                $skippedNoUPN++

                # Add to report even without UPN for visibility
                $isProtected = Test-IsProtectedAccount -SamAccountName $user.sAMAccountName -DistinguishedName $user.DistinguishedName
                $userInfo = [PSCustomObject]@{
                    DisplayName = if ($user.DisplayName) { $user.DisplayName } else { $user.sAMAccountName }
                    CurrentSAM = $user.sAMAccountName
                    NewSAM = "[NO UPN]"
                    UPN = "[NOT SET]"
                    DN = $user.DistinguishedName
                    Enabled = $user.Enabled
                    IsProtected = $isProtected
                    Description = $user.Description
                    Created = $user.whenCreated
                    User = $user
                }

                if ($isProtected) {
                    $protectedAccounts += $userInfo
                } else {
                    $noUPNUsers += $userInfo
                }
                continue
            }

            $upnPrefix = $user.UserPrincipalName.Split('@')[0]

            # Skip if already matching
            if ($upnPrefix -eq $user.sAMAccountName) {
                $skippedAlreadyMatching++
                if ($Debug) {
                    Write-Host "  Skipping $($user.sAMAccountName) - Already matches UPN" -ForegroundColor DarkGray
                }
                continue
            }

            # Check if this is a protected account
            $isProtected = Test-IsProtectedAccount -SamAccountName $user.sAMAccountName -DistinguishedName $user.DistinguishedName

            $userInfo = [PSCustomObject]@{
                DisplayName = if ($user.DisplayName) { $user.DisplayName } else { $user.sAMAccountName }
                CurrentSAM = $user.sAMAccountName
                NewSAM = $upnPrefix
                UPN = $user.UserPrincipalName
                DN = $user.DistinguishedName
                Enabled = $user.Enabled
                IsProtected = $isProtected
                Description = $user.Description
                Created = $user.whenCreated
                User = $user
            }

            if ($isProtected -and !$IncludeProtected) {
                $protectedAccounts += $userInfo
                continue
            }

            $updateableUsers += $userInfo
        }

        # Summary report
        Write-Host "`nScan Summary:" -ForegroundColor Cyan
        Write-Host "  Total users scanned: $totalUsers" -ForegroundColor Gray
        Write-Host "  Protected accounts (excluded): $($protectedAccounts.Count)" -ForegroundColor Yellow
        Write-Host "  Users without UPN: $($noUPNUsers.Count)" -ForegroundColor Yellow
        Write-Host "  Already matching: $skippedAlreadyMatching" -ForegroundColor Gray
        Write-Host "  Users that CAN be updated: $($updateableUsers.Count)" -ForegroundColor Green

    }
    catch {
        Write-Host "Error retrieving users: $_" -ForegroundColor Red
        Write-Host "Error details: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Stack trace: $($_.ScriptStackTrace)" -ForegroundColor DarkRed
        return $null
    }

    # Return structured data
    return [PSCustomObject]@{
        UpdateableUsers = $updateableUsers
        ProtectedAccounts = $protectedAccounts
        NoUPNUsers = $noUPNUsers
        AlreadyMatching = $skippedAlreadyMatching
    }
}

function Start-DryRun {
    param(
        [PSCustomObject]$ScanResults
    )

    Write-Host "`n=== DRY RUN RESULTS ===" -ForegroundColor Cyan

    if ($ScanResults.ProtectedAccounts.Count -gt 0) {
        Write-Host "`nProtected/System accounts (EXCLUDED from updates):" -ForegroundColor Yellow
        Write-Host "Count: $($ScanResults.ProtectedAccounts.Count)" -ForegroundColor Gray
        foreach ($account in $ScanResults.ProtectedAccounts) {
            Write-Host "  - $($account.DisplayName) ($($account.CurrentSAM))" -ForegroundColor Gray
        }
        Write-Host "`nThese accounts are safely excluded and will NEVER be updated." -ForegroundColor Green
    }

    if ($ScanResults.NoUPNUsers.Count -gt 0) {
        Write-Host "`nUsers without UPN (cannot be updated):" -ForegroundColor Yellow
        Write-Host "Count: $($ScanResults.NoUPNUsers.Count)" -ForegroundColor Gray
        foreach ($user in $ScanResults.NoUPNUsers) {
            Write-Host "  - $($user.DisplayName) ($($user.CurrentSAM))" -ForegroundColor Gray
        }
    }

    if ($ScanResults.UpdateableUsers.Count -eq 0) {
        Write-Host "`nNo users need updating. All sAMAccountNames already match UPN prefixes." -ForegroundColor Green
        # Generate report anyway for documentation
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $reportFile = "ad_upn_sync_report_$timestamp.csv"

        # Combine all user types for the report
        $reportUsers = @()
        if ($ScanResults.ProtectedAccounts) { $reportUsers += $ScanResults.ProtectedAccounts }
        if ($ScanResults.NoUPNUsers) { $reportUsers += $ScanResults.NoUPNUsers }
        if ($ScanResults.UpdateableUsers) { $reportUsers += $ScanResults.UpdateableUsers }

        $reportUsers | Select-Object DisplayName, CurrentSAM, NewSAM, UPN, DN, Enabled, IsProtected, Description, Created |
            Export-Csv -Path $reportFile -NoTypeInformation

        Write-Host "`nReport saved to: $reportFile" -ForegroundColor Green
        return $null
    }

    Write-Host "`n=== USERS THAT WILL BE UPDATED ===" -ForegroundColor Green
    Write-Host "Total users to update: $($ScanResults.UpdateableUsers.Count)" -ForegroundColor Green

    # Display updateable users
    $ScanResults.UpdateableUsers | Format-Table -AutoSize @{
        Label = "Display Name"; Expression = { $_.DisplayName }
    }, @{
        Label = "Current SAM"; Expression = { $_.CurrentSAM }
    }, @{
        Label = "New SAM"; Expression = { $_.NewSAM }
    }, @{
        Label = "UPN"; Expression = { $_.UPN }
    }, @{
        Label = "Enabled"; Expression = { $_.Enabled }
    }

    # Generate report
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "ad_upn_sync_report_$timestamp.csv"

    # Store the return value first to avoid PowerShell scoping issues
    $usersToUpdate = $ScanResults.UpdateableUsers

    # Combine all user types for the report (separate from return value)
    $reportUsers = @()
    if ($ScanResults.ProtectedAccounts) { $reportUsers += $ScanResults.ProtectedAccounts }
    if ($ScanResults.NoUPNUsers) { $reportUsers += $ScanResults.NoUPNUsers }
    if ($ScanResults.UpdateableUsers) { $reportUsers += $ScanResults.UpdateableUsers }

    $reportUsers | Select-Object DisplayName, CurrentSAM, NewSAM, UPN, DN, Enabled, IsProtected, Description, Created |
        Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`nReport saved to: $reportFile" -ForegroundColor Green

    return $usersToUpdate
}

function Update-Users {
    param(
        [array]$UsersToUpdate,
        [switch]$Force
    )

    if ($UsersToUpdate.Count -eq 0) {
        Write-Host "No users to update." -ForegroundColor Green
        return
    }

    Write-Host "`n=== STARTING USER UPDATES ===" -ForegroundColor Cyan
    Write-Host "Updating $($UsersToUpdate.Count) user account(s)..." -ForegroundColor Yellow
    Write-Host "All protected/system accounts have been safely excluded." -ForegroundColor Green

    $successCount = 0
    $failedCount = 0
    $failedUsers = @()
    $conflicts = @()
    $updateLog = @()

    foreach ($userInfo in $UsersToUpdate) {
        Write-Host "`nProcessing: $($userInfo.DisplayName) ($($userInfo.CurrentSAM))" -ForegroundColor Cyan

        try {

            # Check if new sAMAccountName already exists
            $existingUser = Get-ADUser -Filter "sAMAccountName -eq '$($userInfo.NewSAM)'" -ErrorAction SilentlyContinue

            if ($existingUser -and $existingUser.DistinguishedName -ne $userInfo.DN) {
                Write-Host "CONFLICT: sAMAccountName '$($userInfo.NewSAM)' already exists for user: $($existingUser.DisplayName)" -ForegroundColor Red
                $conflicts += [PSCustomObject]@{
                    User = $userInfo.DisplayName
                    RequestedSAM = $userInfo.NewSAM
                    ConflictingUser = $existingUser.DisplayName
                }
                $failedCount++
                continue
            }

            # Update the sAMAccountName
            Write-Host "  Updating sAMAccountName: $($userInfo.CurrentSAM) -> $($userInfo.NewSAM)" -ForegroundColor Yellow
            Set-ADUser -Identity $userInfo.User -SamAccountName $userInfo.NewSAM

            Write-Host "  SUCCESS: Updated $($userInfo.DisplayName)" -ForegroundColor Green
            $updateLog += "Updated: $($userInfo.DisplayName) | $($userInfo.CurrentSAM) to $($userInfo.NewSAM) | UPN: $($userInfo.UPN)"
            $successCount++
        }
        catch {
            Write-Host "  FAILED: $($userInfo.DisplayName) - Error: $_" -ForegroundColor Red
            $failedUsers += [PSCustomObject]@{
                User = $userInfo.DisplayName
                CurrentSAM = $userInfo.CurrentSAM
                NewSAM = $userInfo.NewSAM
                Error = $_.ToString()
            }
            $failedCount++
        }
    }

    Write-Host "`n=== UPDATE SUMMARY ===" -ForegroundColor Cyan
    Write-Host "Successfully updated: $successCount users" -ForegroundColor Green

    if ($successCount -gt 0) {
        Write-Host "`nUpdate Details:" -ForegroundColor Green
        foreach ($log in $updateLog) {
            Write-Host "  $log" -ForegroundColor Gray
        }

        # Save update log to file
        $logTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $logFile = "ad_upn_sync_updates_$logTimestamp.log"
        $updateLog | Out-File -FilePath $logFile -Encoding UTF8
        Write-Host "`nUpdate log saved to: $logFile" -ForegroundColor Green
    }

    if ($failedCount -gt 0) {
        Write-Host "`nFailed to update: $failedCount users" -ForegroundColor Red

        if ($conflicts.Count -gt 0) {
            Write-Host "`nConflicts detected:" -ForegroundColor Red
            $conflicts | Format-Table -AutoSize
        }

        if ($failedUsers.Count -gt 0) {
            Write-Host "`nFailed updates:" -ForegroundColor Red
            $failedUsers | Format-Table -AutoSize User, CurrentSAM, NewSAM, Error
        }
    }

    Write-Host "`nUpdate operation completed." -ForegroundColor Cyan
}

function Show-Menu {
    Write-Host "`nAD UPN to sAMAccountName Sync Tool" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Protected accounts are automatically excluded!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "1. Dry run (scan and report all users)" -ForegroundColor White
    Write-Host "2. Dry run (specific OU)" -ForegroundColor White
    Write-Host "3. Update all users (safe mode)" -ForegroundColor White
    Write-Host "4. Update users in specific OU (safe mode)" -ForegroundColor White
    Write-Host "5. Show protected account patterns" -ForegroundColor White
    Write-Host "6. Exit" -ForegroundColor White
    Write-Host ""
}

# Main execution
Clear-Host

# Check for AD module
if (!(Test-ADModule)) {
    Write-Host "`nPress any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit
}

# Check if running as administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "WARNING: Not running as Administrator. Some operations may fail." -ForegroundColor Yellow
    Write-Host ""
}

do {
    Show-Menu
    $choice = Read-Host "Select option (1-6)"

    switch ($choice) {
        '1' {
            Write-Host "`nScanning all users in domain..." -ForegroundColor Yellow
            $scanResults = Get-UsersToUpdate
            if ($scanResults) {
                $updateableUsers = Start-DryRun -ScanResults $scanResults

                if ($updateableUsers -and $updateableUsers.Count -gt 0) {
                    Write-Host "`nDo you want to update these $($updateableUsers.Count) user(s) now? (y/n): " -NoNewline -ForegroundColor Yellow
                    $proceed = Read-Host
                    if ($proceed -eq 'y' -or $proceed -eq 'Y') {
                        Update-Users -UsersToUpdate $updateableUsers
                    }
                } else {
                    Write-Host "`nNo action needed - all accounts are properly configured!" -ForegroundColor Green
                }
            }
            Write-Host "`nPress any key to continue..."
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        '2' {
            $ou = Read-Host "`nEnter OU Distinguished Name (e.g., OU=Users,DC=domain,DC=com)"
            Write-Host "Scanning users in specified OU..." -ForegroundColor Yellow
            $scanResults = Get-UsersToUpdate -SearchBase $ou
            if ($scanResults) {
                $updateableUsers = Start-DryRun -ScanResults $scanResults

                if ($updateableUsers -and $updateableUsers.Count -gt 0) {
                    Write-Host "`nDo you want to update these $($updateableUsers.Count) user(s) now? (y/n): " -NoNewline -ForegroundColor Yellow
                    $proceed = Read-Host
                    if ($proceed -eq 'y' -or $proceed -eq 'Y') {
                        Update-Users -UsersToUpdate $updateableUsers
                    }
                } else {
                    Write-Host "`nNo action needed - all accounts are properly configured!" -ForegroundColor Green
                }
            }
            Write-Host "`nPress any key to continue..."
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        '3' {
            Write-Host "`nThis will update ALL users without preview (protected accounts excluded). Continue? (y/n): " -NoNewline -ForegroundColor Red
            $response = Read-Host
            if ($response -eq 'y' -or $response -eq 'Y') {
                Write-Host "Scanning all users..." -ForegroundColor Yellow
                $scanResults = Get-UsersToUpdate
                if ($scanResults -and $scanResults.UpdateableUsers.Count -gt 0) {
                    Write-Host "Found $($scanResults.UpdateableUsers.Count) user(s) that can be updated." -ForegroundColor Green
                    Update-Users -UsersToUpdate $scanResults.UpdateableUsers
                } else {
                    Write-Host "No users found that need updating." -ForegroundColor Yellow
                }
            } else {
                Write-Host "Operation cancelled." -ForegroundColor Yellow
            }
            Write-Host "`nPress any key to continue..."
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        '4' {
            $ou = Read-Host "`nEnter OU Distinguished Name (e.g., OU=Users,DC=domain,DC=com)"
            Write-Host "This will update users in specified OU without preview (protected accounts excluded). Continue? (y/n): " -NoNewline -ForegroundColor Red
            $response = Read-Host
            if ($response -eq 'y' -or $response -eq 'Y') {
                Write-Host "Scanning users in specified OU..." -ForegroundColor Yellow
                $scanResults = Get-UsersToUpdate -SearchBase $ou
                if ($scanResults -and $scanResults.UpdateableUsers.Count -gt 0) {
                    Write-Host "Found $($scanResults.UpdateableUsers.Count) user(s) that can be updated." -ForegroundColor Green
                    Update-Users -UsersToUpdate $scanResults.UpdateableUsers
                } else {
                    Write-Host "No users found that need updating." -ForegroundColor Yellow
                }
            } else {
                Write-Host "Operation cancelled." -ForegroundColor Yellow
            }
            Write-Host "`nPress any key to continue..."
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        '5' {
            Write-Host "`nProtected Account Patterns:" -ForegroundColor Cyan
            Write-Host "=============================" -ForegroundColor Cyan
            $patterns = Get-ProtectedAccounts
            foreach ($pattern in $patterns) {
                Write-Host "  - $pattern" -ForegroundColor Yellow
            }
            Write-Host "`nProtected OUs:" -ForegroundColor Cyan
            Write-Host "- CN=Builtin" -ForegroundColor Yellow
            Write-Host "- CN=Users (default container)" -ForegroundColor Yellow
            Write-Host "- OU=Domain Controllers" -ForegroundColor Yellow
            Write-Host "- OU=Microsoft Exchange*" -ForegroundColor Yellow
            Write-Host "- OU=Service Accounts*" -ForegroundColor Yellow
            Write-Host "`nWell-known RIDs (500-505) are also protected" -ForegroundColor Cyan
            Write-Host "`nPress any key to continue..."
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        '6' {
            Write-Host "Exiting..." -ForegroundColor Green
            break
        }
        default {
            Write-Host "Invalid option. Please select 1-6." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
} while ($choice -ne '6')
