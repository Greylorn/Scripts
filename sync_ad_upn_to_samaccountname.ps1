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
        [switch]$IncludeProtected
    )

    $users = @()
    $skippedProtected = @()

    try {
        $adParams = @{
            Filter = $Filter
            Properties = @('UserPrincipalName', 'sAMAccountName', 'DisplayName', 'DistinguishedName', 'Enabled', 'Description', 'whenCreated')
        }

        if ($SearchBase) {
            $adParams.SearchBase = $SearchBase
        }

        $allUsers = Get-ADUser @adParams

        foreach ($user in $allUsers) {
            if ($user.UserPrincipalName) {
                $upnPrefix = $user.UserPrincipalName.Split('@')[0]

                if ($upnPrefix -ne $user.sAMAccountName) {
                    # Check if this is a protected account
                    $isProtected = Test-IsProtectedAccount -SamAccountName $user.sAMAccountName -DistinguishedName $user.DistinguishedName

                    if ($isProtected -and !$IncludeProtected) {
                        $skippedProtected += [PSCustomObject]@{
                            DisplayName = $user.DisplayName
                            SamAccountName = $user.sAMAccountName
                            UPN = $user.UserPrincipalName
                            Reason = "Protected/System Account"
                        }
                        continue
                    }

                    $userInfo = [PSCustomObject]@{
                        DisplayName = $user.DisplayName
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

                    $users += $userInfo
                }
            }
        }

        # Report skipped protected accounts
        if ($skippedProtected.Count -gt 0) {
            Write-Host "`nSkipped $($skippedProtected.Count) protected/system account(s):" -ForegroundColor Yellow
            $skippedProtected | Format-Table -AutoSize
        }
    }
    catch {
        Write-Host "Error retrieving users: $_" -ForegroundColor Red
        return $null
    }

    return $users
}

function Start-DryRun {
    param(
        [array]$UsersToUpdate
    )

    Write-Host "`n=== DRY RUN - Users that will be updated ===" -ForegroundColor Cyan
    Write-Host "Total users to update: $($UsersToUpdate.Count)`n" -ForegroundColor Yellow

    if ($UsersToUpdate.Count -eq 0) {
        Write-Host "No users need updating. All sAMAccountNames already match UPN prefixes." -ForegroundColor Green
        return
    }

    # Separate protected and regular users
    $protectedUsers = $UsersToUpdate | Where-Object { $_.IsProtected -eq $true }
    $regularUsers = $UsersToUpdate | Where-Object { $_.IsProtected -ne $true }

    if ($protectedUsers.Count -gt 0) {
        Write-Host "`nWARNING: The following protected accounts are included:" -ForegroundColor Red
        $protectedUsers | Format-Table -AutoSize @{
            Label = "Display Name"; Expression = { $_.DisplayName }
        }, @{
            Label = "Current SAM"; Expression = { $_.CurrentSAM }
        }, @{
            Label = "New SAM"; Expression = { $_.NewSAM }
        }, @{
            Label = "Created"; Expression = { $_.Created }
        }
        Write-Host "These accounts require special attention!" -ForegroundColor Red
    }

    # Display regular users
    if ($regularUsers.Count -gt 0) {
        Write-Host "`nRegular user accounts to update:" -ForegroundColor Green
        $regularUsers | Format-Table -AutoSize @{
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
    }

    # Generate report
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "ad_upn_sync_report_$timestamp.csv"

    $UsersToUpdate | Select-Object DisplayName, CurrentSAM, NewSAM, UPN, DN, Enabled, IsProtected, Description, Created |
        Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`nReport saved to: $reportFile" -ForegroundColor Green
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

    # Check for protected accounts
    $protectedUsers = $UsersToUpdate | Where-Object { $_.IsProtected -eq $true }
    if ($protectedUsers.Count -gt 0 -and !$Force) {
        Write-Host "`nERROR: Cannot proceed - protected accounts detected!" -ForegroundColor Red
        Write-Host "Protected accounts found:" -ForegroundColor Red
        $protectedUsers | Format-Table -AutoSize DisplayName, CurrentSAM
        Write-Host "`nTo update protected accounts, use the -Force parameter (NOT RECOMMENDED)" -ForegroundColor Yellow
        Write-Host "Consider excluding these accounts or updating them manually." -ForegroundColor Yellow
        return
    }

    $successCount = 0
    $failedCount = 0
    $skippedCount = 0
    $failedUsers = @()
    $conflicts = @()

    Write-Host "`nUpdating $($UsersToUpdate.Count) user(s)..." -ForegroundColor Yellow

    foreach ($userInfo in $UsersToUpdate) {
        try {
            # Final safety check even with Force
            if ($userInfo.IsProtected -and !$Force) {
                Write-Host "SKIPPED (Protected): $($userInfo.DisplayName)" -ForegroundColor Yellow
                $skippedCount++
                continue
            }

            # Extra warning for protected accounts
            if ($userInfo.IsProtected) {
                Write-Host "WARNING: Updating protected account: $($userInfo.DisplayName)" -ForegroundColor Red
            }

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
            Set-ADUser -Identity $userInfo.User -SamAccountName $userInfo.NewSAM

            if ($userInfo.IsProtected) {
                Write-Host "Updated (PROTECTED): $($userInfo.DisplayName) - $($userInfo.CurrentSAM) -> $($userInfo.NewSAM)" -ForegroundColor Yellow
            } else {
                Write-Host "Updated: $($userInfo.DisplayName) - $($userInfo.CurrentSAM) -> $($userInfo.NewSAM)" -ForegroundColor Green
            }
            $successCount++
        }
        catch {
            Write-Host "Failed: $($userInfo.DisplayName) - Error: $_" -ForegroundColor Red
            $failedUsers += [PSCustomObject]@{
                User = $userInfo.DisplayName
                Error = $_.ToString()
            }
            $failedCount++
        }
    }

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Successfully updated: $successCount users" -ForegroundColor Green

    if ($skippedCount -gt 0) {
        Write-Host "Skipped (protected): $skippedCount users" -ForegroundColor Yellow
    }

    if ($failedCount -gt 0) {
        Write-Host "Failed to update: $failedCount users" -ForegroundColor Red

        if ($conflicts.Count -gt 0) {
            Write-Host "`nConflicts detected:" -ForegroundColor Red
            $conflicts | Format-Table -AutoSize
        }

        if ($failedUsers.Count -gt 0) {
            Write-Host "`nFailed updates:" -ForegroundColor Red
            $failedUsers | Format-Table -AutoSize
        }
    }
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
            $users = Get-UsersToUpdate
            if ($users) {
                Start-DryRun -UsersToUpdate $users

                if ($users.Count -gt 0) {
                    $protectedCount = ($users | Where-Object { $_.IsProtected -eq $true }).Count
                    if ($protectedCount -gt 0) {
                        Write-Host "`nWARNING: $protectedCount protected account(s) detected and will be skipped!" -ForegroundColor Red
                    }
                    Write-Host "`nDo you want to update these users now? (y/n): " -NoNewline -ForegroundColor Yellow
                    $proceed = Read-Host
                    if ($proceed -eq 'y' -or $proceed -eq 'Y') {
                        Update-Users -UsersToUpdate $users
                    }
                }
            }
            Write-Host "`nPress any key to continue..."
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        '2' {
            $ou = Read-Host "`nEnter OU Distinguished Name (e.g., OU=Users,DC=domain,DC=com)"
            Write-Host "Scanning users in specified OU..." -ForegroundColor Yellow
            $users = Get-UsersToUpdate -SearchBase $ou
            if ($users) {
                Start-DryRun -UsersToUpdate $users

                if ($users.Count -gt 0) {
                    $protectedCount = ($users | Where-Object { $_.IsProtected -eq $true }).Count
                    if ($protectedCount -gt 0) {
                        Write-Host "`nWARNING: $protectedCount protected account(s) detected and will be skipped!" -ForegroundColor Red
                    }
                    Write-Host "`nDo you want to update these users now? (y/n): " -NoNewline -ForegroundColor Yellow
                    $proceed = Read-Host
                    if ($proceed -eq 'y' -or $proceed -eq 'Y') {
                        Update-Users -UsersToUpdate $users
                    }
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
                $users = Get-UsersToUpdate
                if ($users) {
                    Update-Users -UsersToUpdate $users
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
                $users = Get-UsersToUpdate -SearchBase $ou
                if ($users) {
                    Update-Users -UsersToUpdate $users
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