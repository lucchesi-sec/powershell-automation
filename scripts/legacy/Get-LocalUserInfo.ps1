<#
.SYNOPSIS
    Retrieves detailed information about local user accounts.
.DESCRIPTION
    This script lists all local user accounts on the system and displays
    key properties such as their SID, enabled status, password policies,
    last logon time (if available), and group memberships.
.EXAMPLE
    .\Get-LocalUserInfo.ps1
    Displays information for all local users.
.EXAMPLE
    .\Get-LocalUserInfo.ps1 -UserName "JohnDoe"
    Displays information for the specified local user "JohnDoe".
.NOTES
    Author: Your Name
    Date: $(Get-Date)
    Requires Administrator privileges to get all information for all users.
    LastLogon times for local accounts might not always be accurate or available.
#>
param (
    [string]$UserName
)

Write-Host "Gathering Local User Information..." -ForegroundColor Yellow

try {
    if ($UserName) {
        $users = Get-LocalUser -Name $UserName -ErrorAction Stop
    } else {
        $users = Get-LocalUser -ErrorAction Stop
    }
}
catch {
    Write-Error "Failed to retrieve users. Ensure you have sufficient permissions. Error: $($_.Exception.Message)"
    exit 1
}

if (-not $users) {
    Write-Warning "No users found."
    exit 0
}

$allUserInfo = @()

foreach ($user in $users) {
    Write-Host "Processing user: $($user.Name)" -ForegroundColor Cyan
    $userInfo = [PSCustomObject]@{
        Name                = $user.Name
        FullName            = $user.FullName
        SID                 = $user.SID.Value
        Enabled             = $user.Enabled
        Description         = $user.Description
        PasswordLastSet     = if ($user.PasswordLastSet) { $user.PasswordLastSet } else { "N/A" }
        PasswordNeverExpires = $user.PasswordNeverExpires
        UserMayNotChangePassword = $user.UserMayNotChangePassword
        PasswordChangeableDate = if ($user.PasswordChangeableDate) { $user.PasswordChangeableDate } else { "N/A" }
        AccountExpires      = if ($user.AccountExpires) { $user.AccountExpires } else { "N/A" }
        LastLogon           = if ($user.LastLogon) { $user.LastLogon } else { "N/A (Often unreliable for local accounts)" }
    }

    # Get group memberships
    try {
        $groups = Get-LocalPrincipalGroupMembership -Principal $user.SID -ErrorAction SilentlyContinue
        if ($groups) {
            $userInfo | Add-Member -MemberType NoteProperty -Name "MemberOf" -Value ($groups.Name -join ", ")
        } else {
            $userInfo | Add-Member -MemberType NoteProperty -Name "MemberOf" -Value "None"
        }
    }
    catch {
        Write-Warning "Could not retrieve group membership for $($user.Name): $($_.Exception.Message)"
        $userInfo | Add-Member -MemberType NoteProperty -Name "MemberOf" -Value "Error retrieving"
    }
    
    $allUserInfo += $userInfo
}

Write-Host "`n--- All User Details ---" -ForegroundColor Green
$allUserInfo | Format-List

# If you prefer a table for some key info:
# $allUserInfo | Select-Object Name, Enabled, SID, MemberOf | Format-Table -AutoSize

Write-Host "`nLocal user information gathering complete." -ForegroundColor Green
