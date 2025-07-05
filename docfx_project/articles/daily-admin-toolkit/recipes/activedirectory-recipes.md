# ActiveDirectory Recipes

## Overview

The ActiveDirectory module provides essential user and group management functions for daily admin tasks. These recipes cover the most common scenarios sys admins encounter when managing Active Directory environments.

## Prerequisites

- **RSAT Tools** installed (Active Directory PowerShell module)
- **Domain Admin** or **delegated permissions** for user management
- **Network connectivity** to domain controllers
- **PowerShell execution policy** allowing module import

```powershell
# Verify AD PowerShell module is available
Get-Module -ListAvailable ActiveDirectory

# Import the Daily Admin Toolkit ActiveDirectory module
Import-Module ProjectName.ActiveDirectory
```

## Recipe 1: Unlock User Accounts

### Scenario
A user calls the help desk because they cannot log in. After multiple failed attempts, their account is locked out.

### Solution

```powershell
# Basic unlock operation
Unlock-ADAccount -Identity 'jdoe'

# Unlock with verification
Unlock-ADAccount -Identity 'jdoe' -Confirm:$false -Verbose

# Unlock multiple accounts from a list
$lockedUsers = @('jdoe', 'jsmith', 'bwilson')
$lockedUsers | ForEach-Object { 
    Unlock-ADAccount -Identity $_ -Verbose 
}

# Unlock with error handling
try {
    Unlock-ADAccount -Identity 'jdoe'
    Write-Host "✅ Account 'jdoe' unlocked successfully" -ForegroundColor Green
} catch {
    Write-Warning "❌ Failed to unlock account 'jdoe': $($_.Exception.Message)"
}
```

### Advanced Usage

```powershell
# Find and unlock all locked accounts in an OU
Search-ADAccount -LockedOut -SearchBase "OU=Users,DC=contoso,DC=com" | 
    Unlock-ADAccount -WhatIf

# Bulk unlock with logging
$results = @()
Get-Content "C:\Admin\LockedAccounts.txt" | ForEach-Object {
    try {
        Unlock-ADAccount -Identity $_ -ErrorAction Stop
        $results += [PSCustomObject]@{
            User = $_
            Status = "Success"
            Timestamp = Get-Date
        }
    } catch {
        $results += [PSCustomObject]@{
            User = $_
            Status = "Failed: $($_.Exception.Message)"
            Timestamp = Get-Date
        }
    }
}
$results | Export-Csv "C:\Admin\UnlockResults.csv" -NoTypeInformation
```

### Troubleshooting
- **Access Denied**: Verify you have unlock permissions
- **User Not Found**: Check spelling and domain context
- **Already Unlocked**: Account may not have been locked

## Recipe 2: Reset User Passwords

### Scenario
A user needs a password reset either due to forgotten password or security policy requirements.

### Solution

```powershell
# Generate secure random password
$newPassword = ConvertTo-SecureString "TempPass123!" -AsPlainText -Force
Reset-ADUserPassword -Identity 'jdoe' -NewPassword $newPassword -ChangePasswordAtLogon:$true

# Interactive password reset
$securePassword = Read-Host "Enter new password" -AsSecureString
Reset-ADUserPassword -Identity 'jdoe' -NewPassword $securePassword -ChangePasswordAtLogon:$true

# Reset with account unlock
Reset-ADUserPassword -Identity 'jdoe' -NewPassword $newPassword -ChangePasswordAtLogon:$true
Unlock-ADAccount -Identity 'jdoe'
```

### Advanced Usage

```powershell
# Function for secure password reset workflow
function Reset-UserPasswordSecurely {
    param(
        [Parameter(Mandatory)]
        [string]$Username,
        
        [switch]$ForceChangeAtLogon = $true,
        
        [switch]$UnlockAccount = $true
    )
    
    # Generate cryptographically secure password
    $password = [System.Web.Security.Membership]::GeneratePassword(12, 4)
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    
    try {
        # Reset password
        Reset-ADUserPassword -Identity $Username -NewPassword $securePassword -ChangePasswordAtLogon:$ForceChangeAtLogon
        
        # Unlock if requested
        if ($UnlockAccount) {
            Unlock-ADAccount -Identity $Username
        }
        
        # Return temporary password securely
        return @{
            Username = $Username
            TempPassword = $password
            PasswordExpires = (Get-Date).AddDays(1)
            Status = "Success"
        }
    } catch {
        return @{
            Username = $Username
            Status = "Failed: $($_.Exception.Message)"
        }
    }
}

# Usage
$result = Reset-UserPasswordSecurely -Username 'jdoe' -UnlockAccount
Write-Host "Temporary password for $($result.Username): $($result.TempPassword)" -ForegroundColor Yellow
```

### Security Best Practices

```powershell
# Secure password generation with complexity requirements
function New-SecurePassword {
    param([int]$Length = 16)
    
    $uppercase = 'ABCDEFGHKLMNOPRSTUVWXYZ'
    $lowercase = 'abcdefghiklmnoprstuvwxyz'
    $numbers = '1234567890'
    $symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?'
    
    $password = ''
    $password += Get-Random -InputObject $uppercase.ToCharArray()
    $password += Get-Random -InputObject $lowercase.ToCharArray()
    $password += Get-Random -InputObject $numbers.ToCharArray()
    $password += Get-Random -InputObject $symbols.ToCharArray()
    
    for ($i = 4; $i -lt $Length; $i++) {
        $allChars = $uppercase + $lowercase + $numbers + $symbols
        $password += Get-Random -InputObject $allChars.ToCharArray()
    }
    
    # Shuffle the password
    $passwordArray = $password.ToCharArray()
    $shuffled = $passwordArray | Get-Random -Count $passwordArray.Length
    return -join $shuffled
}
```

## Recipe 3: Check User Last Logon

### Scenario
You need to determine when a user last logged in, possibly across multiple domain controllers, for security auditing or account cleanup.

### Solution

```powershell
# Check last logon on current DC
Get-ADUserLastLogon -Identity 'jdoe'

# Check across all domain controllers
Get-ADUserLastLogon -Identity 'jdoe' -AllDomainControllers

# Check multiple users
$users = @('jdoe', 'jsmith', 'bwilson')
$users | ForEach-Object { Get-ADUserLastLogon -Identity $_ }

# Get last logon with detailed information
Get-ADUserLastLogon -Identity 'jdoe' -IncludeDetails | Format-Table -AutoSize
```

### Advanced Usage

```powershell
# Find inactive users (no logon in 90 days)
$cutoffDate = (Get-Date).AddDays(-90)
Get-ADUser -Filter * -Properties LastLogonDate | 
    Where-Object { 
        $_.LastLogonDate -lt $cutoffDate -or $_.LastLogonDate -eq $null 
    } | 
    Select-Object Name, SamAccountName, LastLogonDate, Enabled |
    Sort-Object LastLogonDate

# Comprehensive user activity report
function Get-UserActivityReport {
    param(
        [Parameter(Mandatory)]
        [string[]]$UserList,
        
        [int]$DaysBack = 30
    )
    
    $results = @()
    $cutoffDate = (Get-Date).AddDays(-$DaysBack)
    
    foreach ($user in $UserList) {
        try {
            $lastLogon = Get-ADUserLastLogon -Identity $user -AllDomainControllers
            $adUser = Get-ADUser -Identity $user -Properties LastLogonDate, PasswordLastSet, Enabled
            
            $results += [PSCustomObject]@{
                Username = $user
                LastLogon = $lastLogon.LastLogon
                DomainController = $lastLogon.DomainController
                LastLogonDate = $adUser.LastLogonDate
                PasswordLastSet = $adUser.PasswordLastSet
                Enabled = $adUser.Enabled
                DaysSinceLogon = if ($lastLogon.LastLogon) { 
                    (New-TimeSpan -Start $lastLogon.LastLogon -End (Get-Date)).Days 
                } else { 
                    "Never" 
                }
                Status = if ($lastLogon.LastLogon -gt $cutoffDate) { "Active" } 
                        elseif ($lastLogon.LastLogon) { "Inactive" } 
                        else { "Never Logged In" }
            }
        } catch {
            $results += [PSCustomObject]@{
                Username = $user
                Status = "Error: $($_.Exception.Message)"
            }
        }
    }
    
    return $results
}

# Usage
$userReport = Get-UserActivityReport -UserList @('jdoe', 'jsmith') -DaysBack 60
$userReport | Format-Table -AutoSize
```
## Recipe 4: Get User Group Membership

### Scenario
You need to audit user permissions by examining group memberships, either for security reviews or troubleshooting access issues.

### Solution

```powershell
# Get basic group membership
Get-ADUserMembership -Identity 'jdoe'

# Get membership with group details
Get-ADUserMembership -Identity 'jdoe' -IncludeDetails | Format-Table -AutoSize

# Get membership for multiple users
$users = @('jdoe', 'jsmith', 'bwilson')
$users | ForEach-Object { 
    Write-Host "Groups for $_:" -ForegroundColor Yellow
    Get-ADUserMembership -Identity $_ | Format-Table -AutoSize
}

# Export group membership to CSV
Get-ADUserMembership -Identity 'jdoe' -IncludeDetails | 
    Export-Csv "C:\Admin\UserGroups_jdoe.csv" -NoTypeInformation
```

### Advanced Usage

```powershell
# Compare group memberships between users
function Compare-UserGroupMembership {
    param(
        [Parameter(Mandatory)]
        [string]$User1,
        
        [Parameter(Mandatory)]
        [string]$User2
    )
    
    $user1Groups = Get-ADUserMembership -Identity $User1 | Select-Object -ExpandProperty Name
    $user2Groups = Get-ADUserMembership -Identity $User2 | Select-Object -ExpandProperty Name
    
    $comparison = Compare-Object -ReferenceObject $user1Groups -DifferenceObject $user2Groups -IncludeEqual
    
    $results = @{
        User1Only = $comparison | Where-Object { $_.SideIndicator -eq '<=' } | Select-Object -ExpandProperty InputObject
        User2Only = $comparison | Where-Object { $_.SideIndicator -eq '=>' } | Select-Object -ExpandProperty InputObject
        Common = $comparison | Where-Object { $_.SideIndicator -eq '==' } | Select-Object -ExpandProperty InputObject
    }
    
    return $results
}

# Bulk group membership audit
function Get-BulkGroupMembership {
    param(
        [Parameter(Mandatory)]
        [string[]]$UserList,
        
        [string]$ExportPath = "C:\Admin\GroupMembershipAudit.csv"
    )
    
    $results = @()
    
    foreach ($user in $UserList) {
        try {
            $groups = Get-ADUserMembership -Identity $user
            foreach ($group in $groups) {
                $results += [PSCustomObject]@{
                    Username = $user
                    GroupName = $group.Name
                    GroupType = $group.GroupCategory
                    GroupScope = $group.GroupScope
                    AuditDate = Get-Date
                }
            }
        } catch {
            $results += [PSCustomObject]@{
                Username = $user
                GroupName = "ERROR"
                Error = $_.Exception.Message
                AuditDate = Get-Date
            }
        }
    }
    
    $results | Export-Csv $ExportPath -NoTypeInformation
    return $results
}

# Find users with specific group membership
function Find-UsersInGroup {
    param(
        [Parameter(Mandatory)]
        [string]$GroupName,
        
        [string]$SearchBase = $null
    )
    
    $searchParams = @{
        Filter = { memberOf -eq (Get-ADGroup $GroupName).DistinguishedName }
        Properties = 'LastLogonDate', 'Enabled', 'Department'
    }
    
    if ($SearchBase) {
        $searchParams.SearchBase = $SearchBase
    }
    
    Get-ADUser @searchParams | 
        Select-Object Name, SamAccountName, Department, LastLogonDate, Enabled |
        Sort-Object Name
}
```

### Security Auditing Scenarios

```powershell
# Find users with administrative group memberships
$adminGroups = @(
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators'
)

foreach ($group in $adminGroups) {
    Write-Host "Members of $group:" -ForegroundColor Red
    try {
        Find-UsersInGroup -GroupName $group | Format-Table -AutoSize
    } catch {
        Write-Warning "Could not query group: $group"
    }
}

# Identify orphaned group memberships
function Find-OrphanedGroupMemberships {
    param(
        [Parameter(Mandatory)]
        [string]$Username
    )
    
    $userGroups = Get-ADUserMembership -Identity $Username
    $orphanedGroups = @()
    
    foreach ($group in $userGroups) {
        try {
            # Check if group still exists and is valid
            $groupCheck = Get-ADGroup -Identity $group.SamAccountName -ErrorAction Stop
            
            # Check if group is in expected OUs
            if ($groupCheck.DistinguishedName -like "*CN=Builtin*" -or 
                $groupCheck.DistinguishedName -like "*OU=Disabled*") {
                $orphanedGroups += $group
            }
        } catch {
            $orphanedGroups += $group
        }
    }
    
    return $orphanedGroups
}
```

## Common Parameters and Options

### Standard Parameters

All Daily Admin Toolkit ActiveDirectory functions support these common parameters:

```powershell
# Confirm actions before execution
Unlock-ADAccount -Identity 'jdoe' -Confirm

# Show what would happen without making changes
Reset-ADUserPassword -Identity 'jdoe' -WhatIf

# Verbose output for troubleshooting
Get-ADUserLastLogon -Identity 'jdoe' -Verbose

# Error handling
Get-ADUserMembership -Identity 'jdoe' -ErrorAction SilentlyContinue
```

### Pipeline Support

Functions are designed to work with PowerShell pipelines:

```powershell
# Pipeline multiple operations
Get-Content "LockedUsers.txt" | 
    ForEach-Object { Unlock-ADAccount -Identity $_ } |
    ForEach-Object { Get-ADUserLastLogon -Identity $_.SamAccountName }

# Filter and process results
Get-ADUser -Filter * | 
    Where-Object { $_.Enabled -eq $false } |
    Select-Object -First 10 |
    ForEach-Object { Get-ADUserMembership -Identity $_.SamAccountName }
```

## Error Handling and Troubleshooting

### Common Error Scenarios

```powershell
# Handle common errors gracefully
function Safe-ADOperation {
    param(
        [Parameter(Mandatory)]
        [string]$Username,
        
        [Parameter(Mandatory)]
        [scriptblock]$Operation
    )
    
    try {
        $result = & $Operation
        return @{
            Success = $true
            Result = $result
            User = $Username
        }
    } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        return @{
            Success = $false
            Error = "User '$Username' not found"
            User = $Username
        }
    } catch [System.UnauthorizedAccessException] {
        return @{
            Success = $false
            Error = "Access denied. Check permissions."
            User = $Username
        }
    } catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
            User = $Username
        }
    }
}

# Usage example
$result = Safe-ADOperation -Username 'jdoe' -Operation {
    Unlock-ADAccount -Identity 'jdoe'
}

if ($result.Success) {
    Write-Host "✅ Operation successful for $($result.User)" -ForegroundColor Green
} else {
    Write-Warning "❌ Operation failed for $($result.User): $($result.Error)"
}
```

### Diagnostic Functions

```powershell
# Test AD connectivity and permissions
function Test-ADEnvironment {
    $tests = @()
    
    # Test 1: AD Module availability
    $tests += @{
        Test = "AD PowerShell Module"
        Result = if (Get-Module -ListAvailable ActiveDirectory) { "✅ Available" } else { "❌ Not installed" }
    }
    
    # Test 2: Domain connectivity
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $tests += @{
            Test = "Domain Connectivity"
            Result = "✅ Connected to $($domain.DNSRoot)"
        }
    } catch {
        $tests += @{
            Test = "Domain Connectivity"
            Result = "❌ Cannot connect to domain"
        }
    }
    
    # Test 3: Basic permissions
    try {
        Get-ADUser -LDAPFilter "(sAMAccountName=$env:USERNAME)" -ErrorAction Stop | Out-Null
        $tests += @{
            Test = "Read Permissions"
            Result = "✅ Can read AD objects"
        }
    } catch {
        $tests += @{
            Test = "Read Permissions"
            Result = "❌ Cannot read AD objects"
        }
    }
    
    return $tests
}

# Run diagnostics
Test-ADEnvironment | Format-Table Test, Result -AutoSize
```

## Best Practices Summary

1. **Always use `-WhatIf`** when testing new scripts
2. **Implement proper error handling** for production use
3. **Use pipeline-friendly functions** for efficiency
4. **Log important operations** for audit trails
5. **Test permissions** before bulk operations
6. **Use secure password generation** methods
7. **Validate input parameters** before processing
8. **Follow principle of least privilege** for service accounts

## Integration Examples

### With Monitoring Systems

```powershell
# SCOM integration example
function Send-SCOMAlert {
    param($Message, $Severity = "Information")
    # Integration with System Center Operations Manager
    # Implementation depends on your SCOM setup
}

# Enhanced unlock with monitoring
Unlock-ADAccount -Identity 'jdoe'
Send-SCOMAlert -Message "Account jdoe unlocked by $env:USERNAME" -Severity "Information"
```

### With Ticketing Systems

```powershell
# ServiceNow API integration example
function Update-ServiceNowTicket {
    param($TicketNumber, $Status, $Notes)
    # Implementation for ServiceNow REST API
}

# Process help desk tickets
$ticketNumber = "INC123456"
Unlock-ADAccount -Identity 'jdoe'
Update-ServiceNowTicket -TicketNumber $ticketNumber -Status "Resolved" -Notes "Account unlocked successfully"
```

---

> **Next Steps**: Explore [ServerManagement Recipes](servermanagement-recipes.md) for server health monitoring and maintenance tasks.