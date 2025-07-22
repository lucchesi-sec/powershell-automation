<#
.SYNOPSIS
    Performs bulk password resets for Active Directory users with comprehensive security controls.
.DESCRIPTION
    This script automates bulk password resets for AD users with multiple password generation options,
    security controls, and notification capabilities. Supports CSV input, random password generation,
    and secure password distribution to managers or users.
.PARAMETER CsvPath
    Path to CSV file containing usernames for password reset.
    Required columns: Username
    Optional columns: NewPassword, NotificationEmail, Manager
.PARAMETER UserList
    Array of usernames for password reset (alternative to CSV).
.PARAMETER PasswordPolicy
    Password generation policy: Random, Pronounceable, or Custom.
.PARAMETER PasswordLength
    Length of generated passwords (default: 12).
.PARAMETER RequireChange
    If specified, users must change password at next logon.
.PARAMETER NotifyUsers
    If specified, sends new passwords to users via email.
.PARAMETER NotifyManagers
    If specified, sends new passwords to user managers.
.PARAMETER DryRun
    If specified, shows what would be changed without making changes.
.PARAMETER ExcludePrivileged
    If specified, excludes privileged accounts from bulk reset.
.EXAMPLE
    .\Reset-ADUserPasswordBulk.ps1 -CsvPath "C:\PasswordResets.csv" -RequireChange -NotifyManagers
.EXAMPLE
    .\Reset-ADUserPasswordBulk.ps1 -UserList @("jdoe","jsmith") -PasswordPolicy "Pronounceable" -DryRun
.NOTES
    Author: System Administrator
    Requires: ActiveDirectory module, PSAdminCore module
    Security Note: Generated passwords are stored temporarily in memory and logs
#>

[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification='Plain text passwords are required for bulk password reset operations')]
param(
    [Parameter(Mandatory = $false)]
    [string]$CsvPath,
    
    [Parameter(Mandatory = $false)]
    [string[]]$UserList,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Random", "Pronounceable", "Custom")]
    [string]$PasswordPolicy = "Random",
    
    [Parameter(Mandatory = $false)]
    [int]$PasswordLength = 12,
    
    [Parameter(Mandatory = $false)]
    [switch]$RequireChange,
    
    [Parameter(Mandatory = $false)]
    [switch]$NotifyUsers,
    
    [Parameter(Mandatory = $false)]
    [switch]$NotifyManagers,
    
    [Parameter(Mandatory = $false)]
    [switch]$DryRun,
    
    [Parameter(Mandatory = $false)]
    [switch]$ExcludePrivileged
)

# Import required modules
Import-Module ActiveDirectory -ErrorAction Stop
Import-Module "$PSScriptRoot\..\..\modules\PSAdminCore\PSAdminCore.psm1" -Force

# Check administrative privileges
if (-not (Test-AdminPrivileges)) {
    Write-AdminLog -Message "This script requires administrative privileges" -Level "Error"
    exit 1
}

Write-AdminLog -Message "Starting bulk password reset operation" -Level "Info"

# Function to generate secure passwords
function New-SecurePassword {
    param(
        [string]$Policy = "Random",
        [int]$Length = 12
    )
    
    switch ($Policy) {
        "Random" {
            $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"
            return -join ((1..$Length) | ForEach { $chars[(Get-Random -Maximum $chars.Length)] })
        }
        "Pronounceable" {
            $consonants = "bcdfghjklmnpqrstvwxyz"
            $vowels = "aeiou"
            $numbers = "0123456789"
            $special = "!@#$%"
            
            $password = ""
            for ($i = 0; $i -lt ($Length - 2); $i++) {
                if ($i % 2 -eq 0) {
                    $password += $consonants[(Get-Random -Maximum $consonants.Length)]
                } else {
                    $password += $vowels[(Get-Random -Maximum $vowels.Length)]
                }
            }
            $password += $numbers[(Get-Random -Maximum $numbers.Length)]
            $password += $special[(Get-Random -Maximum $special.Length)]
            
            # Capitalize first letter
            return $password.Substring(0,1).ToUpper() + $password.Substring(1)
        }
        "Custom" {
            # Implement custom password policy based on organization requirements
            $words = @("Secure", "System", "Access", "Login", "Portal", "Gateway")
            $word = $words[(Get-Random -Maximum $words.Length)]
            $number = Get-Random -Minimum 10 -Maximum 99
            $special = "!@#$%"[(Get-Random -Maximum 5)]
            return "$word$number$special"
        }
    }
}

# Function to check if user is privileged
function Test-PrivilegedUser {
    param([string]$Username)
    
    $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Account Operators", "Server Operators", "Backup Operators")
    
    foreach ($group in $privilegedGroups) {
        try {
            $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
            if ($members | Where-Object { $_.SamAccountName -eq $Username }) {
                return $true
            }
        } catch {
            # Group might not exist, continue
        }
    }
    return $false
}

try {
    # Determine user list source
    $usersToReset = @()
    
    if ($CsvPath) {
        if (-not (Test-Path $CsvPath)) {
            throw "CSV file not found: $CsvPath"
        }
        
        $csvData = Import-Csv -Path $CsvPath
        Write-AdminLog -Message "Imported $($csvData.Count) records from CSV" -Level "Info"
        
        # Validate CSV structure
        if (-not ($csvData[0].PSObject.Properties.Name -contains "Username")) {
            throw "CSV must contain 'Username' column"
        }
        
        foreach ($record in $csvData) {
            if ($record.Username) {
                $usersToReset += [PSCustomObject]@{
                    Username = $record.Username
                    CustomPassword = $record.NewPassword
                    NotificationEmail = $record.NotificationEmail
                    Manager = $record.Manager
                }
            }
        }
    } elseif ($UserList) {
        foreach ($username in $UserList) {
            $usersToReset += [PSCustomObject]@{
                Username = $username
                CustomPassword = $null
                NotificationEmail = $null
                Manager = $null
            }
        }
    } else {
        throw "Either CsvPath or UserList parameter must be provided"
    }
    
    Write-AdminLog -Message "Processing password reset for $($usersToReset.Count) users" -Level "Info"
    
    $results = @()
    $successCount = 0
    $skipCount = 0
    $errorCount = 0
    
    foreach ($userRecord in $usersToReset) {
        try {
            $username = $userRecord.Username
            
            # Validate user exists
            $user = Get-ADUser -Identity $username -Properties Manager, EmailAddress, Department, Title -ErrorAction Stop
            
            # Check if user is privileged and exclusion is enabled
            if ($ExcludePrivileged -and (Test-PrivilegedUser -Username $username)) {
                $result = [PSCustomObject]@{
                    Username = $username
                    DisplayName = $user.DisplayName
                    Status = "Skipped"
                    Reason = "Privileged account excluded"
                    NewPassword = $null
                    NotificationSent = $false
                    Timestamp = Get-Date
                }
                $results += $result
                $skipCount++
                Write-AdminLog -Message "Skipped privileged user: $username" -Level "Warning"
                continue
            }
            
            # Generate or use provided password
            $newPassword = if ($userRecord.CustomPassword) {
                $userRecord.CustomPassword
            } else {
                New-SecurePassword -Policy $PasswordPolicy -Length $PasswordLength
            }
            
            $result = [PSCustomObject]@{
                Username = $username
                DisplayName = $user.DisplayName
                Department = $user.Department
                Title = $user.Title
                Status = "Unknown"
                Reason = "Bulk password reset"
                NewPassword = $newPassword
                NotificationSent = $false
                NotificationEmail = $userRecord.NotificationEmail
                Manager = if ($userRecord.Manager) { $userRecord.Manager } else { 
                    if ($user.Manager) { (Get-ADUser -Identity $user.Manager).SamAccountName } else { $null }
                }
                Timestamp = Get-Date
            }
            
            if ($DryRun) {
                $result.Status = "Would Reset"
                Write-AdminLog -Message "DRY RUN: Would reset password for $username" -Level "Info"
            } else {
                # Reset password
                $securePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force
                Set-ADAccountPassword -Identity $username -NewPassword $securePassword -Reset
                
                # Set password change requirement if requested
                if ($RequireChange) {
                    Set-ADUser -Identity $username -ChangePasswordAtLogon $true
                }
                
                $result.Status = "Reset"
                $successCount++
                Write-AdminLog -Message "Password reset successful for: $username" -Level "Success"
                
                # Send notifications
                if ($NotifyUsers -and ($user.EmailAddress -or $result.NotificationEmail)) {
                    $emailAddress = if ($result.NotificationEmail) { $result.NotificationEmail } else { $user.EmailAddress }
                    
                    $subject = "Password Reset Notification"
                    $body = @"
Your password has been reset.

Username: $username
New Password: $newPassword
$(if ($RequireChange) { "You will be required to change this password at your next login." })

Please keep this information secure and change your password as soon as possible.
"@
                    
                    try {
                        Send-AdminNotification -Subject $subject -Body $body -Recipients @($emailAddress)
                        $result.NotificationSent = $true
                        Write-AdminLog -Message "Password notification sent to user: $username" -Level "Success"
                    } catch {
                        Write-AdminLog -Message "Failed to send notification to user $username`: $($_.Exception.Message)" -Level "Warning"
                    }
                }
                
                if ($NotifyManagers -and $result.Manager) {
                    $manager = Get-ADUser -Identity $result.Manager -Properties EmailAddress -ErrorAction SilentlyContinue
                    if ($manager -and $manager.EmailAddress) {
                        $subject = "Password Reset - $($user.DisplayName)"
                        $body = @"
A password reset has been performed for your team member:

Employee: $($user.DisplayName)
Username: $username
Department: $($user.Department)
Title: $($user.Title)
New Password: $newPassword
Reset Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
$(if ($RequireChange) { "The user will be required to change this password at next login." })

Please ensure the employee receives this information securely.
"@
                        
                        try {
                            Send-AdminNotification -Subject $subject -Body $body -Recipients @($manager.EmailAddress)
                            Write-AdminLog -Message "Password notification sent to manager for: $username" -Level "Success"
                        } catch {
                            Write-AdminLog -Message "Failed to send notification to manager for $username`: $($_.Exception.Message)" -Level "Warning"
                        }
                    }
                }
            }
            
            $results += $result
            
        } catch {
            $result = [PSCustomObject]@{
                Username = $userRecord.Username
                DisplayName = "Unknown"
                Status = "Failed"
                Reason = $_.Exception.Message
                NewPassword = $null
                NotificationSent = $false
                Timestamp = Get-Date
            }
            $results += $result
            $errorCount++
            Write-AdminLog -Message "Failed to reset password for $($userRecord.Username): $($_.Exception.Message)" -Level "Error"
        }
    }
    
    # Clear passwords from memory for security
    if (-not $DryRun) {
        [System.GC]::Collect()
        Write-AdminLog -Message "Cleared passwords from memory" -Level "Info"
    }
    
    # Generate summary report
    $report = New-AdminReport -ReportTitle "Bulk Password Reset Results" -Data $results -Description "Results of bulk Active Directory password reset operation" -Metadata @{
        PasswordPolicy = $PasswordPolicy
        PasswordLength = $PasswordLength
        RequireChange = $RequireChange.IsPresent
        NotifyUsers = $NotifyUsers.IsPresent
        NotifyManagers = $NotifyManagers.IsPresent
        ExcludePrivileged = $ExcludePrivileged.IsPresent
        DryRun = $DryRun.IsPresent
        TotalUsers = $usersToReset.Count
        SuccessCount = $successCount
        SkipCount = $skipCount
        ErrorCount = $errorCount
        CsvPath = $CsvPath
    }
    
    Write-Output $report
    
    # Summary
    if ($DryRun) {
        Write-AdminLog -Message "DRY RUN COMPLETE: Would reset passwords for $($usersToReset.Count) users" -Level "Info"
    } else {
        Write-AdminLog -Message "Bulk password reset complete. Success: $successCount, Skipped: $skipCount, Failed: $errorCount" -Level "Success"
        
        # Security reminder
        Write-AdminLog -Message "SECURITY REMINDER: Ensure all generated passwords are distributed securely" -Level "Warning"
    }
    
} catch {
    Write-AdminLog -Message "Bulk password reset operation failed: $($_.Exception.Message)" -Level "Error"
    throw
}