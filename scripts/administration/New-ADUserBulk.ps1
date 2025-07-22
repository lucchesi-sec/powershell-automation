<#
.SYNOPSIS
    Creates multiple Active Directory users from a CSV file with comprehensive configuration options.
.DESCRIPTION
    This script automates the bulk creation of Active Directory user accounts from a CSV file.
    It includes password generation, group membership assignment, and organizational unit placement.
    Supports dry-run mode for testing and comprehensive error handling.
.PARAMETER CsvPath
    Path to the CSV file containing user information.
    Required columns: FirstName, LastName, Username, Department, Title
    Optional columns: Email, Manager, Groups, OU, Password
.PARAMETER OrganizationalUnit
    Default OU where users will be created if not specified in CSV.
.PARAMETER DefaultPassword
    Default password for users if not specified in CSV. If not provided, random passwords are generated.
.PARAMETER Domain
    Domain name for user principal names. Defaults to current domain.
.PARAMETER DryRun
    If specified, shows what would be created without actually creating users.
.PARAMETER SendPasswordEmail
    If specified, sends password information to managers (requires email configuration).
.EXAMPLE
    .\New-ADUserBulk.ps1 -CsvPath "C:\NewUsers.csv" -OrganizationalUnit "OU=Users,DC=company,DC=com"
.EXAMPLE
    .\New-ADUserBulk.ps1 -CsvPath "C:\NewUsers.csv" -DryRun
.NOTES
    Author: System Administrator
    Requires: ActiveDirectory module, PSAdminCore module
    CSV Format Example:
    FirstName,LastName,Username,Department,Title,Email,Manager,Groups,OU
    John,Doe,jdoe,IT,Administrator,jdoe@company.com,jane.smith,IT-Admins;Users,"OU=IT,DC=company,DC=com"
#>

[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification='Plain text passwords are required for bulk user creation from CSV files and password generation')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$CsvPath,
    
    [Parameter(Mandatory = $false)]
    [string]$OrganizationalUnit = "CN=Users",
    
    [Parameter(Mandatory = $false)]
    [SecureString]$DefaultPassword,
    
    [Parameter(Mandatory = $false)]
    [string]$Domain = (Get-ADDomain).DNSRoot,
    
    [Parameter(Mandatory = $false)]
    [switch]$DryRun,
    
    [Parameter(Mandatory = $false)]
    [switch]$SendPasswordEmail
)

# Import required modules
Import-Module ActiveDirectory -ErrorAction Stop
Import-Module "$PSScriptRoot\..\..\modules\PSAdminCore\PSAdminCore.psm1" -Force

# Check administrative privileges
if (-not (Test-AdminPrivileges)) {
    Write-AdminLog -Message "This script requires administrative privileges" -Level "Error"
    exit 1
}

Write-AdminLog -Message "Starting bulk AD user creation from: $CsvPath" -Level "Info"

try {
    # Import and validate CSV data
    $userData = Import-Csv -Path $CsvPath
    Write-AdminLog -Message "Imported $($userData.Count) user records from CSV" -Level "Info"
    
    # Validate required columns
    $requiredColumns = @('FirstName', 'LastName', 'Username', 'Department', 'Title')
    $csvColumns = $userData[0].PSObject.Properties.Name
    
    foreach ($column in $requiredColumns) {
        if ($column -notin $csvColumns) {
            throw "Required column '$column' not found in CSV file"
        }
    }
    
    $results = @()
    $successCount = 0
    $failureCount = 0
    
    foreach ($user in $userData) {
        try {
            # Validate required fields
            if (-not (Test-AdminParameter -Value $user.Username -Type "NotEmpty")) {
                throw "Username is required"
            }
            
            # Check if user already exists
            if (Get-ADUser -Filter "SamAccountName -eq '$($user.Username)'" -ErrorAction SilentlyContinue) {
                throw "User '$($user.Username)' already exists"
            }
            
            # Determine OU
            $targetOU = if ($user.OU) { $user.OU } else { $OrganizationalUnit }
            
            # Generate password if not provided
            $userPassword = if ($user.Password) {
                ConvertTo-SecureString $user.Password -AsPlainText -Force
            } elseif ($DefaultPassword) {
                $DefaultPassword
            } else {
                # Generate random password
                $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"
                $randomPassword = -join ((1..12) | ForEach { $chars[(Get-Random -Maximum $chars.Length)] })
                ConvertTo-SecureString $randomPassword -AsPlainText -Force
            }
            
            # Prepare user properties
            $userParams = @{
                Name = "$($user.FirstName) $($user.LastName)"
                GivenName = $user.FirstName
                Surname = $user.LastName
                SamAccountName = $user.Username
                UserPrincipalName = "$($user.Username)@$Domain"
                Path = $targetOU
                AccountPassword = $userPassword
                Enabled = $true
                Department = $user.Department
                Title = $user.Title
                ChangePasswordAtLogon = $true
            }
            
            # Add optional properties
            if ($user.Email -and (Test-AdminParameter -Value $user.Email -Type "Email")) {
                $userParams.EmailAddress = $user.Email
            }
            
            if ($user.Manager) {
                $manager = Get-ADUser -Filter "SamAccountName -eq '$($user.Manager)'" -ErrorAction SilentlyContinue
                if ($manager) {
                    $userParams.Manager = $manager.DistinguishedName
                }
            }
            
            $result = [PSCustomObject]@{
                Username = $user.Username
                FullName = "$($user.FirstName) $($user.LastName)"
                Department = $user.Department
                Title = $user.Title
                OU = $targetOU
                Status = "Pending"
                Error = $null
                Groups = if ($user.Groups) { $user.Groups -split ';' } else { @() }
                GeneratedPassword = if (-not $user.Password -and -not $DefaultPassword) { 
                    [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($userPassword))
                } else { $null }
            }
            
            if ($DryRun) {
                $result.Status = "Would Create"
                Write-AdminLog -Message "DRY RUN: Would create user $($user.Username)" -Level "Info"
            } else {
                # Create the user
                New-ADUser @userParams
                $result.Status = "Created"
                $successCount++
                Write-AdminLog -Message "Created user: $($user.Username)" -Level "Success"
                
                # Add to groups if specified
                if ($user.Groups) {
                    $groups = $user.Groups -split ';'
                    foreach ($group in $groups) {
                        $group = $group.Trim()
                        if ($group) {
                            try {
                                Add-ADGroupMember -Identity $group -Members $user.Username
                                Write-AdminLog -Message "Added $($user.Username) to group: $group" -Level "Success"
                            } catch {
                                Write-AdminLog -Message "Failed to add $($user.Username) to group $group`: $($_.Exception.Message)" -Level "Warning"
                            }
                        }
                    }
                }
                
                # Send password email if requested
                if ($SendPasswordEmail -and $result.GeneratedPassword -and $user.Manager) {
                    $subject = "New User Account Created: $($user.Username)"
                    $body = @"
A new user account has been created:

Name: $($user.FirstName) $($user.LastName)
Username: $($user.Username)
Department: $($user.Department)
Title: $($user.Title)
Temporary Password: $($result.GeneratedPassword)

The user will be required to change their password at first login.
"@
                    $managerUser = Get-ADUser -Filter "SamAccountName -eq '$($user.Manager)'" -Properties EmailAddress
                    if ($managerUser -and $managerUser.EmailAddress) {
                        Send-AdminNotification -Subject $subject -Body $body -Recipients @($managerUser.EmailAddress)
                    }
                }
            }
            
            $results += $result
            
        } catch {
            $result = [PSCustomObject]@{
                Username = $user.Username
                FullName = "$($user.FirstName) $($user.LastName)"
                Department = $user.Department
                Title = $user.Title
                OU = $targetOU
                Status = "Failed"
                Error = $_.Exception.Message
                Groups = if ($user.Groups) { $user.Groups -split ';' } else { @() }
                GeneratedPassword = $null
            }
            $results += $result
            $failureCount++
            Write-AdminLog -Message "Failed to create user $($user.Username): $($_.Exception.Message)" -Level "Error"
        }
    }
    
    # Generate summary report
    $report = New-AdminReport -ReportTitle "Bulk AD User Creation Results" -Data $results -Description "Results of bulk Active Directory user creation operation" -Metadata @{
        CsvPath = $CsvPath
        DryRun = $DryRun.IsPresent
        TotalUsers = $userData.Count
        SuccessCount = $successCount
        FailureCount = $failureCount
        Domain = $Domain
        DefaultOU = $OrganizationalUnit
    }
    
    Write-Output $report
    
    # Summary
    if ($DryRun) {
        Write-AdminLog -Message "DRY RUN COMPLETE: Would process $($userData.Count) users" -Level "Info"
    } else {
        Write-AdminLog -Message "Bulk user creation complete. Success: $successCount, Failed: $failureCount" -Level "Success"
    }
    
} catch {
    Write-AdminLog -Message "Script execution failed: $($_.Exception.Message)" -Level "Error"
    throw
}