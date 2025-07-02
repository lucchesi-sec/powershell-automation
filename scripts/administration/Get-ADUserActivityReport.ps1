<#
.SYNOPSIS
    Generates comprehensive Active Directory user activity reports with security insights.
.DESCRIPTION
    This script creates detailed reports on user activity including logon patterns, failed attempts,
    account changes, and security events. Supports multiple output formats and automated scheduling.
    Provides insights for security monitoring, compliance auditing, and user behavior analysis.
.PARAMETER ReportType
    Type of report to generate: Summary, Detailed, SecurityFocus, or Compliance.
.PARAMETER Days
    Number of days to look back for activity data (default: 30).
.PARAMETER OutputPath
    Directory to save the generated reports.
.PARAMETER Format
    Output format: JSON, CSV, HTML, or All.
.PARAMETER IncludeInactive
    If specified, includes analysis of inactive user accounts.
.PARAMETER SecurityThreshold
    Number of failed logon attempts to flag as suspicious (default: 5).
.PARAMETER EmailReport
    If specified, emails the report to configured recipients.
.EXAMPLE
    .\Get-ADUserActivityReport.ps1 -ReportType "SecurityFocus" -Days 7 -Format "HTML"
.EXAMPLE
    .\Get-ADUserActivityReport.ps1 -ReportType "Compliance" -Days 90 -EmailReport
.NOTES
    Author: System Administrator
    Requires: ActiveDirectory module, PSAdminCore module, appropriate event log permissions
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Summary", "Detailed", "SecurityFocus", "Compliance")]
    [string]$ReportType = "Summary",
    
    [Parameter(Mandatory = $false)]
    [int]$Days = 30,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:TEMP\ADReports",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("JSON", "CSV", "HTML", "All")]
    [string]$Format = "JSON",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeInactive,
    
    [Parameter(Mandatory = $false)]
    [int]$SecurityThreshold = 5,
    
    [Parameter(Mandatory = $false)]
    [switch]$EmailReport
)

# Import required modules
Import-Module ActiveDirectory -ErrorAction Stop
Import-Module "$PSScriptRoot\..\..\modules\PSAdminCore\PSAdminCore.psm1" -Force

# Check administrative privileges
if (-not (Test-AdminPrivileges)) {
    Write-AdminLog -Message "This script requires administrative privileges" -Level "Error"
    exit 1
}

Write-AdminLog -Message "Starting AD user activity report generation (Type: $ReportType, Days: $Days)" -Level "Info"

try {
    # Create output directory
    if (-not (Test-Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }
    
    $startDate = (Get-Date).AddDays(-$Days)
    $reportData = @{}
    
    # Get all users with extended properties
    Write-AdminLog -Message "Retrieving user accounts from Active Directory..." -Level "Info"
    $users = Get-ADUser -Filter * -Properties LastLogonDate, LastBadPasswordAttempt, BadPwdCount, PasswordLastSet, 
                                              whenCreated, whenChanged, AccountExpirationDate, LockedOut, Enabled,
                                              Department, Title, Manager, Description, City, Company
    
    Write-AdminLog -Message "Retrieved $($users.Count) user accounts" -Level "Info"
    
    # Get domain controllers for event log queries
    $domainControllers = Get-ADDomainController -Filter *
    
    switch ($ReportType) {
        "Summary" {
            Write-AdminLog -Message "Generating summary report..." -Level "Info"
            
            $reportData = @{
                ReportType = "Summary"
                GeneratedDate = Get-Date
                Period = "$Days days"
                TotalUsers = $users.Count
                ActiveUsers = ($users | Where-Object { $_.Enabled -eq $true }).Count
                InactiveUsers = ($users | Where-Object { $_.Enabled -eq $false }).Count
                LockedUsers = ($users | Where-Object { $_.LockedOut -eq $true }).Count
                RecentLogons = ($users | Where-Object { $_.LastLogonDate -gt $startDate }).Count
                ExpiringSoon = ($users | Where-Object { 
                    $_.AccountExpirationDate -and $_.AccountExpirationDate -lt (Get-Date).AddDays(30) 
                }).Count
                NeverLoggedOn = ($users | Where-Object { -not $_.LastLogonDate }).Count
                PasswordExpiring = @()
                DepartmentBreakdown = $users | Group-Object Department | Select-Object Name, Count
                RecentlyCreated = ($users | Where-Object { $_.whenCreated -gt $startDate }).Count
                RecentlyModified = ($users | Where-Object { $_.whenChanged -gt $startDate }).Count
            }
        }
        
        "Detailed" {
            Write-AdminLog -Message "Generating detailed report..." -Level "Info"
            
            $userDetails = foreach ($user in $users) {
                [PSCustomObject]@{
                    Username = $user.SamAccountName
                    DisplayName = $user.DisplayName
                    Enabled = $user.Enabled
                    LastLogon = $user.LastLogonDate
                    DaysSinceLastLogon = if ($user.LastLogonDate) { 
                        [math]::Round((Get-Date - $user.LastLogonDate).TotalDays, 0) 
                    } else { "Never" }
                    PasswordLastSet = $user.PasswordLastSet
                    DaysSincePasswordChange = if ($user.PasswordLastSet) { 
                        [math]::Round((Get-Date - $user.PasswordLastSet).TotalDays, 0) 
                    } else { "Never" }
                    AccountCreated = $user.whenCreated
                    LastModified = $user.whenChanged
                    Department = $user.Department
                    Title = $user.Title
                    Manager = if ($user.Manager) { 
                        (Get-ADUser -Identity $user.Manager -ErrorAction SilentlyContinue).DisplayName 
                    } else { $null }
                    LockedOut = $user.LockedOut
                    BadPasswordCount = $user.BadPwdCount
                    LastBadPassword = $user.LastBadPasswordAttempt
                    AccountExpires = $user.AccountExpirationDate
                    Groups = (Get-ADPrincipalGroupMembership -Identity $user.SamAccountName -ErrorAction SilentlyContinue | 
                             Select-Object -ExpandProperty Name) -join '; '
                }
            }
            
            $reportData = @{
                ReportType = "Detailed"
                GeneratedDate = Get-Date
                Period = "$Days days"
                UserDetails = $userDetails
                Summary = @{
                    TotalUsers = $users.Count
                    ActiveUsers = ($userDetails | Where-Object { $_.Enabled -eq $true }).Count
                    RecentActivity = ($userDetails | Where-Object { 
                        $_.LastLogon -and $_.LastLogon -gt $startDate 
                    }).Count
                }
            }
        }
        
        "SecurityFocus" {
            Write-AdminLog -Message "Generating security-focused report..." -Level "Info"
            
            # Get security events from domain controllers
            $securityEvents = @()
            foreach ($dc in $domainControllers) {
                try {
                    Write-AdminLog -Message "Querying security events from $($dc.Name)..." -Level "Info"
                    
                    # Failed logon attempts (Event ID 4625)
                    $failedLogons = Get-WinEvent -ComputerName $dc.Name -FilterHashtable @{
                        LogName = 'Security'
                        ID = 4625
                        StartTime = $startDate
                    } -MaxEvents 1000 -ErrorAction SilentlyContinue
                    
                    # Successful logons (Event ID 4624)
                    $successfulLogons = Get-WinEvent -ComputerName $dc.Name -FilterHashtable @{
                        LogName = 'Security'
                        ID = 4624
                        StartTime = $startDate
                    } -MaxEvents 1000 -ErrorAction SilentlyContinue
                    
                    # Account lockouts (Event ID 4740)
                    $lockouts = Get-WinEvent -ComputerName $dc.Name -FilterHashtable @{
                        LogName = 'Security'
                        ID = 4740
                        StartTime = $startDate
                    } -MaxEvents 100 -ErrorAction SilentlyContinue
                    
                    $securityEvents += @{
                        DomainController = $dc.Name
                        FailedLogons = $failedLogons.Count
                        SuccessfulLogons = $successfulLogons.Count
                        Lockouts = $lockouts.Count
                    }
                } catch {
                    Write-AdminLog -Message "Could not retrieve events from $($dc.Name): $($_.Exception.Message)" -Level "Warning"
                }
            }
            
            # Identify suspicious users
            $suspiciousUsers = $users | Where-Object { 
                $_.BadPwdCount -ge $SecurityThreshold -or 
                $_.LockedOut -eq $true -or
                ($_.LastBadPasswordAttempt -and $_.LastBadPasswordAttempt -gt $startDate)
            } | Select-Object SamAccountName, DisplayName, BadPwdCount, LockedOut, LastBadPasswordAttempt, LastLogonDate
            
            # Inactive but enabled accounts
            $staleAccounts = $users | Where-Object { 
                $_.Enabled -eq $true -and 
                ($_.LastLogonDate -lt $startDate -or -not $_.LastLogonDate)
            } | Select-Object SamAccountName, DisplayName, LastLogonDate, whenCreated, Department
            
            $reportData = @{
                ReportType = "SecurityFocus"
                GeneratedDate = Get-Date
                Period = "$Days days"
                SecurityThreshold = $SecurityThreshold
                SuspiciousUsers = $suspiciousUsers
                StaleAccounts = $staleAccounts
                SecurityEvents = $securityEvents
                Summary = @{
                    SuspiciousUserCount = $suspiciousUsers.Count
                    StaleAccountCount = $staleAccounts.Count
                    TotalFailedLogons = ($securityEvents | Measure-Object FailedLogons -Sum).Sum
                    TotalLockouts = ($securityEvents | Measure-Object Lockouts -Sum).Sum
                }
                Recommendations = @(
                    "Review accounts with $SecurityThreshold+ failed logon attempts",
                    "Disable or remove stale accounts that haven't logged in recently",
                    "Implement account lockout policies if not already in place",
                    "Monitor for unusual logon patterns and times",
                    "Regular password policy compliance checks"
                )
            }
        }
        
        "Compliance" {
            Write-AdminLog -Message "Generating compliance report..." -Level "Info"
            
            # Password policy compliance
            $passwordPolicy = Get-ADDefaultDomainPasswordPolicy
            $usersPasswordExpiring = $users | Where-Object { 
                $_.PasswordLastSet -and 
                $_.PasswordLastSet.AddDays($passwordPolicy.MaxPasswordAge.Days) -lt (Get-Date).AddDays(30)
            }
            
            # Account expiration compliance
            $accountsExpiring = $users | Where-Object { 
                $_.AccountExpirationDate -and $_.AccountExpirationDate -lt (Get-Date).AddDays(30) 
            }
            
            # Privileged accounts
            $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
            $privilegedUsers = @()
            foreach ($group in $privilegedGroups) {
                try {
                    $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
                    foreach ($member in $members) {
                        if ($member.objectClass -eq "user") {
                            $user = Get-ADUser -Identity $member.SamAccountName -Properties LastLogonDate, PasswordLastSet
                            $privilegedUsers += [PSCustomObject]@{
                                Username = $user.SamAccountName
                                DisplayName = $user.DisplayName
                                PrivilegedGroup = $group
                                LastLogon = $user.LastLogonDate
                                PasswordLastSet = $user.PasswordLastSet
                                Enabled = $user.Enabled
                            }
                        }
                    }
                } catch {
                    Write-AdminLog -Message "Could not retrieve members of $group`: $($_.Exception.Message)" -Level "Warning"
                }
            }
            
            $reportData = @{
                ReportType = "Compliance"
                GeneratedDate = Get-Date
                Period = "$Days days"
                PasswordPolicy = @{
                    MaxPasswordAge = $passwordPolicy.MaxPasswordAge.Days
                    MinPasswordLength = $passwordPolicy.MinPasswordLength
                    PasswordHistoryCount = $passwordPolicy.PasswordHistoryCount
                    ComplexityEnabled = $passwordPolicy.ComplexityEnabled
                    LockoutThreshold = $passwordPolicy.LockoutThreshold
                    LockoutDuration = $passwordPolicy.LockoutDuration.TotalMinutes
                }
                PasswordCompliance = @{
                    UsersWithExpiringPasswords = $usersPasswordExpiring
                    ExpiringCount = $usersPasswordExpiring.Count
                    NeverSetPassword = ($users | Where-Object { -not $_.PasswordLastSet }).Count
                }
                AccountCompliance = @{
                    AccountsExpiring = $accountsExpiring
                    ExpiringCount = $accountsExpiring.Count
                    DisabledAccounts = ($users | Where-Object { $_.Enabled -eq $false }).Count
                    AccountsNeverLoggedOn = ($users | Where-Object { -not $_.LastLogonDate }).Count
                }
                PrivilegedAccounts = @{
                    Users = $privilegedUsers
                    TotalCount = $privilegedUsers.Count
                    InactivePrivileged = ($privilegedUsers | Where-Object { 
                        -not $_.LastLogon -or $_.LastLogon -lt $startDate 
                    }).Count
                }
                ComplianceScore = @{
                    PasswordCompliance = [math]::Round((($users.Count - $usersPasswordExpiring.Count) / $users.Count) * 100, 2)
                    ActiveAccountRatio = [math]::Round((($users | Where-Object { $_.Enabled }).Count / $users.Count) * 100, 2)
                    RecentActivityRatio = [math]::Round((($users | Where-Object { 
                        $_.LastLogonDate -and $_.LastLogonDate -gt $startDate 
                    }).Count / $users.Count) * 100, 2)
                }
            }
        }
    }
    
    # Generate output files
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $baseFileName = "ADUserActivity-$ReportType-$timestamp"
    $outputFiles = @()
    
    if ($Format -eq "All" -or $Format -eq "JSON") {
        $jsonFile = Join-Path $OutputPath "$baseFileName.json"
        $reportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile -Encoding UTF8
        $outputFiles += $jsonFile
        Write-AdminLog -Message "JSON report saved: $jsonFile" -Level "Success"
    }
    
    if ($Format -eq "All" -or $Format -eq "CSV") {
        $csvFile = Join-Path $OutputPath "$baseFileName.csv"
        if ($ReportType -eq "Detailed") {
            $reportData.UserDetails | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
        } else {
            # Flatten complex object for CSV
            $flatData = @()
            foreach ($key in $reportData.Keys) {
                $value = $reportData[$key]
                if ($value -is [array] -or $value -is [hashtable]) {
                    $value = $value | ConvertTo-Json -Compress
                }
                $flatData += [PSCustomObject]@{ Property = $key; Value = $value }
            }
            $flatData | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
        }
        $outputFiles += $csvFile
        Write-AdminLog -Message "CSV report saved: $csvFile" -Level "Success"
    }
    
    if ($Format -eq "All" -or $Format -eq "HTML") {
        $htmlFile = Join-Path $OutputPath "$baseFileName.html"
        $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>AD User Activity Report - $ReportType</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 10px; border-radius: 5px; }
        .section { margin: 20px 0; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .warning { color: red; font-weight: bold; }
        .success { color: green; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Active Directory User Activity Report</h1>
        <p><strong>Report Type:</strong> $ReportType</p>
        <p><strong>Generated:</strong> $(Get-Date)</p>
        <p><strong>Period:</strong> $Days days</p>
    </div>
    
    <div class="section">
        <h2>Report Data</h2>
        <pre>$($reportData | ConvertTo-Json -Depth 5)</pre>
    </div>
</body>
</html>
"@
        $htmlContent | Out-File -FilePath $htmlFile -Encoding UTF8
        $outputFiles += $htmlFile
        Write-AdminLog -Message "HTML report saved: $htmlFile" -Level "Success"
    }
    
    # Email report if requested
    if ($EmailReport -and $outputFiles.Count -gt 0) {
        $subject = "AD User Activity Report - $ReportType"
        $body = @"
Active Directory User Activity Report

Report Type: $ReportType
Generated: $(Get-Date)
Period: $Days days
Files: $($outputFiles -join ', ')

Please find the attached reports for review.
"@
        
        try {
            Send-AdminNotification -Subject $subject -Body $body
            Write-AdminLog -Message "Report emailed successfully" -Level "Success"
        } catch {
            Write-AdminLog -Message "Failed to email report: $($_.Exception.Message)" -Level "Warning"
        }
    }
    
    # Generate final summary report
    $finalReport = New-AdminReport -ReportTitle "AD User Activity Report Generation" -Data $reportData -Description "Active Directory user activity report generation results" -Metadata @{
        ReportType = $ReportType
        Days = $Days
        Format = $Format
        OutputFiles = $outputFiles
        UserCount = $users.Count
        DomainControllers = $domainControllers.Count
    }
    
    Write-Output $finalReport
    Write-AdminLog -Message "AD user activity report generation completed successfully" -Level "Success"
    
} catch {
    Write-AdminLog -Message "AD user activity report generation failed: $($_.Exception.Message)" -Level "Error"
    throw
}