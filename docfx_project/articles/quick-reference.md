---
uid: articles.quick-reference
---

# Quick Reference

This quick reference guide provides essential commands, functions, and workflows for the PowerShell Automation Platform. Keep this handy for day-to-day operations.

## Essential Commands

### Core Module Functions

| Function | Purpose | Example |
|----------|---------|---------|
| `Test-AdminPrivileges` | Validate administrative permissions | `Test-AdminPrivileges` |
| `Write-AdminLog` | Centralized logging with structured output | `Write-AdminLog -Message "Operation completed" -Level "Info"` |
| `Send-AdminNotification` | SMTP notifications for operations | `Send-AdminNotification -Subject "Alert" -Body "System issue detected"` |
| `New-AdminReport` | Generate comprehensive activity reports | `New-AdminReport -Type "UserActivity" -OutputPath "C:\Reports"` |
| `Get-SystemInfo` | Retrieve detailed system information | `Get-SystemInfo -IncludeHardware` |
| `Test-NetworkConnectivity` | Test network connectivity and services | `Test-NetworkConnectivity -Target "domain.com" -Port 443` |

### Module Import Commands

```powershell
# Import core module
Import-Module ./modules/PSAdminCore/PSAdminCore.psm1

# Import with verbose output
Import-Module ./modules/PSAdminCore/PSAdminCore.psm1 -Verbose

# Force reload module
Import-Module ./modules/PSAdminCore/PSAdminCore.psm1 -Force
```

## Key Scripts Reference

### User Management

| Script | Purpose | Key Parameters |
|--------|---------|----------------|
| `New-ADUserWithStandardGroups.ps1` | Create new AD user with standard groups | `-FirstName`, `-LastName`, `-Department` |
| `Import-ADUsersFromCSV.ps1` | Bulk user creation from CSV | `-CsvPath`, `-WhatIf` |
| `Disable-ADUser.ps1` | Disable departing user | `-Username`, `-BackupData` |
| `Get-ADUserActivityReport.ps1` | Generate user activity report | `-Days`, `-OutputPath` |
| `Sync-ADGroupMembership.ps1` | Synchronize group memberships | `-GroupName`, `-SourceOU` |

### System Maintenance

| Script | Purpose | Key Parameters |
|--------|---------|----------------|
| `Monitor-CriticalServices.ps1` | Monitor critical services | `-Services`, `-SendEmail` |
| `Clear-DiskSpace.ps1` | Clean up disk space | `-WhatIf`, `-Confirm` |
| `Update-SystemPatches.ps1` | Automated patch management | `-RebootIfRequired`, `-Schedule` |
| `Backup-SystemConfiguration.ps1` | Backup system configuration | `-BackupPath`, `-IncludeRegistry` |

### Backup Operations

| Script | Purpose | Key Parameters |
|--------|---------|----------------|
| `Start-AutomatedBackup.ps1` | Start automated backup | `-BackupType`, `-Priority` |
| `Test-BackupIntegrity.ps1` | Test backup integrity | `-BackupPath`, `-ReportPath` |
| `Sync-BackupToCloud.ps1` | Sync backups to cloud | `-Provider`, `-StorageAccount` |
| `Restore-FromBackup.ps1` | Restore from backup | `-BackupFile`, `-RestorePath` |

## Common Workflows

### Daily Operations Checklist

```powershell
# 1. Import core module
Import-Module ./modules/PSAdminCore/PSAdminCore.psm1

# 2. Check system health
./scripts/maintenance/Monitor-CriticalServices.ps1 -SendEmail

# 3. Verify backup status
./scripts/backup/Test-BackupIntegrity.ps1 -ReportPath "C:\Reports"

# 4. Check disk space
./scripts/maintenance/Clear-DiskSpace.ps1 -WhatIf

# 5. Review security status
./scripts/security/Test-SecurityCompliance.ps1 -GenerateReport
```

### Weekly Maintenance

```powershell
# 1. Generate weekly reports
./scripts/reports/New-WeeklySummaryReport.ps1

# 2. Update system patches
./scripts/maintenance/Update-SystemPatches.ps1 -WhatIf

# 3. Backup system configuration
./scripts/maintenance/Backup-SystemConfiguration.ps1

# 4. Clean up old logs
./scripts/maintenance/Clear-OldLogs.ps1 -Days 30

# 5. Test backup integrity
./scripts/backup/Test-BackupIntegrity.ps1 -FullTest
```

### Monthly Operations

```powershell
# 1. Generate monthly reports
./scripts/reports/New-MonthlyOperationsReport.ps1

# 2. Review user activity
./scripts/administration/Get-ADUserActivityReport.ps1 -Days 30

# 3. Security audit
./scripts/security/Invoke-SecurityAudit.ps1 -FullScan

# 4. Performance analysis
./scripts/analytics/Get-PerformanceTrends.ps1 -Period "30days"

# 5. Compliance check
./scripts/security/New-ComplianceReport.ps1 -Standard "CIS"
```

## Configuration Quick Reference

### Email Configuration (`config/email.json`)

```json
{
    "From": "automation@company.com",
    "SmtpServer": "smtp.company.com",
    "Port": 587,
    "UseSsl": true,
    "Credential": true,
    "Recipients": {
        "Administrators": ["admin@company.com"],
        "Security": ["security@company.com"],
        "Operations": ["ops@company.com"]
    }
}
```

### Backup Configuration (`config/backup.json`)

```json
{
    "BackupPath": "\\BackupServer\\Backups",
    "RetentionDays": 30,
    "CloudSync": {
        "Enabled": true,
        "Provider": "Azure",
        "StorageAccount": "companybackups",
        "Container": "daily-backups"
    },
    "Schedule": {
        "Daily": "02:00",
        "Weekly": "Sunday 01:00",
        "Monthly": "First Sunday 00:00"
    }
}
```

### Monitoring Configuration (`config/monitoring.json`)

```json
{
    "CriticalServices": [
        "WinRM",
        "DNS",
        "DHCP",
        "Active Directory Domain Services"
    ],
    "DiskSpaceThreshold": 85,
    "MemoryThreshold": 90,
    "CPUThreshold": 95,
    "NotificationSettings": {
        "EmailOnCritical": true,
        "EmailOnWarning": false,
        "LogAll": true
    }
}
```

## Error Handling Patterns

### Try-Catch Template

```powershell
try {
    # Your operation here
    Write-AdminLog -Message "Operation started" -Level "Info"
    
    # Main logic
    $result = Invoke-SomeOperation
    
    Write-AdminLog -Message "Operation completed successfully" -Level "Info"
    return $result
}
catch {
    Write-AdminLog -Message "Operation failed: $($_.Exception.Message)" -Level "Error"
    Send-AdminNotification -Subject "Operation Failed" -Body $_.Exception.Message
    throw
}
```

### Parameter Validation

```powershell
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Username,
    
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 365)]
    [int]$Days = 30,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Info", "Warning", "Error")]
    [string]$LogLevel = "Info"
)
```

## Scheduling Commands

### Windows Task Scheduler

```powershell
# Create daily task
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\DailyMaintenance.ps1"
$Trigger = New-ScheduledTaskTrigger -Daily -At 2:00AM
$Settings = New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable
Register-ScheduledTask -TaskName "Daily Maintenance" -Action $Action -Trigger $Trigger -Settings $Settings

# Create weekly task
$Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 1:00AM
Register-ScheduledTask -TaskName "Weekly Backup" -Action $Action -Trigger $Trigger -Settings $Settings
```

### PowerShell Jobs

```powershell
# Start background job
$Job = Start-Job -ScriptBlock {
    Import-Module C:\Scripts\modules\PSAdminCore\PSAdminCore.psm1
    & C:\Scripts\maintenance\Monitor-CriticalServices.ps1
}

# Check job status
Get-Job $Job

# Get job results
Receive-Job $Job -Wait -AutoRemoveJob
```

## Security Best Practices

### Credential Management

```powershell
# Store credentials securely
$Credential = Get-Credential
$Credential | Export-Clixml -Path "C:\Secure\ServiceAccount.xml"

# Load credentials
$Credential = Import-Clixml -Path "C:\Secure\ServiceAccount.xml"

# Use Windows Credential Manager
cmdkey /generic:ServiceAccount /user:domain\serviceaccount /pass:password
$Credential = Get-StoredCredential -Target "ServiceAccount"
```

### Execution Policy

```powershell
# Check current execution policy
Get-ExecutionPolicy

# Set execution policy for current user
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Bypass execution policy for specific script
PowerShell.exe -ExecutionPolicy Bypass -File "C:\Scripts\MyScript.ps1"
```

## Troubleshooting Commands

### Common Diagnostics

```powershell
# Check module loading
Get-Module -ListAvailable PSAdminCore
Get-Module PSAdminCore

# Test network connectivity
Test-NetConnection -ComputerName "server.domain.com" -Port 443

# Check event logs
Get-EventLog -LogName System -EntryType Error -Newest 10

# Check services
Get-Service -Name "WinRM" | Format-List

# Check disk space
Get-WmiObject -Class Win32_LogicalDisk | Select-Object DeviceID, Size, FreeSpace
```

### Log Analysis

```powershell
# View recent logs
Get-Content "C:\Logs\PSAdmin\admin.log" -Tail 50

# Search logs for errors
Select-String -Path "C:\Logs\PSAdmin\admin.log" -Pattern "ERROR"

# Get logs for specific date
Get-Content "C:\Logs\PSAdmin\admin.log" | Where-Object { $_ -match "2024-01-15" }
```

## Performance Optimization

### Resource Monitoring

```powershell
# Monitor CPU usage
Get-Counter -Counter "\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples 10

# Monitor memory usage
Get-Counter -Counter "\Memory\Available MBytes" -SampleInterval 1 -MaxSamples 10

# Monitor disk usage
Get-Counter -Counter "\PhysicalDisk(_Total)\% Disk Time" -SampleInterval 1 -MaxSamples 10
```

### Script Optimization

```powershell
# Measure script execution time
Measure-Command { ./scripts/maintenance/Monitor-CriticalServices.ps1 }

# Use parallel processing
1..100 | ForEach-Object -Parallel { 
    # Process items in parallel
} -ThrottleLimit 10
```

## Help and Documentation

### Getting Help

```powershell
# Get help for any script
Get-Help ./scripts/maintenance/Monitor-CriticalServices.ps1 -Full

# Get help for module functions
Get-Help Test-AdminPrivileges -Examples

# Show available parameters
Get-Help New-AdminReport -Parameter *

# Get online help
Get-Help about_PowerShell_ISE -Online
```

### Version Information

```powershell
# Check PowerShell version
$PSVersionTable

# Check module version
Get-Module PSAdminCore | Select-Object Version

# Check OS version
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion
```

---

*For detailed information on any command or script, use `Get-Help` or refer to the [User Guide](user-guide.md) and API Documentation.*