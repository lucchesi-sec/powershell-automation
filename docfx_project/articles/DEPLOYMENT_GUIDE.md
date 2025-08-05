# Production Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying the PowerShell Automation Platform in production environments. It covers installation, configuration, security hardening, and operational procedures for production-scale deployments.

## Prerequisites

### System Requirements
- **Operating System**: Windows Server 2016+ or Windows 10/11 Professional
- **PowerShell**: Version 5.1 minimum, 7.0+ recommended
- **Memory**: 4GB RAM minimum, 8GB+ recommended for large-scale operations
- **Storage**: 10GB minimum, 50GB+ recommended for backup operations
- **Network**: Domain-joined systems for Active Directory operations

### Required Permissions
- **Local Administrator**: Required for most automation tasks
- **Active Directory**: Domain Admin or delegated permissions for user management
- **Backup Operations**: Full control over backup destinations and sources
- **Cloud Storage**: Appropriate permissions for cloud provider APIs

### Software Dependencies
```powershell
# Required PowerShell modules
Install-Module ActiveDirectory -Force
Install-Module Az.Storage -Force          # For Azure integration
Install-Module AWSPowerShell.NetCore -Force  # For AWS integration
Install-Module Pester -Force             # For testing framework
```

## Installation Methods

### Method 1: Manual Installation

#### Step 1: Download and Extract
```powershell
# Clone or download the repository
git clone https://github.com/lucchesi-sec/powershell-automation.git
cd powershell-automation

# Verify file integrity
Get-ChildItem -Recurse | Get-FileHash -Algorithm SHA256 | Out-File checksums.txt
```

#### Step 2: Install Modules
```powershell
# Create module directory
$moduleBase = "$env:ProgramFiles\WindowsPowerShell\Modules"
New-Item -Path $moduleBase -ItemType Directory -Force

# Copy modules
Copy-Item -Path ".\modules\*" -Destination $moduleBase -Recurse -Force

# Verify installation
Get-Module -ListAvailable PSAdminCore
```

#### Step 3: Configure Environment
```powershell
# Set execution policy
Set-ExecutionPolicy RemoteSigned -Scope LocalMachine

# Create configuration directory
New-Item -Path "C:\ProgramData\PSAutomation\config" -ItemType Directory -Force

# Copy configuration files
Copy-Item -Path ".\config\*" -Destination "C:\ProgramData\PSAutomation\config" -Force
```

### Method 2: Automated Installation

An installation script is not provided in this project. You can create your own deployment script based on the manual installation steps.

## Configuration

### Core Configuration

#### 1. Email Notifications
Create a file named `email.json` in a secure location (e.g., `C:\ProgramData\PSAutomation\config`) with the following structure. This project includes a sample file in the `config` directory.
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

#### 2. Cloud Storage Configuration
Create `C:\ProgramData\PSAutomation\config\cloud-config.json`:
```json
{
    "Azure": {
        "StorageAccountName": "companybackups",
        "StorageAccountKey": "encrypted-key-here",
        "DefaultContainer": "production-backups"
    },
    "AWS": {
        "AccessKeyId": "encrypted-access-key",
        "SecretAccessKey": "encrypted-secret-key",
        "Region": "us-east-1",
        "DefaultBucket": "company-backups"
    }
}
```

#### 3. Active Directory Configuration
Create `C:\ProgramData\PSAutomation\config\ad-config.json`:
```json
{
    "DomainController": "dc01.company.com",
    "DefaultOU": "OU=Users,DC=company,DC=com",
    "GroupMappings": {
        "Department": {
            "IT": ["IT-Department", "VPN-Users"],
            "HR": ["HR-Department", "Confidential-Access"],
            "Finance": ["Finance-Department", "Financial-Systems"]
        }
    },
    "PasswordPolicy": {
        "Length": 12,
        "RequireComplexity": true,
        "ExpirationDays": 90
    }
}
```

### Security Configuration

#### 1. Credential Management
```powershell
# Create secure credential store
New-Item -Path "C:\ProgramData\PSAutomation\credentials" -ItemType Directory -Force

# Set appropriate permissions
$acl = Get-Acl "C:\ProgramData\PSAutomation\credentials"
$acl.SetAccessRuleProtection($true, $false)
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($adminRule)
Set-Acl "C:\ProgramData\PSAutomation\credentials" $acl
```

#### 2. Encryption Keys
```powershell
# Generate encryption key for backup encryption
$key = New-Object byte[] 32
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($key)
$key | Out-File "C:\ProgramData\PSAutomation\credentials\backup.key" -Encoding Byte

# Protect the key file
$keyAcl = Get-Acl "C:\ProgramData\PSAutomation\credentials\backup.key"
$keyAcl.SetAccessRuleProtection($true, $false)
$keyAdminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "Allow")
$keyAcl.SetAccessRule($keyAdminRule)
Set-Acl "C:\ProgramData\PSAutomation\credentials\backup.key" $keyAcl
```

#### 3. Service Account Setup
```powershell
# Create service account for automated operations
New-ADUser -Name "PSAutomationService" -SamAccountName "psautosvc" -UserPrincipalName "psautosvc@company.com" -Path "OU=ServiceAccounts,DC=company,DC=com" -AccountPassword (ConvertTo-SecureString "ComplexPassword123!" -AsPlainText -Force) -Enabled $true

# Grant necessary permissions
Add-ADGroupMember -Identity "Domain Admins" -Members "psautosvc"  # Adjust as needed for least privilege
```

## Scheduled Task Configuration

### Automated Backup Tasks
```powershell
# Daily backup task
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NonInteractive -File C:\PSAutomation\scripts\administration\Start-AutomatedBackup.ps1 -BackupConfigPath C:\ProgramData\PSAutomation\config\backup-config.json -EmailReport"

$trigger = New-ScheduledTaskTrigger -Daily -At "2:00 AM"

$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName "Production Daily Backup" -Action $action -Trigger $trigger -Settings $settings -User "COMPANY\psautosvc" -Password "ComplexPassword123!"
```

### Health Monitoring Tasks
```powershell
# Weekly backup health report
$healthAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NonInteractive -File C:\PSAutomation\scripts\administration\Get-BackupHealthReport.ps1 -BackupPath \\backup-server\backups -ReportType Compliance -GenerateDashboard -EmailReport"

$healthTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At "6:00 AM"

Register-ScheduledTask -TaskName "Weekly Backup Health Report" -Action $healthAction -Trigger $healthTrigger -Settings $settings -User "COMPANY\psautosvc" -Password "ComplexPassword123!"
```

### User Activity Monitoring
```powershell
# Monthly AD user activity report
$adAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NonInteractive -File C:\PSAutomation\scripts\administration\Get-ADUserActivityReport.ps1 -ReportType SecurityFocus -Days 30 -Format HTML -EmailReport"

$adTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Friday -At "5:00 PM"

Register-ScheduledTask -TaskName "Monthly AD Security Report" -Action $adAction -Trigger $adTrigger -Settings $settings -User "COMPANY\psautosvc" -Password "ComplexPassword123!"
```

## Network and Firewall Configuration

### Required Network Access
```powershell
# Backup destinations
New-NetFirewallRule -DisplayName "PSAutomation-SMB" -Direction Outbound -Protocol TCP -LocalPort 445 -Action Allow

# Email notifications
New-NetFirewallRule -DisplayName "PSAutomation-SMTP" -Direction Outbound -Protocol TCP -LocalPort 587 -Action Allow

# Cloud storage (HTTPS)
New-NetFirewallRule -DisplayName "PSAutomation-Cloud" -Direction Outbound -Protocol TCP -LocalPort 443 -Action Allow

# Active Directory (if remote)
New-NetFirewallRule -DisplayName "PSAutomation-LDAP" -Direction Outbound -Protocol TCP -LocalPort 389,636 -Action Allow
```

### DNS Configuration
Ensure the following DNS names are resolvable:
- Domain controllers for AD operations
- SMTP servers for email notifications
- Cloud storage endpoints (Azure, AWS)
- Backup server destinations

## Monitoring and Logging

### Event Log Configuration
```powershell
# Create custom event log for PSAutomation
New-EventLog -LogName "PSAutomation" -Source "PSAdminCore"
New-EventLog -LogName "PSAutomation" -Source "BackupManager"
New-EventLog -LogName "PSAutomation" -Source "ADManager"

# Configure log retention
Limit-EventLog -LogName "PSAutomation" -MaximumSize 50MB -OverflowAction OverwriteOlder
```

### Performance Monitoring
```powershell
# Create performance counters for monitoring
$counterPath = "\PSAutomation\Scripts Executed"
$counterPath2 = "\PSAutomation\Operations Per Minute"
$counterPath3 = "\PSAutomation\Average Execution Time"

# These would be implemented in the actual scripts
```

### Log Aggregation
Configure log forwarding to SIEM or centralized logging:
```powershell
# Configure Windows Event Forwarding
wecutil cs C:\ProgramData\PSAutomation\config\event-forwarding.xml
```

## Backup Strategy

### Backup Configuration
Create `C:\ProgramData\PSAutomation\config\backup-config.json`:
```json
{
    "jobs": [
        {
            "name": "CriticalSystems",
            "type": "FileSystem",
            "sources": ["C:\\CriticalData", "D:\\Databases"],
            "destination": "\\\\backup-server\\production",
            "compression": true,
            "encryption": true,
            "cloudSync": true,
            "schedule": "Daily",
            "retention": 30
        },
        {
            "name": "UserProfiles",
            "type": "FileSystem",
            "sources": ["C:\\Users"],
            "destination": "\\\\backup-server\\profiles",
            "compression": true,
            "encryption": false,
            "cloudSync": false,
            "schedule": "Weekly",
            "retention": 90
        }
    ],
    "cloudProviders": {
        "primary": "Azure",
        "secondary": "AWS"
    },
    "encryption": {
        "keyPath": "C:\\ProgramData\\PSAutomation\\credentials\\backup.key",
        "algorithm": "AES256"
    }
}
```

### Disaster Recovery
```powershell
# Create disaster recovery documentation
$drPlan = @"
# Disaster Recovery Plan for PSAutomation Platform

## Recovery Procedures
1. Restore configuration files from backup
2. Reinstall PowerShell modules
3. Recreate scheduled tasks
4. Verify cloud connectivity
5. Test backup restoration

## Critical Files
- C:\ProgramData\PSAutomation\config\*
- C:\ProgramData\PSAutomation\credentials\*
- Scheduled task exports

## Recovery Time Objective: 4 hours
## Recovery Point Objective: 24 hours
"@

$drPlan | Out-File "C:\ProgramData\PSAutomation\docs\disaster-recovery-plan.md"
```

## Testing and Validation

### Pre-Production Testing
```powershell
# Test script execution
Import-Module PSAdminCore -Force
Test-AdminPrivileges

# Test email notifications
Send-AdminNotification -Subject "Test Email" -Body "Testing email configuration"

# Test backup operations
.\Start-AutomatedBackup.ps1 -TestMode -BackupConfigPath "C:\ProgramData\PSAutomation\config\backup-config.json"

# Test AD connectivity
Get-ADUser -Filter * -ResultSetSize 1
```

### Validation Checklist
- [ ] All modules import successfully
- [ ] Configuration files are properly formatted
- [ ] Email notifications work
- [ ] Backup destinations are accessible
- [ ] Cloud storage connectivity verified
- [ ] Active Directory operations functional
- [ ] Scheduled tasks created and enabled
- [ ] Event logging operational
- [ ] Security permissions configured
- [ ] Service account has required permissions

## Maintenance Procedures

### Regular Maintenance Tasks

#### Weekly
```powershell
# Check script execution logs
Get-EventLog -LogName "PSAutomation" -Newest 100

# Verify backup integrity
.\Test-BackupIntegrity.ps1 -BackupPath "\\backup-server\backups" -ValidationMode "Quick"

# Check disk space on backup destinations
.\Get-LowDiskSpace.ps1 -Threshold 10
```

#### Monthly
```powershell
# Generate comprehensive health reports
.\Get-BackupHealthReport.ps1 -ReportType "Detailed" -GenerateDashboard

# Review AD user activity
.\Get-ADUserActivityReport.ps1 -ReportType "Compliance" -Days 30

# Update modules if available
Update-Module PSAdminCore -Force
```

#### Quarterly
```powershell
# Full backup validation
.\Test-BackupIntegrity.ps1 -BackupPath "\\backup-server\backups" -ValidationMode "Full"

# Security review
Get-ScheduledTask | Where-Object {$_.TaskName -like "*PSAutomation*"} | Get-ScheduledTaskInfo

# Performance analysis
# Review execution times and optimize slow operations
```

## Troubleshooting

### Common Issues

#### Module Import Failures
```powershell
# Check module paths
$env:PSModulePath -split ';'

# Verify module files exist
Get-ChildItem "C:\Program Files\WindowsPowerShell\Modules\PSAdminCore"

# Import with full path
Import-Module "C:\Program Files\WindowsPowerShell\Modules\PSAdminCore\PSAdminCore.psm1" -Force -Verbose
```

#### Scheduled Task Failures
```powershell
# Check task history
Get-ScheduledTask -TaskName "Production Daily Backup" | Get-ScheduledTaskInfo

# Review event logs
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational'; ID=201}

# Test manual execution
& "C:\PSAutomation\scripts\administration\Start-AutomatedBackup.ps1" -BackupConfigPath "C:\ProgramData\PSAutomation\config\backup-config.json"
```

#### Network Connectivity Issues
```powershell
# Test backup destination connectivity
Test-NetConnection -ComputerName "backup-server" -Port 445

# Test cloud connectivity
Test-NetConnection -ComputerName "blob.core.windows.net" -Port 443

# Test SMTP connectivity
Test-NetConnection -ComputerName "smtp.company.com" -Port 587
```

## Security Considerations

### Hardening Checklist
- [ ] Service account follows least privilege principle
- [ ] Encryption keys are properly protected
- [ ] Configuration files have appropriate permissions
- [ ] Audit logging is enabled
- [ ] Network access is restricted to required destinations
- [ ] Regular security reviews are scheduled
- [ ] Backup data is encrypted at rest and in transit
- [ ] Cloud storage uses proper authentication

### Compliance Requirements
- Document all automated operations
- Maintain audit trails for all changes
- Implement data retention policies
- Regular compliance assessments
- Incident response procedures

This deployment guide provides the foundation for successfully implementing the PowerShell Automation Platform in production environments with production-grade security and reliability.