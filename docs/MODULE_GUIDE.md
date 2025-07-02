# PowerShell Module Guide

## Overview

This guide provides comprehensive information about the PowerShell modules included in the Enterprise Automation Platform. Each module is designed for specific enterprise functions and can be used independently or together for comprehensive automation solutions.

## Core Architecture

### Module Structure
```
modules/
├── PSAdminCore/           # Core shared functions
│   ├── PSAdminCore.psm1   # Main module file
│   └── PSAdminCore.psd1   # Module manifest
├── PSActiveDirectory/     # Active Directory operations
├── PSBackupManager/       # Backup and recovery
├── PSPerformanceMonitor/  # System performance monitoring
└── PSSoftwareManager/     # Software deployment and management
```

## PSAdminCore Module

### Purpose
Provides shared enterprise functions used across all administration scripts, ensuring consistency and reducing code duplication.

### Key Functions

#### Logging and Reporting
```powershell
Write-AdminLog -Message "Operation completed" -Level "Success" -LogPath "C:\Logs\admin.log"
New-AdminReport -ReportTitle "System Status" -Data $results -Description "Daily system report"
```

#### Security and Access Control
```powershell
Test-AdminPrivileges                    # Check if running as administrator
Get-AdminCredential -Purpose "Service" # Secure credential management
Test-AdminParameter -Value $email -Type "Email"  # Input validation
```

#### Notifications and Communication
```powershell
Send-AdminNotification -Subject "Alert" -Body "System alert message" -Priority "High"
Test-AdminConnectivity -ComputerName @("server1", "server2") -Port 443
```

### Usage Examples

#### Basic Logging
```powershell
Import-Module .\modules\PSAdminCore\PSAdminCore.psm1

# Standard logging
Write-AdminLog -Message "Starting backup operation" -Level "Info"
Write-AdminLog -Message "Backup completed successfully" -Level "Success"
Write-AdminLog -Message "Disk space low" -Level "Warning"
Write-AdminLog -Message "Backup failed" -Level "Error"
```

#### Credential Management
```powershell
# Secure credential prompt
$creds = Get-AdminCredential -Purpose "SQL Server Connection" -Username "sa"

# Validate input parameters
if (Test-AdminParameter -Value $emailAddress -Type "Email") {
    Write-AdminLog -Message "Valid email address provided" -Level "Success"
}
```

#### Reporting Framework
```powershell
# Create structured report
$reportData = @{
    SystemName = $env:COMPUTERNAME
    Status = "Healthy"
    LastCheck = Get-Date
    Issues = @()
}

$report = New-AdminReport -ReportTitle "System Health Check" -Data $reportData -Description "Daily health monitoring report"
```

## Module Dependencies

### Required Modules
- **PowerShell 5.1+**: Core PowerShell functionality
- **ActiveDirectory**: For AD management scripts
- **Az.Storage**: For Azure cloud backup features
- **AWSPowerShell.NetCore**: For AWS cloud backup features

### Optional Modules
- **Pester**: For unit testing functionality
- **ImportExcel**: For advanced Excel reporting
- **PoshRSJob**: For parallel job processing

## Installation and Configuration

### Manual Installation
```powershell
# Copy modules to PowerShell module path
$modulePath = "$env:USERPROFILE\Documents\PowerShell\Modules"
Copy-Item -Path ".\modules\*" -Destination $modulePath -Recurse -Force

# Import modules
Import-Module PSAdminCore
```

### Automatic Installation
```powershell
# Run the installation script
.\Install-Modules.ps1 -Scope CurrentUser
```

### Configuration Files
Create configuration files in the `config/` directory:

#### Email Configuration (`config/email.json`)
```json
{
    "From": "automation@company.com",
    "SmtpServer": "smtp.company.com",
    "Port": 587,
    "UseSsl": true,
    "Credential": true
}
```

#### Cloud Configuration (`config/cloud-config.json`)
```json
{
    "Azure": {
        "StorageAccountName": "companybackups",
        "StorageAccountKey": "your-storage-key",
        "ConnectionString": "DefaultEndpointsProtocol=https;..."
    },
    "AWS": {
        "AccessKeyId": "your-access-key",
        "SecretAccessKey": "your-secret-key",
        "Region": "us-east-1"
    }
}
```

## Advanced Module Features

### Error Handling
All modules implement consistent error handling:

```powershell
try {
    # Module operation
    $result = Invoke-SomeOperation
    Write-AdminLog -Message "Operation successful" -Level "Success"
} catch {
    Write-AdminLog -Message "Operation failed: $($_.Exception.Message)" -Level "Error"
    throw
}
```

### Performance Monitoring
Built-in performance tracking:

```powershell
$startTime = Get-Date
# ... operation ...
$duration = (Get-Date) - $startTime
Write-AdminLog -Message "Operation completed in $($duration.TotalSeconds) seconds" -Level "Info"
```

### Parallel Processing
Support for parallel operations:

```powershell
$computers = @("server1", "server2", "server3")
$results = $computers | ForEach-Object -Parallel {
    Import-Module PSAdminCore
    Test-AdminConnectivity -ComputerName $_ -Port 443
} -ThrottleLimit 5
```

## Best Practices

### Module Development
1. **Consistent Naming**: Use approved PowerShell verbs and consistent naming conventions
2. **Error Handling**: Implement comprehensive try-catch blocks
3. **Logging**: Use Write-AdminLog for all operations
4. **Documentation**: Include comment-based help for all functions
5. **Testing**: Write unit tests for all public functions

### Performance Optimization
1. **Filtering**: Apply filters early in pipelines
2. **Parallel Processing**: Use parallel execution for independent operations
3. **Caching**: Cache expensive operations when appropriate
4. **Memory Management**: Dispose of objects properly

### Security Considerations
1. **Credential Management**: Never hardcode credentials
2. **Input Validation**: Validate all user inputs
3. **Privilege Checking**: Verify administrative privileges
4. **Audit Logging**: Log all security-relevant operations

## Troubleshooting

### Common Issues

#### Module Import Errors
```powershell
# Check module path
$env:PSModulePath -split ';'

# Import with full path
Import-Module "C:\Full\Path\To\PSAdminCore\PSAdminCore.psm1" -Force
```

#### Permission Errors
```powershell
# Check execution policy
Get-ExecutionPolicy

# Set execution policy
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### Missing Dependencies
```powershell
# Check available modules
Get-Module -ListAvailable

# Install missing modules
Install-Module ActiveDirectory -Force
```

### Logging and Diagnostics
```powershell
# Enable verbose logging
Import-Module PSAdminCore -Force -Verbose

# Check log files
Get-Content "$env:TEMP\PSAdmin.log" -Tail 50
```

## Version Compatibility

| Module Version | PowerShell Version | Windows Version | Notes |
|----------------|-------------------|-----------------|--------|
| 1.0.0 | 5.1+ | Server 2016+ | Initial release |
| 2.0.0 | 5.1, 7.0+ | Server 2016+ | Enhanced features |

## Support and Maintenance

### Regular Maintenance
1. **Log Rotation**: Implement log file rotation
2. **Performance Monitoring**: Monitor module performance
3. **Security Updates**: Keep modules updated
4. **Testing**: Regular testing in dev/test environments

### Update Process
```powershell
# Backup current modules
Copy-Item $env:PSModulePath\PSAdminCore $env:PSModulePath\PSAdminCore.backup -Recurse

# Install new version
.\Update-Modules.ps1

# Test functionality
Test-ModuleFunctionality
```

This module guide provides the foundation for effectively using and maintaining the PowerShell Enterprise Automation Platform modules.