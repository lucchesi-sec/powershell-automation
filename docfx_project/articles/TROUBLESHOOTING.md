---
uid: articles.troubleshooting
---

# Troubleshooting Guide

This comprehensive troubleshooting guide helps you diagnose and resolve common issues with the PowerShell Automation Platform.

## Table of Contents
- [Common Issues](#common-issues)
- [Module Loading Problems](#module-loading-problems)
- [Script Execution Errors](#script-execution-errors)
- [Network and Connectivity Issues](#network-and-connectivity-issues)
- [Active Directory Problems](#active-directory-problems)
- [Backup and Storage Issues](#backup-and-storage-issues)
- [Performance Problems](#performance-problems)
- [Security and Permissions](#security-and-permissions)
- [Logging and Monitoring](#logging-and-monitoring)
- [Advanced Diagnostics](#advanced-diagnostics)

## Common Issues

### Issue: "Execution Policy Error"

**Symptoms:**
```
.\script.ps1 : File cannot be loaded because running scripts is disabled on this system.
```

**Cause:** PowerShell execution policy is set to Restricted or AllSigned.

**Solution:**
```powershell
# Check current execution policy
Get-ExecutionPolicy

# Set execution policy for current user
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Alternative: Bypass for single script
PowerShell.exe -ExecutionPolicy Bypass -File "C:\Scripts\MyScript.ps1"
```

### Issue: "Access Denied" Errors

**Symptoms:**
```
Access to the path 'C:\Windows\System32\...' is denied.
```

**Cause:** Insufficient privileges or UAC restrictions.

**Solution:**
```powershell
# Check if running as administrator
Test-AdminPrivileges

# If not, restart PowerShell as administrator
Start-Process PowerShell -Verb RunAs
```

### Issue: "Module Not Found"

**Symptoms:**
```
Import-Module : The specified module 'PSAdminCore' was not loaded.
```

**Cause:** Module path is incorrect or module is not installed.

**Solution:**
```powershell
# Check available modules
Get-Module -ListAvailable PSAdminCore

# Import with full path
Import-Module "C:\Scripts\modules\PSAdminCore\PSAdminCore.psm1" -Force

# Add module path to PSModulePath
$env:PSModulePath += ";C:\Scripts\modules"
```

## Module Loading Problems

### Diagnostic Steps

1. **Check Module Location:**
   ```powershell
   Get-ChildItem -Path ".\modules\PSAdminCore" -Recurse
   ```

2. **Verify Module Manifest:**
   ```powershell
   Test-ModuleManifest -Path ".\modules\PSAdminCore\PSAdminCore.psd1"
   ```

3. **Check Module Dependencies:**
   ```powershell
   Get-Module PSAdminCore -ListAvailable | Select-Object RequiredModules
   ```

### Common Module Issues

#### Issue: "Invalid Module Manifest"

**Solution:**
```powershell
# Recreate module manifest
New-ModuleManifest -Path ".\modules\PSAdminCore\PSAdminCore.psd1" -ModuleVersion "1.0.0" -Author "Your Name"
```

#### Issue: "Function Not Exported"

**Solution:**
Ensure functions are properly exported in the module manifest:
```powershell
# In PSAdminCore.psd1
FunctionsToExport = @('Test-AdminPrivileges', 'Write-AdminLog', 'Send-AdminNotification')
```

## Script Execution Errors

### Parameter Validation Errors

**Issue:** "Cannot validate argument on parameter"

**Diagnosis:**
```powershell
# Test parameter validation
$Parameters = @{
    Username = ""  # Invalid empty string
    Days = 400     # Invalid range
}
```

**Solution:**
```powershell
# Provide valid parameters
$Parameters = @{
    Username = "john.doe"
    Days = 30
}
```

### Path-Related Errors

**Issue:** "Cannot find path"

**Diagnosis:**
```powershell
# Check if path exists
Test-Path "C:\Scripts\config\email.json"

# Get current location
Get-Location

# List current directory contents
Get-ChildItem
```

**Solution:**
```powershell
# Use absolute paths
$ConfigPath = "C:\Scripts\config\email.json"

# Or resolve relative paths
$ConfigPath = Join-Path $PSScriptRoot "config\email.json"
```

### JSON Configuration Errors

**Issue:** "Invalid JSON format"

**Diagnosis:**
```powershell
# Test JSON validity
try {
    $Config = Get-Content "config\email.json" | ConvertFrom-Json
    Write-Host "JSON is valid"
}
catch {
    Write-Host "JSON is invalid: $($_.Exception.Message)"
}
```

**Solution:**
```powershell
# Validate JSON structure
$ValidConfig = @{
    From = "automation@company.com"
    SmtpServer = "smtp.company.com"
    Port = 587
    UseSsl = $true
} | ConvertTo-Json -Depth 3
```

## Network and Connectivity Issues

### SMTP Email Problems

**Issue:** "Unable to connect to SMTP server"

**Diagnosis:**
```powershell
# Test SMTP connectivity
Test-NetConnection -ComputerName "smtp.company.com" -Port 587

# Test with telnet
telnet smtp.company.com 587
```

**Solution:**
```powershell
# Check firewall settings
Get-NetFirewallRule -DisplayName "*SMTP*" | Where-Object Enabled -eq "True"

# Test with different port
Test-NetConnection -ComputerName "smtp.company.com" -Port 25
```

### Active Directory Connectivity

**Issue:** "Cannot contact domain controller"

**Diagnosis:**
```powershell
# Test AD connectivity
Test-ComputerSecureChannel

# Check domain controllers
Get-ADDomainController -Discover

# Test LDAP connection
Test-NetConnection -ComputerName "dc1.company.com" -Port 389
```

**Solution:**
```powershell
# Reset computer account
Reset-ComputerMachinePassword

# Use specific domain controller
Get-ADUser -Server "dc1.company.com" -Filter *
```

## Active Directory Problems

### User Creation Issues

**Issue:** "The object already exists"

**Diagnosis:**
```powershell
# Check if user exists
Get-ADUser -Filter "SamAccountName -eq 'john.doe'"

# Check deleted objects
Get-ADObject -Filter "Name -eq 'john.doe'" -IncludeDeletedObjects
```

**Solution:**
```powershell
# Use different username or restore deleted object
Restore-ADObject -Identity "CN=John Doe\0ADEL:..."
```

### Permission Problems

**Issue:** "Insufficient access rights"

**Diagnosis:**
```powershell
# Check AD permissions
Get-ADUser $env:USERNAME | Get-ADPermission

# Check group memberships
Get-ADGroupMember -Identity "Domain Admins"
```

**Solution:**
```powershell
# Run with appropriate service account
$Credential = Get-Credential
Get-ADUser -Filter * -Credential $Credential
```

## Backup and Storage Issues

### Backup Path Problems

**Issue:** "Cannot access backup path"

**Diagnosis:**
```powershell
# Test backup path
Test-Path "\\BackupServer\Backups"

# Check network connectivity
Test-NetConnection -ComputerName "BackupServer" -Port 445

# Test with credentials
$Credential = Get-Credential
New-PSDrive -Name "BackupDrive" -PSProvider FileSystem -Root "\\BackupServer\Backups" -Credential $Credential
```

**Solution:**
```powershell
# Use UNC path with credentials
$BackupPath = "\\BackupServer\Backups"
$Credential = Get-StoredCredential -Target "BackupServer"
```

### Cloud Sync Issues

**Issue:** "Cloud authentication failed"

**Diagnosis:**
```powershell
# Test cloud credentials
Test-AzureConnection -Credential $CloudCredential

# Check service principal
Get-AzContext
```

**Solution:**
```powershell
# Re-authenticate to cloud service
Connect-AzAccount -ServicePrincipal -Credential $ServicePrincipal
```

## Performance Problems

### Slow Script Execution

**Issue:** Scripts taking too long to execute

**Diagnosis:**
```powershell
# Measure execution time
Measure-Command { .\scripts\maintenance\Monitor-CriticalServices.ps1 }

# Profile script performance
Trace-Command -Name ParameterBinding -Expression { .\scripts\MyScript.ps1 } -PSHost
```

**Solutions:**
```powershell
# Use efficient cmdlets
Get-ADUser -Filter * -Properties Name, Email  # Instead of Get-ADUser -Filter * | Select-Object Name, Email

# Implement parallel processing
1..100 | ForEach-Object -Parallel { Process-Item $_ } -ThrottleLimit 10

# Use background jobs for long-running tasks
$Job = Start-Job -ScriptBlock { .\scripts\LongRunningScript.ps1 }
```

### Memory Usage Issues

**Issue:** High memory consumption

**Diagnosis:**
```powershell
# Monitor memory usage
Get-Counter -Counter "\Process(PowerShell)\Working Set" -SampleInterval 1 -MaxSamples 10

# Check object count
[System.GC]::GetTotalMemory($false)
```

**Solution:**
```powershell
# Explicitly dispose objects
$LargeObject = $null
[System.GC]::Collect()

# Use streaming for large datasets
Get-Content -Path "LargeFile.txt" -ReadCount 1000 | ForEach-Object { Process-Batch $_ }
```

## Security and Permissions

### Credential Storage Issues

**Issue:** "Credentials not found"

**Diagnosis:**
```powershell
# Check Windows Credential Manager
cmdkey /list

# Check stored credentials
Get-StoredCredential -Target "ServiceAccount"
```

**Solution:**
```powershell
# Store credentials properly
$Credential = Get-Credential
$Credential | Export-Clixml -Path "C:\Secure\ServiceAccount.xml"

# Use Windows Credential Manager
cmdkey /generic:ServiceAccount /user:domain\serviceaccount /pass:password
```

### Certificate Issues

**Issue:** "Certificate validation failed"

**Diagnosis:**
```powershell
# Check certificates
Get-ChildItem -Path Cert:\LocalMachine\My

# Test certificate validity
Test-Certificate -Cert $Certificate
```

**Solution:**
```powershell
# Import certificate
Import-Certificate -FilePath "certificate.cer" -CertStoreLocation "Cert:\LocalMachine\My"

# Skip certificate validation (not recommended for production)
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

## Logging and Monitoring

### Log File Issues

**Issue:** "Log files not being created"

**Diagnosis:**
```powershell
# Check log directory
Test-Path "C:\Logs\PSAdmin"

# Check permissions
Get-Acl "C:\Logs\PSAdmin"

# Test log writing
Write-AdminLog -Message "Test log entry" -Level "Info"
```

**Solution:**
```powershell
# Create log directory
New-Item -Path "C:\Logs\PSAdmin" -ItemType Directory -Force

# Set appropriate permissions
$Acl = Get-Acl "C:\Logs\PSAdmin"
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Users", "FullControl", "Allow")
$Acl.SetAccessRule($AccessRule)
Set-Acl "C:\Logs\PSAdmin" $Acl
```

### Event Log Problems

**Issue:** "Cannot write to event log"

**Diagnosis:**
```powershell
# Check event log sources
Get-EventLog -List

# Test event log writing
Write-EventLog -LogName Application -Source "PSAdmin" -EventID 1000 -Message "Test"
```

**Solution:**
```powershell
# Create event log source
New-EventLog -LogName Application -Source "PSAdmin"

# Write to event log
Write-EventLog -LogName Application -Source "PSAdmin" -EventID 1000 -EntryType Information -Message "Test"
```

## Advanced Diagnostics

### Enable Detailed Logging

```powershell
# Enable PowerShell transcript logging
Start-Transcript -Path "C:\Logs\PowerShell\transcript.txt"

# Enable verbose output
$VerbosePreference = "Continue"

# Enable debug output
$DebugPreference = "Continue"

# Enable module logging
Set-PSDebug -Trace 1
```

### Network Diagnostics

```powershell
# Comprehensive network test
function Test-NetworkDiagnostics {
    param($ComputerName, $Port)
    
    # DNS resolution
    Resolve-DnsName -Name $ComputerName
    
    # Ping test
    Test-Connection -ComputerName $ComputerName -Count 4
    
    # Port connectivity
    Test-NetConnection -ComputerName $ComputerName -Port $Port
    
    # Traceroute
    Test-NetConnection -ComputerName $ComputerName -TraceRoute
}
```

### System Information Gathering

```powershell
# Collect comprehensive system information
function Get-DiagnosticInfo {
    return @{
        OSVersion = Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion
        PowerShellVersion = $PSVersionTable
        AvailableMemory = Get-Counter -Counter "\Memory\Available MBytes" -SampleInterval 1 -MaxSamples 1
        DiskSpace = Get-WmiObject -Class Win32_LogicalDisk | Select-Object DeviceID, Size, FreeSpace
        Services = Get-Service | Where-Object Status -eq "Stopped"
        EventLogErrors = Get-EventLog -LogName System -EntryType Error -Newest 10
    }
}
```

### Performance Monitoring

```powershell
# Monitor script performance
function Monitor-ScriptPerformance {
    param($ScriptPath)
    
    $Job = Start-Job -ScriptBlock {
        param($Path)
        while ($true) {
            $Process = Get-Process PowerShell | Where-Object { $_.MainWindowTitle -like "*$Path*" }
            if ($Process) {
                [PSCustomObject]@{
                    Time = Get-Date
                    CPU = $Process.CPU
                    Memory = $Process.WorkingSet64 / 1MB
                }
            }
            Start-Sleep -Seconds 1
        }
    } -ArgumentList $ScriptPath
    
    # Execute script
    & $ScriptPath
    
    # Stop monitoring
    Stop-Job $Job
    Receive-Job $Job
}
```

## Getting Help

### Built-in Help

```powershell
# Get help for any command
Get-Help <CommandName> -Full

# Get examples
Get-Help <CommandName> -Examples

# Get online help
Get-Help <CommandName> -Online
```

### Community Resources

- **PowerShell Gallery**: Search for additional modules
- **Microsoft Documentation**: Official PowerShell documentation
- **Stack Overflow**: Community Q&A
- **GitHub Issues**: Report bugs and request features

### Support Escalation

If you cannot resolve an issue:

1. **Collect diagnostic information** using the functions above
2. **Check logs** for detailed error messages
3. **Document the issue** with steps to reproduce
4. **Contact your system administrator** with all relevant information

---

*For additional troubleshooting assistance, refer to the [User Guide](user-guide.md) or contact your IT support team.*