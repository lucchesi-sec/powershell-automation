# Error Codes Reference

## Overview

Comprehensive reference for error codes, common issues, and troubleshooting solutions in the Daily Admin Toolkit.

## Error Categories

### Network and Connectivity Errors

#### ERROR_001: Cannot Connect to Remote Computer
**Message**: "Cannot connect to remote computer 'SERVERNAME'"

**Causes:**
- Network connectivity issues
- Firewall blocking connections
- Target computer is offline
- DNS resolution problems

**Solutions:**
```powershell
# Test basic connectivity
Test-NetConnection -ComputerName 'SERVERNAME' -Port 5985
ping SERVERNAME

# Test DNS resolution
Resolve-DnsName 'SERVERNAME'

# Check firewall rules
Get-NetFirewallRule -DisplayName "*WinRM*" | Where-Object {$_.Enabled -eq "True"}

# Enable PowerShell remoting on target
Enable-PSRemoting -Force
```

#### ERROR_002: WinRM Service Not Available
**Message**: "WinRM service is not available on target computer"

**Causes:**
- WinRM service not running
- WinRM not configured
- Listener not configured

**Solutions:**
```powershell
# Check WinRM service status
Get-Service WinRM -ComputerName 'SERVERNAME'

# Start WinRM service remotely (if accessible via other means)
Get-Service WinRM -ComputerName 'SERVERNAME' | Start-Service

# Configure WinRM listener
winrm quickconfig -force

# Test WinRM connectivity
Test-WSMan -ComputerName 'SERVERNAME'
```

#### ERROR_003: Connection Timeout
**Message**: "Connection to remote computer timed out"

**Causes:**
- Network latency
- Overloaded target system
- Insufficient timeout value
- Network packet loss

**Solutions:**
```powershell
# Increase timeout value
Get-ServerHealth -ComputerName 'SERVERNAME' -TimeoutSeconds 120

# Test network performance
Test-NetConnection -ComputerName 'SERVERNAME' -DiagnoseRouting

# Check for packet loss
ping SERVERNAME -t

# Use parallel processing to handle slow servers
Get-ServerHealth -ComputerName $servers -Parallel -TimeoutSeconds 180
```

### Authentication and Authorization Errors

#### ERROR_101: Access Denied
**Message**: "Access is denied"

**Causes:**
- Insufficient permissions
- Account lockout
- Service account issues
- UAC restrictions

**Solutions:**
```powershell
# Check current user context
whoami
whoami /groups

# Use alternate credentials
$cred = Get-Credential -UserName "DOMAIN\Administrator"
Get-ServerHealth -ComputerName 'SERVERNAME' -Credential $cred

# Check account lockout status
Get-ADUser -Identity $env:USERNAME -Properties LockedOut

# Run PowerShell as administrator
Start-Process PowerShell -Verb RunAs
```

#### ERROR_102: Kerberos Authentication Failed
**Message**: "Kerberos authentication failed"

**Causes:**
- Time synchronization issues
- SPN (Service Principal Name) problems
- Domain trust issues
- Ticket expiration

**Solutions:**
```powershell
# Check time synchronization
w32tm /query /status

# Force time sync
w32tm /resync /force

# Check SPNs for computer account
setspn -L SERVERNAME

# Clear Kerberos tickets and re-authenticate
klist purge
gpupdate /force
```

#### ERROR_103: Credential Validation Failed
**Message**: "The user name or password is incorrect"

**Causes:**
- Wrong username/password
- Account disabled
- Password expired
- Wrong domain specified

**Solutions:**
```powershell
# Verify account status
Get-ADUser -Identity 'username' -Properties Enabled, PasswordExpired, LockedOut

# Test credentials interactively
$cred = Get-Credential
Test-Connection -ComputerName 'SERVERNAME' -Credential $cred

# Check account in different domain
Get-ADUser -Identity 'username' -Server 'domain.com'
```

### Active Directory Errors

#### ERROR_201: User Not Found
**Message**: "Cannot find an object with identity 'username'"

**Causes:**
- User doesn't exist
- Wrong domain context
- Insufficient search permissions
- Typing error in username

**Solutions:**
```powershell
# Search for similar usernames
Get-ADUser -Filter "Name -like '*john*'" | Select-Object Name, SamAccountName

# Search in different domain
Get-ADUser -Identity 'username' -Server 'otherdomain.com'

# Check current domain context
Get-ADDomain

# Use different identity formats
Get-ADUser -Identity 'CN=John Doe,OU=Users,DC=domain,DC=com'
Get-ADUser -Identity 'jdoe@domain.com'
```

#### ERROR_202: Cannot Contact Domain Controller
**Message**: "Unable to contact the server"

**Causes:**
- Domain controller unavailable
- Network connectivity issues
- DNS problems
- Service account issues

**Solutions:**
```powershell
# Check domain controller availability
nltest /dclist:domain.com
nslookup -type=SRV _ldap._tcp.domain.com

# Test connectivity to specific DC
Test-ComputerSecureChannel -Server 'DC01.domain.com'

# Force refresh of domain controller list
ipconfig /flushdns
nltest /dsgetdc:domain.com /force
```

#### ERROR_203: Insufficient Permissions to Modify Object
**Message**: "Insufficient access rights to perform the operation"

**Causes:**
- User lacks required permissions
- Object protected by ACL
- Delegation not configured
- Administrative approval required

**Solutions:**
```powershell
# Check effective permissions
dsacls "CN=John Doe,OU=Users,DC=domain,DC=com"

# Use higher privileged account
$adminCred = Get-Credential -UserName "DOMAIN\Domain Admins"
Unlock-ADAccount -Identity 'jdoe' -Credential $adminCred

# Check delegation settings
Get-ADUser -Identity $env:USERNAME -Properties msDS-AllowedToDelegateTo
```

### Service Management Errors

#### ERROR_301: Service Not Found
**Message**: "Cannot find any service with service name 'SERVICENAME'"

**Causes:**
- Service name misspelled
- Service not installed
- Different service name on target system
- Case sensitivity issues

**Solutions:**
```powershell
# Search for similar service names
Get-Service -ComputerName 'SERVERNAME' | Where-Object {$_.Name -like "*web*"}

# Check service display names
Get-Service -ComputerName 'SERVERNAME' | Where-Object {$_.DisplayName -like "*IIS*"}

# List all services
Get-Service -ComputerName 'SERVERNAME' | Sort-Object Name | Format-Table Name, DisplayName

# Use wildcard searches
Get-Service -ComputerName 'SERVERNAME' -Name "*W3*"
```

#### ERROR_302: Service Cannot Be Stopped
**Message**: "Service cannot be stopped due to the following error: Access is denied"

**Causes:**
- Insufficient permissions
- Service has dependent services
- Service in transition state
- Service marked as non-stoppable

**Solutions:**
```powershell
# Check service dependencies
Get-Service -Name 'SERVICENAME' -DependentServices

# Stop dependent services first
Get-Service -Name 'SERVICENAME' -DependentServices | Stop-Service -Force

# Use elevated privileges
$adminCred = Get-Credential
Stop-Service -Name 'SERVICENAME' -Force -Credential $adminCred

# Check service configuration
Get-WmiObject -Class Win32_Service -Filter "Name='SERVICENAME'" | 
    Select-Object Name, StartMode, State, AcceptStop
```

#### ERROR_303: Service Start Timeout
**Message**: "Service did not start within the specified timeout period"

**Causes:**
- Service initialization taking too long
- Dependency issues
- Resource constraints
- Configuration problems

**Solutions:**
```powershell
# Increase timeout value
Restart-RemoteService -ComputerName 'SERVERNAME' -ServiceName 'SERVICENAME' -TimeoutSeconds 300

# Check service dependencies
Get-Service -Name 'SERVICENAME' -RequiredServices | 
    Where-Object {$_.Status -ne 'Running'}

# Check system resources
Get-ServerHealth -ComputerName 'SERVERNAME' -IncludePerformance

# Check event logs for service startup issues
Get-WinEvent -ComputerName 'SERVERNAME' -FilterHashtable @{LogName='System'; ID=7000,7001,7034}
```

### Process Management Errors

#### ERROR_401: Process Not Found
**Message**: "Cannot find a process with the name 'PROCESSNAME'"

**Causes:**
- Process not running
- Process name misspelled
- Process running under different user context
- Case sensitivity

**Solutions:**
```powershell
# Search for similar process names
Get-Process -ComputerName 'SERVERNAME' | Where-Object {$_.Name -like "*app*"}

# Check all processes with full details
Get-Process -ComputerName 'SERVERNAME' | Sort-Object Name | 
    Format-Table Name, Id, ProcessName -AutoSize

# Search by partial name
Get-Process -ComputerName 'SERVERNAME' | Where-Object {$_.ProcessName -match "app"}

# Include processes from all users
Get-WmiObject -Class Win32_Process -ComputerName 'SERVERNAME' | 
    Where-Object {$_.Name -like "*app*"}
```

#### ERROR_402: Cannot Terminate Process
**Message**: "Access is denied"

**Causes:**
- Insufficient permissions
- System process protection
- Process in protected mode
- Antivirus protection

**Solutions:**
```powershell
# Use elevated privileges
$adminCred = Get-Credential
Stop-ProcessRemotely -ComputerName 'SERVERNAME' -ProcessName 'PROCESSNAME' -Credential $adminCred

# Use force parameter
Stop-ProcessRemotely -ComputerName 'SERVERNAME' -ProcessId 1234 -Force

# Check process security context
Get-WmiObject -Class Win32_Process -ComputerName 'SERVERNAME' -Filter "ProcessId=1234" | 
    Select-Object Name, ProcessId, ExecutablePath, GetOwner()

# Attempt graceful shutdown first
Stop-ProcessRemotely -ComputerName 'SERVERNAME' -ProcessName 'PROCESSNAME' -GracefulShutdown
```

### Performance and Resource Errors

#### ERROR_501: Out of Memory
**Message**: "Insufficient memory to complete the operation"

**Causes:**
- System low on memory
- Memory leak in target process
- Large dataset processing
- Inefficient query

**Solutions:**
```powershell
# Check memory usage
Get-ServerHealth -ComputerName 'SERVERNAME' -IncludePerformance

# Find memory-intensive processes
Get-ProcessByName -ComputerName 'SERVERNAME' -MinMemoryMB 500

# Use filtering to reduce data size
Get-ProcessByName -ComputerName 'SERVERNAME' -ProcessName 'specific_app'

# Process in smaller batches
$servers | ForEach-Object { Get-ServerHealth -ComputerName $_ }
```

#### ERROR_502: High CPU Usage Preventing Operation
**Message**: "Operation failed due to high system load"

**Causes:**
- System under heavy load
- CPU-intensive processes running
- Insufficient system resources
- Multiple simultaneous operations

**Solutions:**
```powershell
# Check CPU usage
Get-ProcessByName -ComputerName 'SERVERNAME' -MinCPUPercent 50

# Wait for system load to decrease
do {
    $cpu = Get-Counter "\\SERVERNAME\Processor(_Total)\% Processor Time"
    Start-Sleep -Seconds 30
} while ($cpu.CounterSamples[0].CookedValue -gt 80)

# Increase timeout to accommodate high load
Get-ServerHealth -ComputerName 'SERVERNAME' -TimeoutSeconds 300

# Schedule operation for off-peak hours
```

## Common Resolution Strategies

### Network Connectivity Issues

**Step-by-Step Diagnosis:**
```powershell
# 1. Basic connectivity test
Test-NetConnection -ComputerName 'SERVERNAME'

# 2. DNS resolution test
Resolve-DnsName 'SERVERNAME'

# 3. Port-specific tests
Test-NetConnection -ComputerName 'SERVERNAME' -Port 5985  # PowerShell Remoting
Test-NetConnection -ComputerName 'SERVERNAME' -Port 3389  # RDP
Test-NetConnection -ComputerName 'SERVERNAME' -Port 445   # File Sharing

# 4. WinRM specific test
Test-WSMan -ComputerName 'SERVERNAME'

# 5. Firewall check (run on target server)
Get-NetFirewallRule -DisplayName "*WinRM*" | Where-Object {$_.Enabled -eq "True"}
```

### Permission Issues

**Escalation Procedure:**
```powershell
# 1. Check current context
whoami
whoami /groups

# 2. Try with explicit credentials
$cred = Get-Credential -UserName "DOMAIN\AdminAccount"
Get-ServerHealth -ComputerName 'SERVERNAME' -Credential $cred

# 3. Check account status
Get-ADUser -Identity $env:USERNAME -Properties LockedOut, Enabled, PasswordExpired

# 4. Use different authentication method
Enter-PSSession -ComputerName 'SERVERNAME' -Authentication Kerberos
```

### Service Dependency Resolution

**Dependency Analysis:**
```powershell
# 1. Identify dependencies
$service = Get-Service -Name 'SERVICENAME' -ComputerName 'SERVERNAME'
$dependencies = $service.ServicesDependedOn
$dependents = Get-Service -ComputerName 'SERVERNAME' | 
    Where-Object {$_.ServicesDependedOn.Name -contains 'SERVICENAME'}

# 2. Check dependency status
$dependencies | Select-Object Name, Status
$dependents | Select-Object Name, Status

# 3. Start dependencies first
$dependencies | Where-Object {$_.Status -ne 'Running'} | Start-Service

# 4. Then start main service
Start-Service -Name 'SERVICENAME'

# 5. Finally start dependents
$dependents | Where-Object {$_.Status -ne 'Running'} | Start-Service
```

## Error Prevention

### Proactive Monitoring

```powershell
# Daily health check script
$servers = Get-Content "C:\Admin\ServerList.txt"
$healthResults = Get-ServerHealth -ComputerName $servers -Parallel

# Identify potential issues
$healthResults | Where-Object {$_.OverallStatus -ne 'Healthy'} | 
    ForEach-Object {
        Write-Warning "Issue detected on $($_.ComputerName): $($_.Issues -join ', ')"
    }
```

### Preventive Configuration

```powershell
# Ensure PowerShell remoting is configured
$servers | ForEach-Object {
    try {
        Test-WSMan -ComputerName $_ -ErrorAction Stop
        Write-Host "✅ $_ - PowerShell remoting OK"
    } catch {
        Write-Warning "❌ $_ - PowerShell remoting needs configuration"
    }
}

# Verify service account permissions
$serviceAccounts = @('SVC_App1', 'SVC_Web')
$serviceAccounts | ForEach-Object {
    $account = Get-ADUser -Identity $_ -Properties PasswordLastSet, PasswordExpired
    if ($account.PasswordExpired) {
        Write-Warning "Service account $_ password has expired"
    }
}
```

### Best Practices for Error Avoidance

1. **Always use -WhatIf first**
2. **Test connectivity before bulk operations**
3. **Use appropriate timeouts for network conditions**
4. **Implement proper error handling in scripts**
5. **Monitor service dependencies**
6. **Keep service account passwords current**
7. **Verify permissions before critical operations**
8. **Use logging for operation tracking**

## Troubleshooting Workflow

### Standard Troubleshooting Steps

1. **Reproduce the issue**
   ```powershell
   # Run the exact same command with -Verbose
   Get-ServerHealth -ComputerName 'SERVERNAME' -Verbose
   ```

2. **Check basic connectivity**
   ```powershell
   Test-NetConnection -ComputerName 'SERVERNAME'
   Test-WSMan -ComputerName 'SERVERNAME'
   ```

3. **Verify permissions**
   ```powershell
   whoami
   $cred = Get-Credential
   Get-ServerHealth -ComputerName 'SERVERNAME' -Credential $cred
   ```

4. **Check event logs**
   ```powershell
   Get-WinEvent -ComputerName 'SERVERNAME' -FilterHashtable @{
       LogName='System'
       StartTime=(Get-Date).AddHours(-1)
   } | Where-Object {$_.LevelDisplayName -eq 'Error'}
   ```

5. **Test with minimal parameters**
   ```powershell
   # Simplify the command to isolate the issue
   Get-Service -ComputerName 'SERVERNAME' -Name 'W3SVC'
   ```

6. **Check system resources**
   ```powershell
   Get-ServerHealth -ComputerName 'SERVERNAME' -IncludePerformance
   ```

---

> **Need Help?** If you encounter errors not covered in this guide, check the [Troubleshooting Guide](../../TROUBLESHOOTING.md) or contact your system administrator.