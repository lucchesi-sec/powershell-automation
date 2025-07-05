# Command Reference

## Overview

Quick reference for all Daily Admin Toolkit functions with syntax, parameters, and common usage examples.

## ActiveDirectory Module

### Unlock-ADAccount

Unlocks user accounts in Active Directory.

**Syntax:**
```powershell
Unlock-ADAccount [-Identity] <string> [-WhatIf] [-Confirm] [-Verbose]
```

**Parameters:**
- `-Identity` - User account to unlock (SamAccountName, Distinguished Name, or GUID)
- `-WhatIf` - Shows what would happen without making changes
- `-Confirm` - Prompts for confirmation before unlocking
- `-Verbose` - Displays detailed operation information

**Examples:**
```powershell
# Basic unlock
Unlock-ADAccount -Identity 'jdoe'

# Unlock with confirmation
Unlock-ADAccount -Identity 'jdoe' -Confirm

# Test what would happen
Unlock-ADAccount -Identity 'jdoe' -WhatIf

# Unlock multiple accounts
@('jdoe', 'jsmith') | ForEach-Object { Unlock-ADAccount -Identity $_ }
```

### Reset-ADUserPassword

Resets user passwords with security options.

**Syntax:**
```powershell
Reset-ADUserPassword [-Identity] <string> [-NewPassword] <SecureString> 
    [-ChangePasswordAtLogon <bool>] [-WhatIf] [-Confirm]
```

**Parameters:**
- `-Identity` - User account to reset password for
- `-NewPassword` - New password as SecureString
- `-ChangePasswordAtLogon` - Force password change at next logon (default: $true)
- `-WhatIf` - Preview changes without execution
- `-Confirm` - Require confirmation before reset

**Examples:**
```powershell
# Interactive password reset
$newPass = Read-Host "Enter password" -AsSecureString
Reset-ADUserPassword -Identity 'jdoe' -NewPassword $newPass

# Programmatic password reset
$pass = ConvertTo-SecureString "TempPass123!" -AsPlainText -Force
Reset-ADUserPassword -Identity 'jdoe' -NewPassword $pass -ChangePasswordAtLogon:$true

# Combined reset and unlock
Reset-ADUserPassword -Identity 'jdoe' -NewPassword $pass
Unlock-ADAccount -Identity 'jdoe'
```

### Get-ADUserLastLogon

Retrieves user last logon information.

**Syntax:**
```powershell
Get-ADUserLastLogon [-Identity] <string> [-AllDomainControllers] 
    [-IncludeDetails] [-Verbose]
```

**Parameters:**
- `-Identity` - User account to query
- `-AllDomainControllers` - Check all domain controllers for most recent logon
- `-IncludeDetails` - Include additional logon details
- `-Verbose` - Show detailed query information

**Examples:**
```powershell
# Basic last logon check
Get-ADUserLastLogon -Identity 'jdoe'

# Check across all DCs
Get-ADUserLastLogon -Identity 'jdoe' -AllDomainControllers

# Get detailed information
Get-ADUserLastLogon -Identity 'jdoe' -IncludeDetails | Format-List

# Check multiple users
@('jdoe', 'jsmith') | ForEach-Object { Get-ADUserLastLogon -Identity $_ }
```

### Get-ADUserMembership

Retrieves user group memberships.

**Syntax:**
```powershell
Get-ADUserMembership [-Identity] <string> [-IncludeDetails] [-Recursive] [-Verbose]
```

**Parameters:**
- `-Identity` - User account to query
- `-IncludeDetails` - Include group properties and details
- `-Recursive` - Include nested group memberships
- `-Verbose` - Display detailed membership information

**Examples:**
```powershell
# Basic group membership
Get-ADUserMembership -Identity 'jdoe'

# Detailed membership with group info
Get-ADUserMembership -Identity 'jdoe' -IncludeDetails | Format-Table

# Include nested groups
Get-ADUserMembership -Identity 'jdoe' -Recursive

# Export to CSV
Get-ADUserMembership -Identity 'jdoe' -IncludeDetails | 
    Export-Csv "UserGroups.csv" -NoTypeInformation
```

## ServerManagement Module

### Get-ServerHealth

Performs comprehensive server health checks.

**Syntax:**
```powershell
Get-ServerHealth [-ComputerName] <string[]> [-Detailed] [-IncludePerformance] 
    [-TimeoutSeconds <int>] [-Credential <PSCredential>]
```

**Parameters:**
- `-ComputerName` - Server(s) to check (accepts array)
- `-Detailed` - Include detailed health metrics
- `-IncludePerformance` - Add performance counters to health check
- `-TimeoutSeconds` - Timeout for remote operations (default: 60)
- `-Credential` - Alternate credentials for remote access

**Examples:**
```powershell
# Basic health check
Get-ServerHealth -ComputerName 'SERVER01'

# Check multiple servers
Get-ServerHealth -ComputerName @('WEB01', 'WEB02', 'DB01')

# Detailed health report
Get-ServerHealth -ComputerName 'SERVER01' -Detailed | Format-List

# Health check with performance data
Get-ServerHealth -ComputerName 'SERVER01' -IncludePerformance
```

### Test-ServerConnectivity

Tests server connectivity and network accessibility.

**Syntax:**
```powershell
Test-ServerConnectivity [-ComputerName] <string[]> [-IncludePorts <int[]>] 
    [-TimeoutSeconds <int>] [-Credential <PSCredential>]
```

**Parameters:**
- `-ComputerName` - Server(s) to test
- `-IncludePorts` - Additional ports to test (default: 5985, 5986, 3389)
- `-TimeoutSeconds` - Connection timeout (default: 30)
- `-Credential` - Credentials for connectivity tests

**Examples:**
```powershell
# Basic connectivity test
Test-ServerConnectivity -ComputerName 'SERVER01'

# Test with custom ports
Test-ServerConnectivity -ComputerName 'WEB01' -IncludePorts @(80, 443, 8080)

# Test multiple servers
Test-ServerConnectivity -ComputerName @('WEB01', 'WEB02') | Format-Table

# Quick timeout for fast checks
Test-ServerConnectivity -ComputerName 'SERVER01' -TimeoutSeconds 10
```

### Get-ServiceStatus

Monitors Windows service status across servers.

**Syntax:**
```powershell
Get-ServiceStatus [-ComputerName] <string[]> [-ServiceName] <string[]> 
    [-IncludeDetails] [-Credential <PSCredential>]
```

**Parameters:**
- `-ComputerName` - Target server(s)
- `-ServiceName` - Service(s) to monitor
- `-IncludeDetails` - Include service configuration details
- `-Credential` - Alternate credentials

**Examples:**
```powershell
# Check specific service
Get-ServiceStatus -ComputerName 'WEB01' -ServiceName 'W3SVC'

# Monitor multiple services
Get-ServiceStatus -ComputerName 'WEB01' -ServiceName @('W3SVC', 'WAS', 'IIS')

# Check across multiple servers
$servers = @('WEB01', 'WEB02', 'WEB03')
Get-ServiceStatus -ComputerName $servers -ServiceName 'W3SVC' | Format-Table

# Detailed service information
Get-ServiceStatus -ComputerName 'WEB01' -ServiceName 'W3SVC' -IncludeDetails
```

## ServiceManagement Module

### Restart-RemoteService

Safely restarts Windows services on remote servers.

**Syntax:**
```powershell
Restart-RemoteService [-ComputerName] <string[]> [-ServiceName] <string[]> 
    [-WaitForStart] [-TimeoutSeconds <int>] [-CheckDependencies] 
    [-RestartDependents] [-Parallel] [-WhatIf] [-Confirm]
```

**Parameters:**
- `-ComputerName` - Target server(s)
- `-ServiceName` - Service(s) to restart
- `-WaitForStart` - Wait for service to fully start before continuing
- `-TimeoutSeconds` - Maximum wait time for restart (default: 300)
- `-CheckDependencies` - Verify dependencies before restart
- `-RestartDependents` - Also restart dependent services
- `-Parallel` - Process multiple servers simultaneously
- `-WhatIf` - Preview restart actions
- `-Confirm` - Require confirmation

**Examples:**
```powershell
# Basic service restart
Restart-RemoteService -ComputerName 'WEB01' -ServiceName 'W3SVC'

# Safe restart with dependency checking
Restart-RemoteService -ComputerName 'WEB01' -ServiceName 'W3SVC' -CheckDependencies -WaitForStart

# Restart across multiple servers
Restart-RemoteService -ComputerName @('WEB01', 'WEB02') -ServiceName 'W3SVC' -Parallel

# Test restart operation
Restart-RemoteService -ComputerName 'WEB01' -ServiceName 'W3SVC' -WhatIf
```

### Get-ProcessByName

Finds and monitors processes by name across servers.

**Syntax:**
```powershell
Get-ProcessByName [-ComputerName] <string[]> [-ProcessName] <string[]> 
    [-IncludeDetails] [-MinCPUPercent <double>] [-MinMemoryMB <int>] 
    [-Credential <PSCredential>]
```

**Parameters:**
- `-ComputerName` - Target server(s)
- `-ProcessName` - Process name(s) to find
- `-IncludeDetails` - Include detailed process information
- `-MinCPUPercent` - Filter by minimum CPU usage
- `-MinMemoryMB` - Filter by minimum memory usage (MB)
- `-Credential` - Alternate credentials

**Examples:**
```powershell
# Find processes by name
Get-ProcessByName -ComputerName 'SERVER01' -ProcessName 'notepad'

# Find high-resource processes
Get-ProcessByName -ComputerName 'SERVER01' -MinCPUPercent 50 -MinMemoryMB 500

# Detailed process information
Get-ProcessByName -ComputerName 'WEB01' -ProcessName 'w3wp' -IncludeDetails

# Monitor across multiple servers
Get-ProcessByName -ComputerName @('WEB01', 'WEB02') -ProcessName 'w3wp' | Format-Table
```

### Stop-ProcessRemotely

Safely terminates processes on remote servers.

**Syntax:**
```powershell
Stop-ProcessRemotely [-ComputerName] <string[]> 
    {[-ProcessName] <string[]> | [-ProcessId] <int[]>} 
    [-GracefulShutdown] [-TimeoutSeconds <int>] [-Force] 
    [-WhatIf] [-Confirm] [-Credential <PSCredential>]
```

**Parameters:**
- `-ComputerName` - Target server(s)
- `-ProcessName` - Process name(s) to stop
- `-ProcessId` - Process ID(s) to stop
- `-GracefulShutdown` - Attempt graceful shutdown before force kill
- `-TimeoutSeconds` - Graceful shutdown timeout (default: 30)
- `-Force` - Force termination without graceful shutdown
- `-WhatIf` - Preview termination actions
- `-Confirm` - Require confirmation
- `-Credential` - Alternate credentials

**Examples:**
```powershell
# Graceful process termination
Stop-ProcessRemotely -ComputerName 'SERVER01' -ProcessName 'notepad' -GracefulShutdown

# Force terminate by process ID
Stop-ProcessRemotely -ComputerName 'SERVER01' -ProcessId 1234 -Force

# Stop processes with confirmation
Stop-ProcessRemotely -ComputerName 'SERVER01' -ProcessName 'badapp' -Confirm

# Test termination
Stop-ProcessRemotely -ComputerName 'SERVER01' -ProcessName 'testapp' -WhatIf
```

## Common Parameters

All Daily Admin Toolkit functions support these standard PowerShell parameters:

### Risk Mitigation Parameters
- `-WhatIf` - Shows what would happen without making changes
- `-Confirm` - Prompts for confirmation before executing
- `-Verbose` - Displays detailed operation information
- `-Debug` - Shows debugging information
- `-ErrorAction` - Controls error handling behavior

### Common Usage Patterns

**Testing Operations:**
```powershell
# Always test first
Get-ServerHealth -ComputerName 'SERVER01' -WhatIf
Restart-RemoteService -ComputerName 'WEB01' -ServiceName 'W3SVC' -WhatIf
```

**Batch Operations:**
```powershell
# Process multiple targets
$servers = @('WEB01', 'WEB02', 'WEB03')
$servers | ForEach-Object { Get-ServerHealth -ComputerName $_ }
```

**Pipeline Processing:**
```powershell
# Use pipeline for efficiency
Get-Content "ServerList.txt" | 
    Get-ServerHealth | 
    Where-Object { $_.Status -ne 'Healthy' } |
    Format-Table -AutoSize
```

**Error Handling:**
```powershell
# Graceful error handling
try {
    Unlock-ADAccount -Identity 'jdoe' -ErrorAction Stop
    Write-Host "Account unlocked successfully" -ForegroundColor Green
} catch {
    Write-Warning "Failed to unlock account: $($_.Exception.Message)"
}
```

**Credential Management:**
```powershell
# Using alternate credentials
$cred = Get-Credential -Message "Enter admin credentials"
Get-ServerHealth -ComputerName 'REMOTESERVER' -Credential $cred
```

## Output Formatting

### Common Formatting Options

**Table Format:**
```powershell
Get-ServiceStatus -ComputerName $servers -ServiceName 'W3SVC' | Format-Table -AutoSize
```

**List Format:**
```powershell
Get-ServerHealth -ComputerName 'SERVER01' -Detailed | Format-List
```

**CSV Export:**
```powershell
Get-ADUserMembership -Identity 'jdoe' -IncludeDetails | 
    Export-Csv "UserGroups.csv" -NoTypeInformation
```

**HTML Report:**
```powershell
Get-ServerHealth -ComputerName $servers | 
    ConvertTo-Html -Title "Server Health Report" | 
    Out-File "HealthReport.html"
```

**GridView (Interactive):**
```powershell
Get-ProcessByName -ComputerName 'SERVER01' -IncludeDetails | Out-GridView
```

## Quick Troubleshooting

### Connection Issues
```powershell
# Test basic connectivity
Test-WSMan -ComputerName 'SERVER01'
Test-NetConnection -ComputerName 'SERVER01' -Port 5985

# Verify credentials
$cred = Get-Credential
Test-ServerConnectivity -ComputerName 'SERVER01' -Credential $cred
```

### Permission Issues
```powershell
# Check current user context
whoami
whoami /groups

# Test with explicit credentials
$adminCred = Get-Credential -UserName "DOMAIN\Administrator"
Get-ServerHealth -ComputerName 'SERVER01' -Credential $adminCred
```

### Service Issues
```powershell
# Verify service exists
Get-Service -Name 'ServiceName' -ComputerName 'SERVER01'

# Check service dependencies
Get-Service -Name 'W3SVC' -ComputerName 'WEB01' -DependentServices
Get-Service -Name 'W3SVC' -ComputerName 'WEB01' -RequiredServices
```

---

> **Next**: See [Parameter Guide](parameter-guide.md) for detailed parameter explanations and [Error Codes](error-codes.md) for troubleshooting reference.