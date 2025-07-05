# Parameter Guide

## Overview

Comprehensive guide to parameters used across Daily Admin Toolkit functions, including common patterns, best practices, and advanced usage scenarios.

## Common Parameter Types

### Identity Parameters

Used to specify target users, computers, or services.

**-Identity**
- **Type**: String
- **Used in**: All ActiveDirectory functions
- **Accepts**: SamAccountName, Distinguished Name, GUID, UPN
- **Examples**:
  ```powershell
  -Identity 'jdoe'                    # SamAccountName
  -Identity 'CN=John Doe,OU=Users,DC=contoso,DC=com'  # DN
  -Identity 'jdoe@contoso.com'        # UPN
  -Identity '{12345678-1234-1234-1234-123456789012}'  # GUID
  ```

**-ComputerName**
- **Type**: String[]
- **Used in**: All ServerManagement and ServiceManagement functions
- **Accepts**: NetBIOS names, FQDN, IP addresses, arrays
- **Examples**:
  ```powershell
  -ComputerName 'SERVER01'                    # Single server
  -ComputerName @('WEB01', 'WEB02', 'WEB03')  # Multiple servers
  -ComputerName 'server01.contoso.com'       # FQDN
  -ComputerName '192.168.1.100'              # IP address
  ```

**-ServiceName**
- **Type**: String[]
- **Used in**: ServiceManagement functions
- **Accepts**: Service names, display names, arrays
- **Examples**:
  ```powershell
  -ServiceName 'W3SVC'                        # Single service
  -ServiceName @('W3SVC', 'WAS', 'IIS')       # Multiple services
  -ServiceName 'World Wide Web Publishing Service'  # Display name
  ```

### Control Parameters

Parameters that modify function behavior and execution.

**-WhatIf**
- **Type**: Switch
- **Purpose**: Preview changes without execution
- **Available in**: All functions that modify state
- **Usage**: Always use when testing new scripts
- **Examples**:
  ```powershell
  Unlock-ADAccount -Identity 'jdoe' -WhatIf
  Restart-RemoteService -ComputerName 'WEB01' -ServiceName 'W3SVC' -WhatIf
  ```

**-Confirm**
- **Type**: Switch
- **Purpose**: Prompt for confirmation before execution
- **Available in**: All functions that modify state
- **Usage**: Use for interactive operations or critical changes
- **Examples**:
  ```powershell
  Reset-ADUserPassword -Identity 'jdoe' -NewPassword $pass -Confirm
  Stop-ProcessRemotely -ComputerName 'SERVER01' -ProcessName 'critical' -Confirm
  ```

**-Force**
- **Type**: Switch
- **Purpose**: Override safety checks and force execution
- **Available in**: Restart-RemoteService, Stop-ProcessRemotely
- **Usage**: Use with caution, only when standard methods fail
- **Examples**:
  ```powershell
  Stop-ProcessRemotely -ComputerName 'SERVER01' -ProcessId 1234 -Force
  Restart-RemoteService -ComputerName 'WEB01' -ServiceName 'W3SVC' -Force
  ```

### Information Parameters

Parameters that control the amount and type of information returned.

**-IncludeDetails**
- **Type**: Switch
- **Purpose**: Return additional detailed information
- **Available in**: Most query functions
- **Impact**: Slower execution but more comprehensive data
- **Examples**:
  ```powershell
  Get-ADUserLastLogon -Identity 'jdoe' -IncludeDetails
  Get-ServiceStatus -ComputerName 'WEB01' -ServiceName 'W3SVC' -IncludeDetails
  ```

**-Detailed**
- **Type**: Switch
- **Purpose**: Perform comprehensive analysis
- **Available in**: Get-ServerHealth
- **Impact**: Significantly more data and longer execution time
- **Examples**:
  ```powershell
  Get-ServerHealth -ComputerName 'SERVER01' -Detailed
  ```

**-Verbose**
- **Type**: Switch
- **Purpose**: Display detailed operation progress
- **Available in**: All functions
- **Usage**: Troubleshooting and understanding function behavior
- **Examples**:
  ```powershell
  Unlock-ADAccount -Identity 'jdoe' -Verbose
  Get-ServerHealth -ComputerName 'SERVER01' -Verbose
  ```

### Timeout and Performance Parameters

Parameters that control timing and performance characteristics.

**-TimeoutSeconds**
- **Type**: Integer
- **Purpose**: Set maximum wait time for operations
- **Default**: Varies by function (30-300 seconds)
- **Available in**: Most remote operations
- **Usage**: Adjust based on network conditions and requirements
- **Examples**:
  ```powershell
  Test-ServerConnectivity -ComputerName 'REMOTE01' -TimeoutSeconds 60
  Restart-RemoteService -ComputerName 'WEB01' -ServiceName 'W3SVC' -TimeoutSeconds 180
  ```

**-Parallel**
- **Type**: Switch
- **Purpose**: Process multiple targets simultaneously
- **Available in**: Functions supporting multiple computers
- **Benefits**: Faster execution for multiple targets
- **Considerations**: Higher resource usage
- **Examples**:
  ```powershell
  Restart-RemoteService -ComputerName @('WEB01', 'WEB02') -ServiceName 'W3SVC' -Parallel
  Get-ServerHealth -ComputerName $serverList -Parallel
  ```

### Security Parameters

Parameters related to authentication and security.

**-Credential**
- **Type**: PSCredential
- **Purpose**: Specify alternate credentials for remote operations
- **Available in**: All remote functions
- **Usage**: When current user lacks necessary permissions
- **Examples**:
  ```powershell
  $cred = Get-Credential -UserName "DOMAIN\Administrator"
  Get-ServerHealth -ComputerName 'SERVER01' -Credential $cred
  Test-ServerConnectivity -ComputerName 'REMOTE01' -Credential $cred
  ```

**-NewPassword**
- **Type**: SecureString
- **Purpose**: Specify new password for reset operations
- **Available in**: Reset-ADUserPassword
- **Security**: Always use SecureString, never plain text
- **Examples**:
  ```powershell
  $newPass = Read-Host "Enter password" -AsSecureString
  Reset-ADUserPassword -Identity 'jdoe' -NewPassword $newPass
  
  $plainPass = "TempPass123!"
  $securePass = ConvertTo-SecureString $plainPass -AsPlainText -Force
  Reset-ADUserPassword -Identity 'jdoe' -NewPassword $securePass
  ```

### Filtering Parameters

Parameters that filter results based on specific criteria.

**-MinCPUPercent**
- **Type**: Double
- **Purpose**: Filter processes by minimum CPU usage
- **Available in**: Get-ProcessByName
- **Range**: 0.0 to 100.0
- **Examples**:
  ```powershell
  Get-ProcessByName -ComputerName 'SERVER01' -MinCPUPercent 50.0
  ```

**-MinMemoryMB**
- **Type**: Integer
- **Purpose**: Filter processes by minimum memory usage
- **Available in**: Get-ProcessByName
- **Unit**: Megabytes
- **Examples**:
  ```powershell
  Get-ProcessByName -ComputerName 'SERVER01' -MinMemoryMB 500
  ```

**-IncludePorts**
- **Type**: Integer[]
- **Purpose**: Specify additional ports to test
- **Available in**: Test-ServerConnectivity
- **Default**: 5985, 5986, 3389 (PowerShell remoting and RDP)
- **Examples**:
  ```powershell
  Test-ServerConnectivity -ComputerName 'WEB01' -IncludePorts @(80, 443, 8080)
  ```

### Scope Parameters

Parameters that control the scope of operations.

**-AllDomainControllers**
- **Type**: Switch
- **Purpose**: Query all domain controllers for most recent data
- **Available in**: Get-ADUserLastLogon
- **Impact**: Slower but more accurate results
- **Examples**:
  ```powershell
  Get-ADUserLastLogon -Identity 'jdoe' -AllDomainControllers
  ```

**-Recursive**
- **Type**: Switch
- **Purpose**: Include nested group memberships
- **Available in**: Get-ADUserMembership
- **Impact**: More comprehensive but slower results
- **Examples**:
  ```powershell
  Get-ADUserMembership -Identity 'jdoe' -Recursive
  ```

**-CheckDependencies**
- **Type**: Switch
- **Purpose**: Verify and handle service dependencies
- **Available in**: Restart-RemoteService
- **Impact**: Safer operations but longer execution time
- **Examples**:
  ```powershell
  Restart-RemoteService -ComputerName 'WEB01' -ServiceName 'W3SVC' -CheckDependencies
  ```

**-RestartDependents**
- **Type**: Switch
- **Purpose**: Also restart services that depend on the target service
- **Available in**: Restart-RemoteService
- **Impact**: More comprehensive but affects more services
- **Examples**:
  ```powershell
  Restart-RemoteService -ComputerName 'WEB01' -ServiceName 'W3SVC' -RestartDependents
  ```

### Process Management Parameters

Specialized parameters for process operations.

**-ProcessName**
- **Type**: String[]
- **Purpose**: Target processes by name
- **Available in**: Get-ProcessByName, Stop-ProcessRemotely
- **Mutually exclusive with**: -ProcessId
- **Examples**:
  ```powershell
  Get-ProcessByName -ComputerName 'SERVER01' -ProcessName 'notepad'
  Stop-ProcessRemotely -ComputerName 'SERVER01' -ProcessName @('app1', 'app2')
  ```

**-ProcessId**
- **Type**: Integer[]
- **Purpose**: Target processes by ID
- **Available in**: Stop-ProcessRemotely
- **Mutually exclusive with**: -ProcessName
- **Examples**:
  ```powershell
  Stop-ProcessRemotely -ComputerName 'SERVER01' -ProcessId 1234
  Stop-ProcessRemotely -ComputerName 'SERVER01' -ProcessId @(1234, 5678)
  ```

**-GracefulShutdown**
- **Type**: Switch
- **Purpose**: Attempt graceful process termination before force kill
- **Available in**: Stop-ProcessRemotely
- **Recommended**: Always use unless immediate termination required
- **Examples**:
  ```powershell
  Stop-ProcessRemotely -ComputerName 'SERVER01' -ProcessName 'myapp' -GracefulShutdown
  ```

### Service Management Parameters

Specialized parameters for service operations.

**-WaitForStart**
- **Type**: Switch
- **Purpose**: Wait for service to fully start before continuing
- **Available in**: Restart-RemoteService
- **Recommended**: Use for critical services requiring verification
- **Examples**:
  ```powershell
  Restart-RemoteService -ComputerName 'WEB01' -ServiceName 'W3SVC' -WaitForStart
  ```

**-ChangePasswordAtLogon**
- **Type**: Boolean
- **Purpose**: Force user to change password at next logon
- **Available in**: Reset-ADUserPassword
- **Default**: $true
- **Examples**:
  ```powershell
  Reset-ADUserPassword -Identity 'jdoe' -NewPassword $pass -ChangePasswordAtLogon:$false
  ```

## Parameter Combination Patterns

### Safety-First Pattern
Always test operations before execution:
```powershell
# Pattern: Test → Confirm → Execute
Restart-RemoteService -ComputerName 'WEB01' -ServiceName 'W3SVC' -WhatIf
Restart-RemoteService -ComputerName 'WEB01' -ServiceName 'W3SVC' -Confirm
Restart-RemoteService -ComputerName 'WEB01' -ServiceName 'W3SVC' -Verbose
```

### Comprehensive Monitoring Pattern
Get maximum information for analysis:
```powershell
Get-ServerHealth -ComputerName 'SERVER01' -Detailed -IncludePerformance -Verbose
Get-ADUserLastLogon -Identity 'jdoe' -AllDomainControllers -IncludeDetails
```

### Batch Processing Pattern
Efficient operations across multiple targets:
```powershell
$servers = @('WEB01', 'WEB02', 'WEB03')
Get-ServerHealth -ComputerName $servers -Parallel -TimeoutSeconds 60
Restart-RemoteService -ComputerName $servers -ServiceName 'W3SVC' -Parallel -WaitForStart
```

### High-Security Pattern
Maximum security and verification:
```powershell
$adminCred = Get-Credential -UserName "DOMAIN\Administrator"
Restart-RemoteService -ComputerName 'PROD01' -ServiceName 'CriticalApp' -Credential $adminCred -CheckDependencies -WaitForStart -Confirm
```

### Performance Tuning Pattern
Optimized for speed and efficiency:
```powershell
# Fast connectivity check
Test-ServerConnectivity -ComputerName $servers -TimeoutSeconds 10 -Parallel

# Quick health assessment
Get-ServerHealth -ComputerName $servers -TimeoutSeconds 30 -Parallel
```

## Error Handling Parameters

### ErrorAction Parameter
Controls how functions respond to errors:

**Values:**
- `Stop` - Terminate on first error
- `Continue` - Display error and continue (default)
- `SilentlyContinue` - Suppress errors and continue
- `Inquire` - Prompt user for action

**Examples:**
```powershell
# Stop on any error
Get-ServerHealth -ComputerName $servers -ErrorAction Stop

# Continue despite errors
Get-ServiceStatus -ComputerName $servers -ServiceName 'W3SVC' -ErrorAction Continue

# Suppress error messages
Test-ServerConnectivity -ComputerName $servers -ErrorAction SilentlyContinue
```

### ErrorVariable Parameter
Capture errors for later analysis:
```powershell
Get-ServerHealth -ComputerName $servers -ErrorAction SilentlyContinue -ErrorVariable healthErrors
if ($healthErrors) {
    Write-Warning "Encountered $($healthErrors.Count) errors during health check"
    $healthErrors | ForEach-Object { Write-Host "Error: $($_.Exception.Message)" }
}
```

## Advanced Parameter Usage

### Dynamic Parameter Values
Using variables and expressions:
```powershell
# Dynamic timeout based on server count
$timeout = [Math]::Max(30, $servers.Count * 10)
Get-ServerHealth -ComputerName $servers -TimeoutSeconds $timeout

# Conditional parameter usage
$includeDetails = $servers.Count -le 5
Get-ServerHealth -ComputerName $servers -Detailed:$includeDetails
```

### Parameter Splatting
Clean way to pass multiple parameters:
```powershell
$healthParams = @{
    ComputerName = @('WEB01', 'WEB02', 'WEB03')
    Detailed = $true
    IncludePerformance = $true
    TimeoutSeconds = 120
    Parallel = $true
    Verbose = $true
}
Get-ServerHealth @healthParams
```

### Pipeline Parameter Binding
Passing objects through pipeline:
```powershell
# Computer names from pipeline
Get-Content "ServerList.txt" | Get-ServerHealth -Detailed

# Service restart with pipeline input
@('W3SVC', 'WAS') | ForEach-Object { 
    Restart-RemoteService -ComputerName 'WEB01' -ServiceName $_ -WaitForStart 
}
```

## Best Practices

### Parameter Selection Guidelines

1. **Always use -WhatIf first** for destructive operations
2. **Use -Verbose** when troubleshooting
3. **Set appropriate timeouts** based on network conditions
4. **Use -Parallel** for multiple targets when possible
5. **Specify -Credential** when working across security boundaries
6. **Use -IncludeDetails** only when needed (performance impact)
7. **Combine -CheckDependencies with service operations** for safety

### Common Mistakes to Avoid

1. **Not using -WhatIf before production changes**
2. **Using -Force without understanding implications**
3. **Not setting timeouts for slow networks**
4. **Ignoring -Credential requirements for remote servers**
5. **Using -Detailed unnecessarily (performance impact)**
6. **Not handling errors appropriately**

### Performance Optimization

1. **Use -Parallel for multiple targets**
2. **Set reasonable timeouts**
3. **Avoid -IncludeDetails unless necessary**
4. **Use filtering parameters to reduce data**
5. **Consider -ErrorAction SilentlyContinue for large batches**

---

> **Next**: See [Error Codes Reference](error-codes.md) for troubleshooting common issues.