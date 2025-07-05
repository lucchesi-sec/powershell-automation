# Prerequisites

## Overview

This guide covers all prerequisites and requirements for installing and using the Daily Admin Toolkit effectively in your environment.

## System Requirements

### PowerShell Version Requirements

**Minimum Requirements:**
- **PowerShell 5.1** (Windows PowerShell)
- **PowerShell 7.0+** (PowerShell Core) - Recommended for best performance

**Compatibility:**
- Windows Server 2016 and later
- Windows 10 and later
- Cross-platform support with PowerShell 7.x

**Version Check:**
```powershell
# Check PowerShell version
$PSVersionTable.PSVersion

# Check PowerShell edition
$PSVersionTable.PSEdition

# Recommended: PowerShell 7.x for optimal performance
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Warning "Consider upgrading to PowerShell 7.x for enhanced features"
}
```

### Operating System Support

**Windows Server:**
- Windows Server 2016 (PowerShell 5.1)
- Windows Server 2019 (PowerShell 5.1 + optional PowerShell 7.x)
- Windows Server 2022 (PowerShell 5.1 + PowerShell 7.x)

**Windows Client:**
- Windows 10 (version 1607 and later)
- Windows 11 (all versions)

**Cross-Platform (PowerShell 7.x only):**
- Linux (Ubuntu 18.04+, CentOS 7+, RHEL 7+)
- macOS (10.13+)

## Required Windows Features and Tools

### Remote Server Administration Tools (RSAT)

**For Windows 10/11:**
```powershell
# Install RSAT tools via Windows Features
Get-WindowsCapability -Online | Where-Object {$_.Name -like "*RSAT*"} | 
    Add-WindowsCapability -Online

# Verify Active Directory module
Get-Module -ListAvailable ActiveDirectory
```

**For Windows Server:**
```powershell
# RSAT tools are typically included, but verify installation
Get-WindowsFeature -Name *RSAT* | Where-Object {$_.InstallState -eq "Available"}

# Install if needed
Install-WindowsFeature RSAT-AD-PowerShell, RSAT-AD-AdminCenter, RSAT-ADDS-Tools
```

### Required PowerShell Modules

**ActiveDirectory Module:**
```powershell
# Check if installed
Get-Module -ListAvailable ActiveDirectory

# Import and test
Import-Module ActiveDirectory
Get-ADDomain  # Should return domain information
```

**Hyper-V Module (for server management):**
```powershell
# Check availability
Get-Module -ListAvailable Hyper-V

# Install on Windows 10/11 (if using Hyper-V)
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
```

### Windows Management Framework (WMF)

**For older systems:**
- Windows Server 2012 R2: Install WMF 5.1
- Windows 8.1: Install WMF 5.1

**Download and Installation:**
1. Download WMF 5.1 from Microsoft Download Center
2. Install appropriate version for your OS
3. Restart system after installation
4. Verify installation:
   ```powershell
   $PSVersionTable.PSVersion  # Should show 5.1.x
   ```

## Network and Security Requirements

### PowerShell Remoting Configuration

**Enable PowerShell Remoting:**
```powershell
# On target servers (run as Administrator)
Enable-PSRemoting -Force

# Configure trusted hosts (if needed for workgroup environments)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*.domain.com" -Force

# Verify configuration
Test-WSMan
Get-PSSessionConfiguration
```

**Firewall Configuration:**
```powershell
# Check Windows Firewall rules
Get-NetFirewallRule -DisplayName "*WinRM*" | Where-Object {$_.Enabled -eq "True"}

# Enable WinRM through firewall (if not already enabled)
Enable-PSRemoting -Force  # This also configures firewall rules

# Manual firewall rule creation (if needed)
New-NetFirewallRule -DisplayName "PowerShell Remoting HTTP" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow
New-NetFirewallRule -DisplayName "PowerShell Remoting HTTPS" -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow
```

### Network Connectivity Requirements

**Required Ports:**
- **5985** - PowerShell Remoting (HTTP)
- **5986** - PowerShell Remoting (HTTPS)
- **3389** - RDP (for manual access)
- **445** - SMB (for file operations)
- **135** - RPC Endpoint Mapper
- **Dynamic RPC** - Typically 1024-1034 or 49152-65535

**Network Testing:**
```powershell
# Test basic connectivity
Test-NetConnection -ComputerName 'TARGET_SERVER' -Port 5985

# Test PowerShell remoting specifically
Test-WSMan -ComputerName 'TARGET_SERVER'

# Comprehensive connectivity test
$servers = @('SERVER01', 'SERVER02', 'SERVER03')
$servers | ForEach-Object {
    $result = Test-NetConnection -ComputerName $_ -Port 5985 -InformationLevel Quiet
    Write-Host "$_`: $($result ? 'Connected' : 'Failed')"
}
```

### DNS Requirements

**DNS Configuration:**
- Forward and reverse DNS resolution for all target servers
- Domain controllers must be resolvable
- Short names and FQDNs should both work

**DNS Testing:**
```powershell
# Test DNS resolution
Resolve-DnsName 'TARGET_SERVER'
Resolve-DnsName 'TARGET_SERVER.domain.com'

# Test reverse lookup
Resolve-DnsName '192.168.1.100'

# Check DNS servers
Get-DnsClientServerAddress
```

## Security and Permissions

### User Account Requirements

**Minimum Permissions:**
- **Local Logon Rights** on target systems
- **Remote Management Users** group membership (or equivalent)
- **Service Control Manager** access for service operations
- **Performance Monitor Users** for performance data

**Active Directory Permissions:**
- **Account Operators** (or delegated permissions) for user management
- **Read access** to user objects and containers
- **Reset Password** and **Unlock Account** permissions

**Service Account Considerations:**
```powershell
# Check current user permissions
whoami
whoami /groups

# Test AD permissions
try {
    Get-ADUser -Identity $env:USERNAME
    Write-Host "✅ AD read access confirmed"
} catch {
    Write-Warning "❌ AD read access denied"
}

# Test unlock permissions (safe test)
try {
    # This will fail gracefully if user doesn't exist or no permissions
    Unlock-ADAccount -Identity 'NonExistentUser123' -WhatIf
    Write-Host "✅ AD unlock permissions confirmed"
} catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
    Write-Host "✅ AD unlock permissions confirmed (test user not found is expected)"
} catch {
    Write-Warning "❌ AD unlock permissions denied: $($_.Exception.Message)"
}
```

### Execution Policy Configuration

**Recommended Settings:**
```powershell
# Check current execution policy
Get-ExecutionPolicy -List

# Recommended setting for administrative workstations
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

# For server environments (if needed)
Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force

# Verify configuration
Get-ExecutionPolicy -List | Format-Table -AutoSize
```

### Credential Management

**Best Practices:**
- Use Windows Credential Manager for stored credentials
- Implement service accounts for automation
- Use Group Managed Service Accounts (gMSA) where possible
- Avoid hardcoded credentials in scripts

**Credential Testing:**
```powershell
# Test credential validity
$cred = Get-Credential -Message "Enter admin credentials"
try {
    Get-ADUser -Identity $env:USERNAME -Credential $cred
    Write-Host "✅ Credentials validated"
} catch {
    Write-Warning "❌ Credential validation failed"
}

# Store credentials securely (for testing only)
$cred | Export-Clixml -Path "$env:USERPROFILE\test_cred.xml"
$savedCred = Import-Clixml -Path "$env:USERPROFILE\test_cred.xml"
```

## Environment-Specific Requirements

### Domain Environment

**Domain Controller Access:**
- Network connectivity to domain controllers
- DNS resolution for domain services
- Time synchronization with domain

**Trust Relationships:**
```powershell
# Test domain trust
Test-ComputerSecureChannel

# Check domain controllers
nltest /dclist:domain.com

# Verify time sync
w32tm /query /status
```

### Workgroup Environment

**Additional Configuration:**
```powershell
# Configure trusted hosts for workgroup
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.1.*" -Force

# Use NTLM authentication
$sessionOptions = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
Enter-PSSession -ComputerName 'TARGET' -Credential $cred -SessionOption $sessionOptions
```

### Multi-Domain Environment

**Cross-Domain Configuration:**
```powershell
# Test cross-domain connectivity
Get-ADTrust -Filter * | Select-Object Name, Direction, TrustType

# Specify domain in AD operations
Get-ADUser -Identity 'user' -Server 'otherdomain.com'
```

## Performance and Scalability

### Memory Requirements

**Minimum Requirements:**
- **4 GB RAM** for basic operations
- **8 GB RAM** for moderate server management (10-50 servers)
- **16 GB RAM** for large environments (100+ servers)

**Memory Testing:**
```powershell
# Check available memory
Get-CimInstance -ClassName Win32_ComputerSystem | 
    Select-Object @{Name='TotalRAM_GB';Expression={[math]::Round($_.TotalPhysicalMemory/1GB,2)}}

# Monitor memory during operations
Get-Process PowerShell* | Select-Object Name, WorkingSet, PagedMemorySize
```

### Concurrent Connection Limits

**PowerShell Remoting Limits:**
- Default: 25 concurrent sessions per user
- Maximum: 100 concurrent sessions per system (configurable)

**Configuration:**
```powershell
# Check current limits
Get-PSSessionConfiguration | Select-Object Name, MaxShellsPerUser, MaxConcurrentUsers

# Increase limits if needed (run as Administrator)
Set-PSSessionConfiguration -Name Microsoft.PowerShell -MaxShellsPerUser 50 -Force
```

## Validation and Testing

### Comprehensive Environment Test

```powershell
# Daily Admin Toolkit Prerequisites Test
function Test-DailyAdminToolkitPrerequisites {
    param(
        [string[]]$TestServers = @('localhost'),
        [switch]$IncludeAD
    )
    
    $results = @{
        TestDate = Get-Date
        OverallStatus = "Unknown"
        Tests = @()
    }
    
    # Test 1: PowerShell Version
    $psVersion = $PSVersionTable.PSVersion
    $results.Tests += @{
        Test = "PowerShell Version"
        Status = if ($psVersion.Major -ge 7) { "✅ Excellent (v$psVersion)" }
                elseif ($psVersion.Major -eq 5 -and $psVersion.Minor -ge 1) { "✅ Good (v$psVersion)" }
                else { "❌ Insufficient (v$psVersion)" }
        Details = "Detected PowerShell $psVersion"
    }
    
    # Test 2: Execution Policy
    $execPolicy = Get-ExecutionPolicy
    $results.Tests += @{
        Test = "Execution Policy"
        Status = if ($execPolicy -in @('RemoteSigned', 'Unrestricted')) { "✅ Appropriate ($execPolicy)" }
                else { "⚠️ Restrictive ($execPolicy)" }
        Details = "Current policy: $execPolicy"
    }
    
    # Test 3: Required Modules
    $requiredModules = @('ActiveDirectory')
    foreach ($module in $requiredModules) {
        $moduleAvailable = Get-Module -ListAvailable $module
        $results.Tests += @{
            Test = "$module Module"
            Status = if ($moduleAvailable) { "✅ Available" } else { "❌ Missing" }
            Details = if ($moduleAvailable) { "Version $($moduleAvailable.Version)" } else { "Not installed" }
        }
    }
    
    # Test 4: Network Connectivity
    foreach ($server in $TestServers) {
        $pingResult = Test-Connection -ComputerName $server -Count 1 -Quiet
        $results.Tests += @{
            Test = "Connectivity to $server"
            Status = if ($pingResult) { "✅ Connected" } else { "❌ Failed" }
            Details = if ($pingResult) { "Ping successful" } else { "No response" }
        }
        
        # Test PowerShell remoting if not localhost
        if ($server -ne 'localhost') {
            try {
                Test-WSMan -ComputerName $server -ErrorAction Stop | Out-Null
                $results.Tests += @{
                    Test = "PowerShell Remoting to $server"
                    Status = "✅ Available"
                    Details = "WinRM responding"
                }
            } catch {
                $results.Tests += @{
                    Test = "PowerShell Remoting to $server"
                    Status = "❌ Failed"
                    Details = $_.Exception.Message
                }
            }
        }
    }
    
    # Test 5: Active Directory (if requested)
    if ($IncludeAD) {
        try {
            $domain = Get-ADDomain -ErrorAction Stop
            $results.Tests += @{
                Test = "Active Directory Connectivity"
                Status = "✅ Connected"
                Details = "Domain: $($domain.DNSRoot)"
            }
            
            # Test AD permissions
            try {
                Get-ADUser -Identity $env:USERNAME -ErrorAction Stop | Out-Null
                $results.Tests += @{
                    Test = "AD Read Permissions"
                    Status = "✅ Confirmed"
                    Details = "Can read user objects"
                }
            } catch {
                $results.Tests += @{
                    Test = "AD Read Permissions"
                    Status = "❌ Insufficient"
                    Details = $_.Exception.Message
                }
            }
        } catch {
            $results.Tests += @{
                Test = "Active Directory Connectivity"
                Status = "❌ Failed"
                Details = $_.Exception.Message
            }
        }
    }
    
    # Overall assessment
    $failedTests = ($results.Tests | Where-Object { $_.Status -like "*❌*" }).Count
    $warningTests = ($results.Tests | Where-Object { $_.Status -like "*⚠️*" }).Count
    
    $results.OverallStatus = if ($failedTests -eq 0 -and $warningTests -eq 0) { "✅ Ready" }
                           elseif ($failedTests -eq 0) { "⚠️ Ready with Warnings" }
                           else { "❌ Not Ready" }
    
    return [PSCustomObject]$results
}

# Run prerequisites test
$testResults = Test-DailyAdminToolkitPrerequisites -TestServers @('SERVER01', 'SERVER02') -IncludeAD

# Display results
Write-Host "`n🔍 Daily Admin Toolkit Prerequisites Test" -ForegroundColor Cyan
Write-Host "Overall Status: $($testResults.OverallStatus)" -ForegroundColor Yellow
Write-Host "`nTest Results:" -ForegroundColor Yellow
$testResults.Tests | ForEach-Object {
    Write-Host "  $($_.Test): $($_.Status)" -ForegroundColor White
    if ($_.Details) { Write-Host "    $($_.Details)" -ForegroundColor Gray }
}
```

## Installation Verification

After completing prerequisites setup, verify the installation:

```powershell
# Verify all components
Write-Host "🔍 Verifying Daily Admin Toolkit Prerequisites..." -ForegroundColor Cyan

# 1. PowerShell version
Write-Host "`n1. PowerShell Version Check" -ForegroundColor Yellow
$PSVersionTable | Format-Table PSVersion, PSEdition, Platform -AutoSize

# 2. Required modules
Write-Host "`n2. Required Modules Check" -ForegroundColor Yellow
@('ActiveDirectory') | ForEach-Object {
    $module = Get-Module -ListAvailable $_
    if ($module) {
        Write-Host "✅ $_ - Version $($module.Version)" -ForegroundColor Green
    } else {
        Write-Host "❌ $_ - Not found" -ForegroundColor Red
    }
}

# 3. Execution policy
Write-Host "`n3. Execution Policy Check" -ForegroundColor Yellow
Get-ExecutionPolicy -List | Format-Table -AutoSize

# 4. Network connectivity test
Write-Host "`n4. Network Connectivity Test" -ForegroundColor Yellow
$testServer = Read-Host "Enter a test server name (or press Enter to skip)"
if ($testServer) {
    Test-NetConnection -ComputerName $testServer -Port 5985 | 
        Select-Object ComputerName, RemotePort, TcpTestSucceeded
}

Write-Host "`n✅ Prerequisites verification complete!" -ForegroundColor Green
```

---

> **Next Steps**: After meeting all prerequisites, proceed to [Configuration Guide](configuration.md) to set up the Daily Admin Toolkit for your environment.