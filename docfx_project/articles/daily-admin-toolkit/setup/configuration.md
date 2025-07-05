# Configuration Guide

## Overview

This guide walks you through configuring the Daily Admin Toolkit for your specific environment, including module setup, security configuration, and performance optimization.

## Module Installation and Configuration

### Module Structure

The Daily Admin Toolkit consists of three main modules:

```
ProjectName.ActiveDirectory/
├── ProjectName.ActiveDirectory.psd1    # Module manifest
├── ProjectName.ActiveDirectory.psm1    # Module script
├── Functions/
│   ├── Unlock-ADAccount.ps1
│   ├── Reset-ADUserPassword.ps1
│   ├── Get-ADUserLastLogon.ps1
│   └── Get-ADUserMembership.ps1
└── Tests/
    └── ActiveDirectory.Tests.ps1

ProjectName.ServerManagement/
├── ProjectName.ServerManagement.psd1
├── ProjectName.ServerManagement.psm1
├── Functions/
│   ├── Get-ServerHealth.ps1
│   ├── Test-ServerConnectivity.ps1
│   └── Get-ServiceStatus.ps1
└── Tests/
    └── ServerManagement.Tests.ps1

ProjectName.ServiceManagement/
├── ProjectName.ServiceManagement.psd1
├── ProjectName.ServiceManagement.psm1
├── Functions/
│   ├── Restart-RemoteService.ps1
│   ├── Get-ProcessByName.ps1
│   └── Stop-ProcessRemotely.ps1
└── Tests/
    └── ServiceManagement.Tests.ps1
```

### Installation Methods

#### Method 1: Local Installation

```powershell
# Create module directories
$moduleBase = "$env:USERPROFILE\Documents\PowerShell\Modules"
# For Windows PowerShell 5.1, use: "$env:USERPROFILE\Documents\WindowsPowerShell\Modules"

New-Item -Path "$moduleBase\ProjectName.ActiveDirectory" -ItemType Directory -Force
New-Item -Path "$moduleBase\ProjectName.ServerManagement" -ItemType Directory -Force
New-Item -Path "$moduleBase\ProjectName.ServiceManagement" -ItemType Directory -Force

# Copy module files to directories (after development)
# Copy-Item -Path "C:\Development\Modules\*" -Destination $moduleBase -Recurse -Force
```

#### Method 2: Network Share Installation

```powershell
# Set up shared module location
$networkModulePath = "\\FileServer\IT\PowerShellModules"

# Add to PSModulePath for all users
$currentPath = [Environment]::GetEnvironmentVariable("PSModulePath", "Machine")
if ($currentPath -notlike "*$networkModulePath*") {
    $newPath = "$currentPath;$networkModulePath"
    [Environment]::SetEnvironmentVariable("PSModulePath", $newPath, "Machine")
}

# Verify module path
$env:PSModulePath -split ';'
```

#### Method 3: Repository Installation (Future)

```powershell
# When published to PowerShell Gallery or internal repository
Install-Module ProjectName.ActiveDirectory -Scope CurrentUser
Install-Module ProjectName.ServerManagement -Scope CurrentUser
Install-Module ProjectName.ServiceManagement -Scope CurrentUser
```

### Module Import and Verification

```powershell
# Import all Daily Admin Toolkit modules
Import-Module ProjectName.ActiveDirectory -Force
Import-Module ProjectName.ServerManagement -Force
Import-Module ProjectName.ServiceManagement -Force

# Verify modules are loaded
Get-Module ProjectName.*

# Check available functions
Get-Command -Module ProjectName.* | Sort-Object ModuleName, Name

# Test basic functionality
Get-Command Unlock-ADAccount
Get-Command Get-ServerHealth
Get-Command Restart-RemoteService
```

## Environment-Specific Configuration

### Configuration File Structure

Create a configuration file for environment-specific settings:

```powershell
# Create configuration directory
$configPath = "$env:USERPROFILE\.dailyadmintoolkit"
New-Item -Path $configPath -ItemType Directory -Force

# Configuration file template
$configTemplate = @{
    Environment = @{
        Type = "Production"  # Development, Testing, Production
        Domain = "contoso.com"
        DefaultTimeout = 120
        MaxConcurrentSessions = 25
    }
    
    ActiveDirectory = @{
        DefaultServer = "DC01.contoso.com"
        SearchBase = "OU=Users,DC=contoso,DC=com"
        PreferredDomainController = $null
        LogUnlockOperations = $true
        LogPasswordResets = $true
    }
    
    ServerManagement = @{
        DefaultHealthCheckTimeout = 60
        PerformanceCounterTimeout = 30
        IncludeDetailsThreshold = 10  # Max servers for automatic detailed checks
        ParallelOperationThreshold = 5  # Min servers to trigger parallel processing
    }
    
    ServiceManagement = @{
        DefaultServiceTimeout = 300
        GracefulShutdownTimeout = 30
        RestartRetryCount = 3
        RestartRetryDelay = 10
        SafetyChecksEnabled = $true
    }
    
    Security = @{
        RequireConfirmationForCriticalOps = $true
        LogAllOperations = $true
        EncryptLogs = $false
        MaxLogRetentionDays = 90
    }
    
    Logging = @{
        LogPath = "$env:USERPROFILE\.dailyadmintoolkit\logs"
        LogLevel = "Information"  # Verbose, Information, Warning, Error
        MaxLogSizeMB = 10
        EnableEventLogLogging = $false
    }
    
    Performance = @{
        EnableParallelProcessing = $true
        MaxParallelThreads = 10
        ConnectionPooling = $true
        CacheResults = $true
        CacheExpirationMinutes = 15
    }
}

# Save configuration
$configFile = Join-Path $configPath "config.json"
$configTemplate | ConvertTo-Json -Depth 3 | Out-File -FilePath $configFile -Encoding UTF8

Write-Host "✅ Configuration template created at: $configFile" -ForegroundColor Green
```

### Environment-Specific Settings

#### Development Environment

```powershell
$devConfig = @{
    Environment = @{
        Type = "Development"
        Domain = "dev.contoso.com"
        DefaultTimeout = 30
        MaxConcurrentSessions = 5
    }
    
    Security = @{
        RequireConfirmationForCriticalOps = $false
        LogAllOperations = $true
        EncryptLogs = $false
    }
    
    Logging = @{
        LogLevel = "Verbose"
        EnableEventLogLogging = $false
    }
}

# Apply development settings
$devConfigFile = Join-Path $configPath "config.dev.json"
$devConfig | ConvertTo-Json -Depth 3 | Out-File -FilePath $devConfigFile -Encoding UTF8
```

#### Production Environment

```powershell
$prodConfig = @{
    Environment = @{
        Type = "Production"
        Domain = "contoso.com"
        DefaultTimeout = 180
        MaxConcurrentSessions = 50
    }
    
    Security = @{
        RequireConfirmationForCriticalOps = $true
        LogAllOperations = $true
        EncryptLogs = $true
        MaxLogRetentionDays = 365
    }
    
    Logging = @{
        LogLevel = "Information"
        EnableEventLogLogging = $true
        MaxLogSizeMB = 50
    }
    
    Performance = @{
        EnableParallelProcessing = $true
        MaxParallelThreads = 20
        ConnectionPooling = $true
    }
}

# Apply production settings
$prodConfigFile = Join-Path $configPath "config.prod.json"
$prodConfig | ConvertTo-Json -Depth 3 | Out-File -FilePath $prodConfigFile -Encoding UTF8
```

### Configuration Loading Function

```powershell
function Get-DailyAdminToolkitConfig {
    param(
        [string]$Environment = "Default",
        [string]$ConfigPath = "$env:USERPROFILE\.dailyadmintoolkit"
    )
    
    # Default configuration
    $defaultConfig = @{
        Environment = @{
            Type = "Default"
            DefaultTimeout = 120
        }
        ActiveDirectory = @{
            LogUnlockOperations = $true
        }
        Security = @{
            RequireConfirmationForCriticalOps = $true
        }
        Logging = @{
            LogLevel = "Information"
        }
    }
    
    # Load base configuration
    $configFile = Join-Path $ConfigPath "config.json"
    if (Test-Path $configFile) {
        try {
            $baseConfig = Get-Content $configFile | ConvertFrom-Json -AsHashtable
            $defaultConfig = Merge-Hashtables $defaultConfig $baseConfig
        } catch {
            Write-Warning "Failed to load base configuration: $($_.Exception.Message)"
        }
    }
    
    # Load environment-specific configuration
    if ($Environment -ne "Default") {
        $envConfigFile = Join-Path $ConfigPath "config.$Environment.json"
        if (Test-Path $envConfigFile) {
            try {
                $envConfig = Get-Content $envConfigFile | ConvertFrom-Json -AsHashtable
                $defaultConfig = Merge-Hashtables $defaultConfig $envConfig
            } catch {
                Write-Warning "Failed to load environment configuration: $($_.Exception.Message)"
            }
        }
    }
    
    return $defaultConfig
}

function Merge-Hashtables {
    param($base, $override)
    
    $result = $base.Clone()
    
    foreach ($key in $override.Keys) {
        if ($result.ContainsKey($key) -and 
            $result[$key] -is [hashtable] -and 
            $override[$key] -is [hashtable]) {
            $result[$key] = Merge-Hashtables $result[$key] $override[$key]
        } else {
            $result[$key] = $override[$key]
        }
    }
    
    return $result
}

# Usage examples
$config = Get-DailyAdminToolkitConfig -Environment "Development"
$prodConfig = Get-DailyAdminToolkitConfig -Environment "Production"
```

## Security Configuration

### Credential Management Setup

```powershell
# Configure Windows Credential Manager integration
function Set-DailyAdminToolkitCredentials {
    param(
        [Parameter(Mandatory)]
        [string]$TargetName,
        
        [Parameter(Mandatory)]
        [PSCredential]$Credential,
        
        [string]$Description = "Daily Admin Toolkit Credential"
    )
    
    try {
        # Store credential in Windows Credential Manager
        cmdkey /generic:$TargetName /user:$($Credential.UserName) /pass:$($Credential.GetNetworkCredential().Password)
        Write-Host "✅ Credential stored successfully for $TargetName" -ForegroundColor Green
    } catch {
        Write-Error "Failed to store credential: $($_.Exception.Message)"
    }
}

function Get-DailyAdminToolkitCredentials {
    param(
        [Parameter(Mandatory)]
        [string]$TargetName
    )
    
    try {
        # Retrieve credential from Windows Credential Manager
        $credResult = cmdkey /list:$TargetName
        if ($credResult -match "User: (.+)") {
            $username = $Matches[1]
            $password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((Read-Host "Password for $username" -AsSecureString)))
            return New-Object PSCredential($username, (ConvertTo-SecureString $password -AsPlainText -Force))
        }
    } catch {
        Write-Warning "Failed to retrieve credential for $TargetName"
        return $null
    }
}

# Setup service account credentials
$serviceAccountCred = Get-Credential -Message "Enter service account credentials for Daily Admin Toolkit"
Set-DailyAdminToolkitCredentials -TargetName "DailyAdminToolkit_ServiceAccount" -Credential $serviceAccountCred
```

### Logging and Auditing Configuration

```powershell
# Configure logging system
function Initialize-DailyAdminToolkitLogging {
    param(
        [string]$LogPath = "$env:USERPROFILE\.dailyadmintoolkit\logs",
        [ValidateSet("Verbose", "Information", "Warning", "Error")]
        [string]$LogLevel = "Information",
        [switch]$EnableEventLog
    )
    
    # Create log directory
    if (-not (Test-Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force
    }
    
    # Configure log rotation
    $logConfig = @{
        LogPath = $LogPath
        LogLevel = $LogLevel
        MaxLogSizeMB = 10
        MaxLogFiles = 10
        EnableEventLog = $EnableEventLog.IsPresent
    }
    
    # Save logging configuration
    $logConfigFile = Join-Path (Split-Path $LogPath) "logging.json"
    $logConfig | ConvertTo-Json | Out-File -FilePath $logConfigFile -Encoding UTF8
    
    # Create event log source if enabled
    if ($EnableEventLog) {
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists("DailyAdminToolkit")) {
                [System.Diagnostics.EventLog]::CreateEventSource("DailyAdminToolkit", "Application")
                Write-Host "✅ Event log source created" -ForegroundColor Green
            }
        } catch {
            Write-Warning "Failed to create event log source: $($_.Exception.Message)"
        }
    }
    
    Write-Host "✅ Logging configured at: $LogPath" -ForegroundColor Green
    return $logConfig
}

# Initialize logging
$loggingConfig = Initialize-DailyAdminToolkitLogging -LogLevel "Information" -EnableEventLog
```

### Permission Validation

```powershell
# Validate required permissions
function Test-DailyAdminToolkitPermissions {
    param(
        [string[]]$TestServers = @(),
        [switch]$IncludeAD,
        [PSCredential]$Credential
    )
    
    $permissionTests = @()
    
    # Test local permissions
    $permissionTests += @{
        Test = "Local Admin Rights"
        Status = if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            "✅ Confirmed"
        } else {
            "⚠️ Not Administrator"
        }
    }
    
    # Test Active Directory permissions
    if ($IncludeAD) {
        try {
            $testUser = Get-ADUser -Identity $env:USERNAME -ErrorAction Stop
            $permissionTests += @{
                Test = "AD Read Access"
                Status = "✅ Confirmed"
            }
            
            # Test unlock permissions (safe test)
            try {
                Unlock-ADAccount -Identity "NonExistentTestUser12345" -WhatIf -ErrorAction Stop
                $permissionTests += @{
                    Test = "AD Unlock Permission"
                    Status = "✅ Confirmed"
                }
            } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                $permissionTests += @{
                    Test = "AD Unlock Permission"
                    Status = "✅ Confirmed"
                }
            } catch {
                $permissionTests += @{
                    Test = "AD Unlock Permission"
                    Status = "❌ Denied"
                }
            }
        } catch {
            $permissionTests += @{
                Test = "AD Access"
                Status = "❌ Failed"
            }
        }
    }
    
    # Test remote server permissions
    foreach ($server in $TestServers) {
        try {
            $session = New-PSSession -ComputerName $server -Credential $Credential -ErrorAction Stop
            $permissionTests += @{
                Test = "Remote Access to $server"
                Status = "✅ Confirmed"
            }
            Remove-PSSession $session
        } catch {
            $permissionTests += @{
                Test = "Remote Access to $server"
                Status = "❌ Failed"
            }
        }
    }
    
    return $permissionTests
}

# Run permission tests
$permissionResults = Test-DailyAdminToolkitPermissions -TestServers @('SERVER01') -IncludeAD
$permissionResults | ForEach-Object {
    Write-Host "$($_.Test): $($_.Status)"
}
```## Performance Optimization

### Parallel Processing Configuration

```powershell
# Configure parallel processing settings
function Set-DailyAdminToolkitPerformance {
    param(
        [int]$MaxParallelThreads = 10,
        [int]$ParallelThreshold = 5,
        [int]$DefaultTimeout = 120,
        [switch]$EnableCaching
    )
    
    $performanceConfig = @{
        MaxParallelThreads = $MaxParallelThreads
        ParallelThreshold = $ParallelThreshold
        DefaultTimeout = $DefaultTimeout
        EnableCaching = $EnableCaching.IsPresent
        CacheExpirationMinutes = 15
        ConnectionPooling = $true
    }
    
    # Test optimal thread count based on system
    $optimalThreads = [Math]::Min($MaxParallelThreads, $env:NUMBER_OF_PROCESSORS * 2)
    if ($MaxParallelThreads -gt $optimalThreads) {
        Write-Warning "Consider reducing MaxParallelThreads to $optimalThreads for optimal performance"
    }
    
    # Save performance configuration
    $configPath = "$env:USERPROFILE\.dailyadmintoolkit"
    $perfConfigFile = Join-Path $configPath "performance.json"
    $performanceConfig | ConvertTo-Json | Out-File -FilePath $perfConfigFile -Encoding UTF8
    
    Write-Host "✅ Performance configuration saved" -ForegroundColor Green
    return $performanceConfig
}

# Apply performance settings
$perfConfig = Set-DailyAdminToolkitPerformance -MaxParallelThreads 8 -ParallelThreshold 3 -EnableCaching
```

### Connection Pooling Setup

```powershell
# Configure connection pooling for remote operations
function Initialize-ConnectionPooling {
    param(
        [int]$MaxPoolSize = 25,
        [int]$MinPoolSize = 5,
        [int]$ConnectionTimeoutSeconds = 30
    )
    
    # Configure PowerShell session options for pooling
    $sessionOptions = New-PSSessionOption -MaxConnectionRetryCount 3 -IdleTimeout 300000
    
    $poolConfig = @{
        MaxPoolSize = $MaxPoolSize
        MinPoolSize = $MinPoolSize
        ConnectionTimeout = $ConnectionTimeoutSeconds
        SessionOptions = $sessionOptions
        EnablePooling = $true
    }
    
    # Set global variables for connection pooling
    $global:DailyAdminToolkit_ConnectionPool = @{}
    $global:DailyAdminToolkit_PoolConfig = $poolConfig
    
    Write-Host "✅ Connection pooling initialized" -ForegroundColor Green
    return $poolConfig
}

# Initialize connection pooling
$poolConfig = Initialize-ConnectionPooling -MaxPoolSize 20 -MinPoolSize 3
```

## Module Customization

### Custom Function Templates

```powershell
# Template for creating custom Daily Admin Toolkit functions
function New-CustomDailyAdminFunction {
    param(
        [Parameter(Mandatory)]
        [string]$FunctionName,
        
        [Parameter(Mandatory)]
        [string]$ModuleName,
        
        [string]$Description,
        
        [string]$OutputPath = "$env:USERPROFILE\.dailyadmintoolkit\custom"
    )
    
    # Ensure output directory exists
    if (-not (Test-Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force
    }
    
    # Function template
    $functionTemplate = @"
function $FunctionName {
    <#
    .SYNOPSIS
    $Description
    
    .DESCRIPTION
    Custom Daily Admin Toolkit function for $Description
    
    .PARAMETER ComputerName
    Target computer(s) for the operation
    
    .PARAMETER Credential
    Alternate credentials for remote operations
    
    .PARAMETER TimeoutSeconds
    Timeout for the operation in seconds
    
    .PARAMETER WhatIf
    Shows what would happen without making changes
    
    .PARAMETER Confirm
    Prompts for confirmation before execution
    
    .EXAMPLE
    $FunctionName -ComputerName 'SERVER01'
    
    .NOTES
    Created: $(Get-Date)
    Module: $ModuleName
    #>
    
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]`$ComputerName,
        
        [PSCredential]`$Credential,
        
        [int]`$TimeoutSeconds = 120,
        
        [switch]`$Detailed
    )
    
    begin {
        # Load configuration
        `$config = Get-DailyAdminToolkitConfig
        
        # Initialize logging
        Write-DailyAdminToolkitLog -Message "Starting $FunctionName" -Level Information
        
        # Initialize results array
        `$results = @()
    }
    
    process {
        foreach (`$computer in `$ComputerName) {
            if (`$PSCmdlet.ShouldProcess(`$computer, "$FunctionName")) {
                try {
                    Write-Verbose "Processing `$computer"
                    
                    # Your custom logic here
                    `$result = [PSCustomObject]@{
                        ComputerName = `$computer
                        Status = "Success"
                        Timestamp = Get-Date
                        # Add your custom properties
                    }
                    
                    `$results += `$result
                    
                } catch {
                    Write-Error "Failed to process `$computer`: `$(`$_.Exception.Message)"
                    
                    `$results += [PSCustomObject]@{
                        ComputerName = `$computer
                        Status = "Error"
                        Error = `$_.Exception.Message
                        Timestamp = Get-Date
                    }
                }
            }
        }
    }
    
    end {
        Write-DailyAdminToolkitLog -Message "$FunctionName completed. Processed `$(`$results.Count) computers" -Level Information
        return `$results
    }
}
"@

    # Save function to file
    $functionFile = Join-Path $OutputPath "$FunctionName.ps1"
    $functionTemplate | Out-File -FilePath $functionFile -Encoding UTF8
    
    Write-Host "✅ Custom function template created: $functionFile" -ForegroundColor Green
    Write-Host "   Edit the function and then dot-source it: . '$functionFile'" -ForegroundColor Cyan
    
    return $functionFile
}

# Create a custom function
$customFunction = New-CustomDailyAdminFunction -FunctionName "Get-CustomServerInfo" -ModuleName "ProjectName.Custom" -Description "Get custom server information"
```

### Configuration Profiles

```powershell
# Create configuration profiles for different scenarios
function New-DailyAdminToolkitProfile {
    param(
        [Parameter(Mandatory)]
        [string]$ProfileName,
        
        [hashtable]$Settings,
        
        [string]$Description
    )
    
    $profilePath = "$env:USERPROFILE\.dailyadmintoolkit\profiles"
    if (-not (Test-Path $profilePath)) {
        New-Item -Path $profilePath -ItemType Directory -Force
    }
    
    $profile = @{
        Name = $ProfileName
        Description = $Description
        CreatedDate = Get-Date
        Settings = $Settings
    }
    
    $profileFile = Join-Path $profilePath "$ProfileName.json"
    $profile | ConvertTo-Json -Depth 3 | Out-File -FilePath $profileFile -Encoding UTF8
    
    Write-Host "✅ Profile '$ProfileName' created at: $profileFile" -ForegroundColor Green
    return $profileFile
}

# Create profile for different scenarios
$quickCheckProfile = New-DailyAdminToolkitProfile -ProfileName "QuickCheck" -Description "Fast health checks with minimal detail" -Settings @{
    ServerManagement = @{
        DefaultHealthCheckTimeout = 30
        IncludeDetailsThreshold = 0
        ParallelOperationThreshold = 2
    }
    Performance = @{
        MaxParallelThreads = 15
        EnableCaching = $true
    }
}

$deepAnalysisProfile = New-DailyAdminToolkitProfile -ProfileName "DeepAnalysis" -Description "Comprehensive analysis with full details" -Settings @{
    ServerManagement = @{
        DefaultHealthCheckTimeout = 180
        IncludeDetailsThreshold = 100
        ParallelOperationThreshold = 10
    }
    Performance = @{
        MaxParallelThreads = 5
        EnableCaching = $false
    }
    Logging = @{
        LogLevel = "Verbose"
    }
}
```

## Integration Configuration

### SCOM Integration

```powershell
# Configure System Center Operations Manager integration
function Set-SCOMIntegration {
    param(
        [string]$SCOMServer = "scom.contoso.com",
        [switch]$EnableAlerts,
        [string]$ManagementGroup = "Default"
    )
    
    $scomConfig = @{
        Enabled = $true
        SCOMServer = $SCOMServer
        ManagementGroup = $ManagementGroup
        EnableAlerts = $EnableAlerts.IsPresent
        AlertCategories = @("ServiceDown", "ServerUnreachable", "HighResourceUsage")
    }
    
    # Test SCOM connectivity
    try {
        Test-NetConnection -ComputerName $SCOMServer -Port 5723 -InformationLevel Quiet
        Write-Host "✅ SCOM connectivity verified" -ForegroundColor Green
    } catch {
        Write-Warning "Cannot connect to SCOM server: $SCOMServer"
    }
    
    # Save SCOM configuration
    $configPath = "$env:USERPROFILE\.dailyadmintoolkit"
    $scomConfigFile = Join-Path $configPath "scom.json"
    $scomConfig | ConvertTo-Json | Out-File -FilePath $scomConfigFile -Encoding UTF8
    
    return $scomConfig
}

# Configure SCOM integration
$scomConfig = Set-SCOMIntegration -SCOMServer "scom.contoso.com" -EnableAlerts
```

### ServiceNow Integration

```powershell
# Configure ServiceNow integration for ticket management
function Set-ServiceNowIntegration {
    param(
        [string]$ServiceNowInstance = "contoso.service-now.com",
        [PSCredential]$Credential,
        [switch]$EnableTicketCreation
    )
    
    $serviceNowConfig = @{
        Enabled = $true
        Instance = $ServiceNowInstance
        BaseURL = "https://$ServiceNowInstance/api"
        EnableTicketCreation = $EnableTicketCreation.IsPresent
        DefaultAssignmentGroup = "IT Operations"
        TicketCategories = @{
            ServiceRestart = "Service Management"
            ServerIssue = "Infrastructure"
            UserAccount = "Identity Management"
        }
    }
    
    # Test ServiceNow connectivity
    try {
        $testUrl = "https://$ServiceNowInstance"
        Invoke-WebRequest -Uri $testUrl -Method Head -TimeoutSec 10 | Out-Null
        Write-Host "✅ ServiceNow connectivity verified" -ForegroundColor Green
    } catch {
        Write-Warning "Cannot connect to ServiceNow instance: $ServiceNowInstance"
    }
    
    # Store credentials securely
    if ($Credential) {
        Set-DailyAdminToolkitCredentials -TargetName "ServiceNow_$ServiceNowInstance" -Credential $Credential
    }
    
    # Save ServiceNow configuration
    $configPath = "$env:USERPROFILE\.dailyadmintoolkit"
    $snowConfigFile = Join-Path $configPath "servicenow.json"
    $serviceNowConfig | ConvertTo-Json | Out-File -FilePath $snowConfigFile -Encoding UTF8
    
    return $serviceNowConfig
}

# Configure ServiceNow integration
$snowCred = Get-Credential -Message "Enter ServiceNow API credentials"
$snowConfig = Set-ServiceNowIntegration -ServiceNowInstance "contoso.service-now.com" -Credential $snowCred -EnableTicketCreation
```

## Validation and Testing

### Configuration Validation

```powershell
function Test-DailyAdminToolkitConfiguration {
    param(
        [string]$ConfigPath = "$env:USERPROFILE\.dailyadmintoolkit"
    )
    
    $validationResults = @{
        OverallStatus = "Unknown"
        Tests = @()
        ConfigPath = $ConfigPath
        TestDate = Get-Date
    }
    
    # Test 1: Configuration directory exists
    $validationResults.Tests += @{
        Test = "Configuration Directory"
        Status = if (Test-Path $ConfigPath) { "✅ Exists" } else { "❌ Missing" }
        Path = $ConfigPath
    }
    
    # Test 2: Main configuration file
    $mainConfigFile = Join-Path $ConfigPath "config.json"
    $validationResults.Tests += @{
        Test = "Main Configuration File"
        Status = if (Test-Path $mainConfigFile) { "✅ Exists" } else { "❌ Missing" }
        Path = $mainConfigFile
    }
    
    # Test 3: Logging configuration
    $logPath = Join-Path $ConfigPath "logs"
    $validationResults.Tests += @{
        Test = "Logging Directory"
        Status = if (Test-Path $logPath) { "✅ Exists" } else { "⚠️ Missing" }
        Path = $logPath
    }
    
    # Test 4: Module availability
    $requiredModules = @('ProjectName.ActiveDirectory', 'ProjectName.ServerManagement', 'ProjectName.ServiceManagement')
    foreach ($module in $requiredModules) {
        $moduleAvailable = Get-Module -ListAvailable $module
        $validationResults.Tests += @{
            Test = "$module Module"
            Status = if ($moduleAvailable) { "✅ Available" } else { "❌ Not Found" }
            Version = if ($moduleAvailable) { $moduleAvailable.Version.ToString() } else { "N/A" }
        }
    }
    
    # Test 5: Configuration file integrity
    if (Test-Path $mainConfigFile) {
        try {
            $config = Get-Content $mainConfigFile | ConvertFrom-Json
            $validationResults.Tests += @{
                Test = "Configuration File Integrity"
                Status = "✅ Valid JSON"
                Details = "Configuration loaded successfully"
            }
        } catch {
            $validationResults.Tests += @{
                Test = "Configuration File Integrity"
                Status = "❌ Invalid"
                Details = $_.Exception.Message
            }
        }
    }
    
    # Test 6: Credential store
    try {
        cmdkey /list | Out-Null
        $validationResults.Tests += @{
            Test = "Credential Store Access"
            Status = "✅ Accessible"
            Details = "Windows Credential Manager available"
        }
    } catch {
        $validationResults.Tests += @{
            Test = "Credential Store Access"
            Status = "⚠️ Limited"
            Details = "May need manual credential entry"
        }
    }
    
    # Overall assessment
    $failedTests = ($validationResults.Tests | Where-Object { $_.Status -like "*❌*" }).Count
    $warningTests = ($validationResults.Tests | Where-Object { $_.Status -like "*⚠️*" }).Count
    
    $validationResults.OverallStatus = if ($failedTests -eq 0 -and $warningTests -eq 0) { "✅ Fully Configured" }
                                     elseif ($failedTests -eq 0) { "⚠️ Configured with Warnings" }
                                     else { "❌ Configuration Issues" }
    
    return [PSCustomObject]$validationResults
}

# Run configuration validation
$configValidation = Test-DailyAdminToolkitConfiguration

Write-Host "`n🔍 Daily Admin Toolkit Configuration Validation" -ForegroundColor Cyan
Write-Host "Overall Status: $($configValidation.OverallStatus)" -ForegroundColor Yellow
Write-Host "`nValidation Results:" -ForegroundColor Yellow
$configValidation.Tests | ForEach-Object {
    Write-Host "  $($_.Test): $($_.Status)" -ForegroundColor White
    if ($_.Path) { Write-Host "    Path: $($_.Path)" -ForegroundColor Gray }
    if ($_.Version) { Write-Host "    Version: $($_.Version)" -ForegroundColor Gray }
    if ($_.Details) { Write-Host "    Details: $($_.Details)" -ForegroundColor Gray }
}
```

### End-to-End Testing

```powershell
# Comprehensive end-to-end test
function Test-DailyAdminToolkitEndToEnd {
    param(
        [string[]]$TestServers = @('localhost'),
        [switch]$IncludeAD,
        [string]$TestUser = $env:USERNAME
    )
    
    Write-Host "🚀 Starting Daily Admin Toolkit End-to-End Test" -ForegroundColor Cyan
    
    $testResults = @{
        StartTime = Get-Date
        Tests = @()
        OverallSuccess = $true
    }
    
    # Test 1: Module Import
    try {
        Import-Module ProjectName.ActiveDirectory -Force -ErrorAction Stop
        Import-Module ProjectName.ServerManagement -Force -ErrorAction Stop
        Import-Module ProjectName.ServiceManagement -Force -ErrorAction Stop
        
        $testResults.Tests += @{
            Test = "Module Import"
            Status = "✅ Success"
            Details = "All modules imported successfully"
        }
    } catch {
        $testResults.Tests += @{
            Test = "Module Import"
            Status = "❌ Failed"
            Details = $_.Exception.Message
        }
        $testResults.OverallSuccess = $false
    }
    
    # Test 2: Server Health Check
    try {
        $healthResults = Get-ServerHealth -ComputerName $TestServers[0] -ErrorAction Stop
        $testResults.Tests += @{
            Test = "Server Health Check"
            Status = "✅ Success"
            Details = "Health check completed for $($TestServers[0])"
        }
    } catch {
        $testResults.Tests += @{
            Test = "Server Health Check"
            Status = "❌ Failed"
            Details = $_.Exception.Message
        }
        $testResults.OverallSuccess = $false
    }
    
    # Test 3: Service Status Check
    try {
        $serviceResults = Get-ServiceStatus -ComputerName $TestServers[0] -ServiceName 'Spooler' -ErrorAction Stop
        $testResults.Tests += @{
            Test = "Service Status Check"
            Status = "✅ Success"
            Details = "Service status retrieved successfully"
        }
    } catch {
        $testResults.Tests += @{
            Test = "Service Status Check"
            Status = "❌ Failed"
            Details = $_.Exception.Message
        }
        $testResults.OverallSuccess = $false
    }
    
    # Test 4: Active Directory (if enabled)
    if ($IncludeAD) {
        try {
            $userInfo = Get-ADUserLastLogon -Identity $TestUser -ErrorAction Stop
            $testResults.Tests += @{
                Test = "Active Directory Access"
                Status = "✅ Success"
                Details = "AD query completed for $TestUser"
            }
        } catch {
            $testResults.Tests += @{
                Test = "Active Directory Access"
                Status = "❌ Failed"
                Details = $_.Exception.Message
            }
            $testResults.OverallSuccess = $false
        }
    }
    
    # Test 5: Configuration Loading
    try {
        $config = Get-DailyAdminToolkitConfig -ErrorAction Stop
        $testResults.Tests += @{
            Test = "Configuration Loading"
            Status = "✅ Success"
            Details = "Configuration loaded successfully"
        }
    } catch {
        $testResults.Tests += @{
            Test = "Configuration Loading"
            Status = "❌ Failed"
            Details = $_.Exception.Message
        }
        $testResults.OverallSuccess = $false
    }
    
    $testResults.EndTime = Get-Date
    $testResults.Duration = New-TimeSpan -Start $testResults.StartTime -End $testResults.EndTime
    
    # Display results
    Write-Host "`n📊 End-to-End Test Results" -ForegroundColor Yellow
    Write-Host "Overall Success: $($testResults.OverallSuccess ? '✅ PASS' : '❌ FAIL')" -ForegroundColor $(if ($testResults.OverallSuccess) { 'Green' } else { 'Red' })
    Write-Host "Duration: $($testResults.Duration.ToString('mm\:ss'))" -ForegroundColor Gray
    
    Write-Host "`nTest Details:" -ForegroundColor Yellow
    $testResults.Tests | ForEach-Object {
        Write-Host "  $($_.Test): $($_.Status)" -ForegroundColor White
        if ($_.Details) { Write-Host "    $($_.Details)" -ForegroundColor Gray }
    }
    
    return [PSCustomObject]$testResults
}

# Run end-to-end test
$e2eResults = Test-DailyAdminToolkitEndToEnd -TestServers @('localhost') -IncludeAD
```

## Final Configuration Checklist

### Pre-Deployment Checklist

```powershell
# Final deployment readiness check
Write-Host "📋 Daily Admin Toolkit Deployment Checklist" -ForegroundColor Cyan

$checklist = @(
    @{ Item = "PowerShell 5.1+ or 7.x installed"; Command = '$PSVersionTable.PSVersion' }
    @{ Item = "RSAT tools installed"; Command = 'Get-Module -ListAvailable ActiveDirectory' }
    @{ Item = "Execution policy configured"; Command = 'Get-ExecutionPolicy' }
    @{ Item = "PowerShell remoting enabled"; Command = 'Test-WSMan' }
    @{ Item = "Required modules imported"; Command = 'Get-Module ProjectName.*' }
    @{ Item = "Configuration files created"; Command = 'Test-Path "$env:USERPROFILE\.dailyadmintoolkit\config.json"' }
    @{ Item = "Logging configured"; Command = 'Test-Path "$env:USERPROFILE\.dailyadmintoolkit\logs"' }
    @{ Item = "Permissions validated"; Command = 'whoami /groups' }
    @{ Item = "Network connectivity tested"; Command = 'Test-NetConnection -ComputerName SERVER01 -Port 5985' }
    @{ Item = "End-to-end test passed"; Command = 'Test-DailyAdminToolkitEndToEnd' }
)

foreach ($item in $checklist) {
    Write-Host "☐ $($item.Item)" -ForegroundColor Yellow
    Write-Host "   Command: $($item.Command)" -ForegroundColor Gray
}

Write-Host "`n✅ Configuration complete! The Daily Admin Toolkit is ready for use." -ForegroundColor Green
Write-Host "📖 Next steps: Review the recipes documentation and start with basic health checks." -ForegroundColor Cyan
```

---

> **Congratulations!** You've successfully configured the Daily Admin Toolkit. Next, explore the [Security Guide](security.md) for security best practices, or jump directly to the [Recipe Documentation](../recipes/activedirectory-recipes.md) to start using the toolkit.