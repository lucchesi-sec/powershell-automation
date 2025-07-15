<#
.SYNOPSIS
    PSCore - Core module for PowerShell Enterprise Automation Platform
.DESCRIPTION
    Provides foundational functionality including logging, configuration management,
    credential handling, performance monitoring, and utility functions.
.NOTES
    Version: 2.0.0
    Author: Enterprise Automation Team
#>

#region Module Variables
$script:PSCoreConfig = @{
    LogPath = Join-Path $env:ProgramData 'PSAutomation\Logs'
    ConfigPath = Join-Path $env:ProgramData 'PSAutomation\Config'
    CredentialPath = Join-Path $env:ProgramData 'PSAutomation\Credentials'
    MaxLogSizeMB = 100
    MaxLogFiles = 10
    DefaultLogLevel = 'Info'
    PerformanceTracking = $true
    RetryAttempts = 3
    RetryDelaySeconds = 5
}

$script:PSLogLevel = @{
    Debug = 0
    Verbose = 1
    Info = 2
    Warning = 3
    Error = 4
    Critical = 5
}

$script:PSPerformanceMetrics = @{}
$script:LogBuffer = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
$script:LogBufferSize = 100
#endregion

#region Logging Functions
function Write-PSLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Debug', 'Verbose', 'Info', 'Warning', 'Error', 'Critical')]
        [string]$Level = 'Info',
        
        [Parameter(Mandatory = $false)]
        [string]$Component = 'General',
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Context = @{},
        
        [Parameter(Mandatory = $false)]
        [switch]$PassThru,
        
        [Parameter(Mandatory = $false)]
        [switch]$NoConsole
    )
    
    begin {
        $timestamp = Get-Date
        $logEntry = [PSCustomObject]@{
            Timestamp = $timestamp
            Level = $Level
            Component = $Component
            Message = $Message
            Context = $Context
            ProcessId = $PID
            ThreadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
            User = $env:USERNAME
            Computer = $env:COMPUTERNAME
        }
    }
    
    process {
        # Add to buffer for batch processing
        $null = $script:LogBuffer.Enqueue($logEntry)
        
        # Flush buffer if it reaches size limit
        if ($script:LogBuffer.Count -ge $script:LogBufferSize) {
            Flush-PSLogBuffer
        }
        
        # Console output
        if (-not $NoConsole) {
            $consoleMessage = "[{0:yyyy-MM-dd HH:mm:ss}] [{1}] [{2}] {3}" -f 
                $timestamp, $Level.ToUpper(), $Component, $Message
            
            switch ($Level) {
                'Debug'    { Write-Debug $consoleMessage }
                'Verbose'  { Write-Verbose $consoleMessage }
                'Info'     { Write-Host $consoleMessage -ForegroundColor Cyan }
                'Warning'  { Write-Warning $consoleMessage }
                'Error'    { Write-Host $consoleMessage -ForegroundColor Red }
                'Critical' { Write-Host $consoleMessage -ForegroundColor Red -BackgroundColor Yellow }
            }
        }
        
        if ($PassThru) {
            return $logEntry
        }
    }
}

function Initialize-PSLogContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Operation,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Properties = @{}
    )
    
    $context = @{
        OperationId = [Guid]::NewGuid().ToString()
        Operation = $Operation
        StartTime = Get-Date
        Properties = $Properties
    }
    
    Write-PSLog -Message "Initialized operation context: $Operation" -Component 'Core' -Context $context
    return $context
}

function Flush-PSLogBuffer {
    [CmdletBinding()]
    param()
    
    $entries = @()
    while ($script:LogBuffer.TryDequeue([ref]$null)) {
        $entries += $_
    }
    
    if ($entries.Count -eq 0) { return }
    
    $logFile = Join-Path $script:PSCoreConfig.LogPath "PSCore-$(Get-Date -Format 'yyyyMMdd').log"
    
    # Ensure log directory exists
    if (-not (Test-Path $script:PSCoreConfig.LogPath)) {
        New-Item -Path $script:PSCoreConfig.LogPath -ItemType Directory -Force | Out-Null
    }
    
    # Thread-safe file write
    $mutex = New-Object System.Threading.Mutex($false, "PSCoreLogMutex")
    try {
        $mutex.WaitOne() | Out-Null
        $entries | ForEach-Object {
            $logLine = ConvertTo-Json $_ -Compress
            Add-Content -Path $logFile -Value $logLine -Encoding UTF8
        }
    }
    finally {
        $mutex.ReleaseMutex()
    }
    
    # Check log rotation
    Invoke-PSLogRotation -LogFile $logFile
}

function Invoke-PSLogRotation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogFile
    )
    
    if (-not (Test-Path $LogFile)) { return }
    
    $fileInfo = Get-Item $LogFile
    $sizeMB = $fileInfo.Length / 1MB
    
    if ($sizeMB -gt $script:PSCoreConfig.MaxLogSizeMB) {
        $archiveName = "{0}-{1}.log" -f 
            [System.IO.Path]::GetFileNameWithoutExtension($LogFile),
            (Get-Date -Format 'yyyyMMdd-HHmmss')
        
        $archivePath = Join-Path $script:PSCoreConfig.LogPath $archiveName
        Move-Item -Path $LogFile -Destination $archivePath -Force
        
        # Compress old log
        Compress-Archive -Path $archivePath -DestinationPath "$archivePath.zip" -Force
        Remove-Item $archivePath -Force
        
        # Clean up old logs
        $logFiles = Get-ChildItem -Path $script:PSCoreConfig.LogPath -Filter "*.zip" |
            Sort-Object CreationTime -Descending |
            Select-Object -Skip $script:PSCoreConfig.MaxLogFiles
            
        $logFiles | Remove-Item -Force
    }
}

function Get-PSLogHistory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [datetime]$StartTime = (Get-Date).AddHours(-24),
        
        [Parameter(Mandatory = $false)]
        [datetime]$EndTime = (Get-Date),
        
        [Parameter(Mandatory = $false)]
        [string]$Level,
        
        [Parameter(Mandatory = $false)]
        [string]$Component,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxRecords = 1000
    )
    
    # Flush current buffer
    Flush-PSLogBuffer
    
    $logs = @()
    $logFiles = Get-ChildItem -Path $script:PSCoreConfig.LogPath -Filter "PSCore-*.log" |
        Where-Object { $_.LastWriteTime -ge $StartTime -and $_.LastWriteTime -le $EndTime }
    
    foreach ($file in $logFiles) {
        $content = Get-Content $file.FullName | ForEach-Object {
            try {
                ConvertFrom-Json $_
            } catch {
                $null
            }
        } | Where-Object { $_ }
        
        $logs += $content
    }
    
    # Apply filters
    if ($Level) {
        $logs = $logs | Where-Object { $_.Level -eq $Level }
    }
    
    if ($Component) {
        $logs = $logs | Where-Object { $_.Component -eq $Component }
    }
    
    # Sort and limit
    $logs | Sort-Object Timestamp -Descending | Select-Object -First $MaxRecords
}
#endregion

#region Configuration Management
function Get-PSConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Scope = 'Module',
        
        [Parameter(Mandatory = $false)]
        [switch]$Decrypt
    )
    
    $configFile = Join-Path $script:PSCoreConfig.ConfigPath "$Scope-$Name.json"
    
    if (-not (Test-Path $configFile)) {
        Write-PSLog -Message "Configuration not found: $Name (Scope: $Scope)" -Level 'Warning' -Component 'Configuration'
        return $null
    }
    
    try {
        $config = Get-Content $configFile -Raw | ConvertFrom-Json
        
        if ($Decrypt -and $config.PSObject.Properties['Encrypted'] -and $config.Encrypted) {
            # Decrypt sensitive values
            $config = Decrypt-PSConfiguration -Configuration $config
        }
        
        Write-PSLog -Message "Configuration loaded: $Name" -Component 'Configuration'
        return $config
    }
    catch {
        Write-PSLog -Message "Failed to load configuration: $_" -Level 'Error' -Component 'Configuration'
        throw
    }
}

function Set-PSConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [object]$Configuration,
        
        [Parameter(Mandatory = $false)]
        [string]$Scope = 'Module',
        
        [Parameter(Mandatory = $false)]
        [switch]$Encrypt,
        
        [Parameter(Mandatory = $false)]
        [string]$Schema
    )
    
    # Ensure config directory exists
    if (-not (Test-Path $script:PSCoreConfig.ConfigPath)) {
        New-Item -Path $script:PSCoreConfig.ConfigPath -ItemType Directory -Force | Out-Null
    }
    
    # Validate against schema if provided
    if ($Schema) {
        if (-not (Test-PSConfiguration -Configuration $Configuration -Schema $Schema)) {
            throw "Configuration validation failed against schema"
        }
    }
    
    $configFile = Join-Path $script:PSCoreConfig.ConfigPath "$Scope-$Name.json"
    
    try {
        $configData = $Configuration
        
        if ($Encrypt) {
            $configData = Encrypt-PSConfiguration -Configuration $Configuration
        }
        
        $configData | ConvertTo-Json -Depth 10 | Set-Content $configFile -Encoding UTF8
        
        Write-PSLog -Message "Configuration saved: $Name" -Component 'Configuration'
    }
    catch {
        Write-PSLog -Message "Failed to save configuration: $_" -Level 'Error' -Component 'Configuration'
        throw
    }
}

function Test-PSConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Configuration,
        
        [Parameter(Mandatory = $true)]
        [object]$Schema
    )
    
    # Implement JSON Schema validation
    # This is a simplified version - in production, use a proper JSON Schema validator
    
    try {
        foreach ($property in $Schema.required) {
            if (-not $Configuration.PSObject.Properties[$property]) {
                Write-PSLog -Message "Missing required property: $property" -Level 'Error' -Component 'Configuration'
                return $false
            }
        }
        
        foreach ($prop in $Configuration.PSObject.Properties) {
            if ($Schema.properties.PSObject.Properties[$prop.Name]) {
                $expectedType = $Schema.properties.$($prop.Name).type
                $actualType = $prop.Value.GetType().Name.ToLower()
                
                if ($expectedType -ne $actualType -and -not ($expectedType -eq 'integer' -and $actualType -eq 'int32')) {
                    Write-PSLog -Message "Type mismatch for property '$($prop.Name)': expected $expectedType, got $actualType" -Level 'Error' -Component 'Configuration'
                    return $false
                }
            }
        }
        
        return $true
    }
    catch {
        Write-PSLog -Message "Configuration validation error: $_" -Level 'Error' -Component 'Configuration'
        return $false
    }
}

function New-PSConfigurationSchema {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Properties,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Required = @(),
        
        [Parameter(Mandatory = $false)]
        [string]$Description
    )
    
    $schema = @{
        '$schema' = 'http://json-schema.org/draft-07/schema#'
        title = $Name
        type = 'object'
        description = $Description
        properties = @{}
        required = $Required
    }
    
    foreach ($key in $Properties.Keys) {
        $prop = $Properties[$key]
        if ($prop -is [hashtable]) {
            $schema.properties[$key] = $prop
        } else {
            $schema.properties[$key] = @{
                type = switch ($prop) {
                    { $_ -is [string] } { 'string' }
                    { $_ -is [int] } { 'integer' }
                    { $_ -is [bool] } { 'boolean' }
                    { $_ -is [array] } { 'array' }
                    default { 'object' }
                }
            }
        }
    }
    
    return $schema
}
#endregion

#region Credential Management
function Get-PSCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Purpose
    )
    
    $credPath = Join-Path $script:PSCoreConfig.CredentialPath "$Name.xml"
    
    if (-not (Test-Path $credPath)) {
        Write-PSLog -Message "Credential not found: $Name" -Level 'Warning' -Component 'Credential'
        
        # Prompt for credential
        $message = if ($Purpose) { "Enter credential for: $Purpose" } else { "Enter credential: $Name" }
        $credential = Get-Credential -Message $message
        
        if ($credential) {
            Set-PSCredential -Name $Name -Credential $credential
        }
        
        return $credential
    }
    
    try {
        $credential = Import-Clixml $credPath
        Write-PSLog -Message "Credential loaded: $Name" -Component 'Credential'
        return $credential
    }
    catch {
        Write-PSLog -Message "Failed to load credential: $_" -Level 'Error' -Component 'Credential'
        throw
    }
}

function Set-PSCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [string]$Description
    )
    
    # Ensure credential directory exists
    if (-not (Test-Path $script:PSCoreConfig.CredentialPath)) {
        New-Item -Path $script:PSCoreConfig.CredentialPath -ItemType Directory -Force | Out-Null
    }
    
    $credPath = Join-Path $script:PSCoreConfig.CredentialPath "$Name.xml"
    
    try {
        # Export with Windows Data Protection API (DPAPI)
        $Credential | Export-Clixml $credPath
        
        # Set restrictive permissions
        $acl = Get-Acl $credPath
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $env:USERNAME, 'FullControl', 'Allow'
        )
        $acl.SetAccessRule($rule)
        Set-Acl $credPath $acl
        
        # Store metadata
        if ($Description) {
            $metaPath = Join-Path $script:PSCoreConfig.CredentialPath "$Name.meta"
            @{
                Name = $Name
                Description = $Description
                CreatedBy = $env:USERNAME
                CreatedDate = Get-Date
                LastModified = Get-Date
            } | ConvertTo-Json | Set-Content $metaPath
        }
        
        Write-PSLog -Message "Credential stored: $Name" -Component 'Credential'
    }
    catch {
        Write-PSLog -Message "Failed to store credential: $_" -Level 'Error' -Component 'Credential'
        throw
    }
}

function Test-PSCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [string]$Domain = $env:USERDOMAIN,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Local', 'Domain', 'Machine')]
        [string]$AuthType = 'Domain'
    )
    
    try {
        $username = $Credential.Username
        $password = $Credential.GetNetworkCredential().Password
        
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        
        $contextType = switch ($AuthType) {
            'Local' { [System.DirectoryServices.AccountManagement.ContextType]::Machine }
            'Domain' { [System.DirectoryServices.AccountManagement.ContextType]::Domain }
            'Machine' { [System.DirectoryServices.AccountManagement.ContextType]::Machine }
        }
        
        $context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
            $contextType, $Domain
        )
        
        $valid = $context.ValidateCredentials($username, $password)
        
        Write-PSLog -Message "Credential validation result for $username`: $valid" -Component 'Credential'
        return $valid
    }
    catch {
        Write-PSLog -Message "Credential validation failed: $_" -Level 'Error' -Component 'Credential'
        return $false
    }
}
#endregion

#region Module Management
function Import-PSModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [version]$MinimumVersion,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    try {
        # Check if module is already loaded
        $loaded = Get-Module -Name $Name
        
        if ($loaded) {
            if ($MinimumVersion -and $loaded.Version -lt $MinimumVersion) {
                Write-PSLog -Message "Module $Name version $($loaded.Version) is below minimum required version $MinimumVersion" -Level 'Warning' -Component 'Module'
                
                if ($Force) {
                    Remove-Module $Name -Force
                    $loaded = $null
                } else {
                    throw "Module version conflict"
                }
            } else {
                Write-PSLog -Message "Module already loaded: $Name v$($loaded.Version)" -Component 'Module'
                return $loaded
            }
        }
        
        # Import module
        $importParams = @{
            Name = $Name
            ErrorAction = 'Stop'
            Force = $Force
        }
        
        if ($MinimumVersion) {
            $importParams['MinimumVersion'] = $MinimumVersion
        }
        
        $module = Import-Module @importParams -PassThru
        
        Write-PSLog -Message "Module imported: $Name v$($module.Version)" -Component 'Module'
        return $module
    }
    catch {
        Write-PSLog -Message "Failed to import module $Name`: $_" -Level 'Error' -Component 'Module'
        throw
    }
}

function Test-PSModuleDependency {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModulePath
    )
    
    $manifest = Get-PSModuleManifest -Path $ModulePath
    $missingDependencies = @()
    
    # Check PowerShell version
    if ($manifest.PowerShellVersion) {
        $currentVersion = $PSVersionTable.PSVersion
        if ($currentVersion -lt [version]$manifest.PowerShellVersion) {
            $missingDependencies += @{
                Type = 'PowerShellVersion'
                Required = $manifest.PowerShellVersion
                Current = $currentVersion.ToString()
            }
        }
    }
    
    # Check required modules
    if ($manifest.RequiredModules) {
        foreach ($required in $manifest.RequiredModules) {
            $moduleName = if ($required -is [hashtable]) { $required.ModuleName } else { $required }
            $moduleVersion = if ($required -is [hashtable]) { $required.ModuleVersion } else { $null }
            
            $available = Get-Module -ListAvailable -Name $moduleName
            
            if (-not $available) {
                $missingDependencies += @{
                    Type = 'Module'
                    Name = $moduleName
                    Required = $moduleVersion
                    Status = 'NotFound'
                }
            } elseif ($moduleVersion -and $available.Version -lt [version]$moduleVersion) {
                $missingDependencies += @{
                    Type = 'Module'
                    Name = $moduleName
                    Required = $moduleVersion
                    Current = $available.Version.ToString()
                    Status = 'VersionMismatch'
                }
            }
        }
    }
    
    return @{
        HasDependencies = $missingDependencies.Count -eq 0
        MissingDependencies = $missingDependencies
    }
}

function Resolve-PSModuleDependencies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModulePath,
        
        [Parameter(Mandatory = $false)]
        [switch]$Install
    )
    
    $dependencyCheck = Test-PSModuleDependency -ModulePath $ModulePath
    
    if ($dependencyCheck.HasDependencies) {
        Write-PSLog -Message "All dependencies satisfied for module: $ModulePath" -Component 'Module'
        return $true
    }
    
    Write-PSLog -Message "Missing dependencies detected: $($dependencyCheck.MissingDependencies.Count)" -Level 'Warning' -Component 'Module'
    
    if ($Install) {
        foreach ($dep in $dependencyCheck.MissingDependencies) {
            if ($dep.Type -eq 'Module') {
                try {
                    Write-PSLog -Message "Installing module: $($dep.Name)" -Component 'Module'
                    
                    $installParams = @{
                        Name = $dep.Name
                        Force = $true
                        AllowClobber = $true
                    }
                    
                    if ($dep.Required) {
                        $installParams['MinimumVersion'] = $dep.Required
                    }
                    
                    Install-Module @installParams
                    Write-PSLog -Message "Module installed: $($dep.Name)" -Level 'Success' -Component 'Module'
                }
                catch {
                    Write-PSLog -Message "Failed to install module $($dep.Name): $_" -Level 'Error' -Component 'Module'
                }
            }
        }
        
        # Re-check dependencies
        return (Test-PSModuleDependency -ModulePath $ModulePath).HasDependencies
    }
    
    return $false
}

function Get-PSModuleManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    
    if ($Path -notlike '*.psd1') {
        # Look for manifest in module directory
        $manifestPath = Get-ChildItem -Path $Path -Filter '*.psd1' | Select-Object -First 1
        if (-not $manifestPath) {
            throw "No module manifest found in path: $Path"
        }
        $Path = $manifestPath.FullName
    }
    
    try {
        $manifest = Import-PowerShellDataFile -Path $Path
        return $manifest
    }
    catch {
        Write-PSLog -Message "Failed to read module manifest: $_" -Level 'Error' -Component 'Module'
        throw
    }
}
#endregion

#region Error Handling
function New-PSError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [string]$ErrorId = 'PSCoreError',
        
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.ErrorCategory]$Category = 'NotSpecified',
        
        [Parameter(Mandatory = $false)]
        [object]$TargetObject,
        
        [Parameter(Mandatory = $false)]
        [Exception]$InnerException
    )
    
    $exception = if ($InnerException) {
        New-Object System.Exception($Message, $InnerException)
    } else {
        New-Object System.Exception($Message)
    }
    
    $errorRecord = New-Object System.Management.Automation.ErrorRecord(
        $exception,
        $ErrorId,
        $Category,
        $TargetObject
    )
    
    Write-PSErrorLog -ErrorRecord $errorRecord
    return $errorRecord
}

function Write-PSErrorLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Context = @{}
    )
    
    $errorDetails = @{
        Message = $ErrorRecord.Exception.Message
        ErrorId = $ErrorRecord.FullyQualifiedErrorId
        Category = $ErrorRecord.CategoryInfo.Category
        Activity = $ErrorRecord.CategoryInfo.Activity
        Reason = $ErrorRecord.CategoryInfo.Reason
        TargetName = $ErrorRecord.CategoryInfo.TargetName
        TargetType = $ErrorRecord.CategoryInfo.TargetType
        ScriptStackTrace = $ErrorRecord.ScriptStackTrace
        InnerException = if ($ErrorRecord.Exception.InnerException) {
            $ErrorRecord.Exception.InnerException.Message
        } else { $null }
    }
    
    Write-PSLog -Message $ErrorRecord.Exception.Message -Level 'Error' -Component 'ErrorHandler' -Context @{
        ErrorDetails = $errorDetails
        UserContext = $Context
    }
}

function Invoke-PSRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxAttempts = 3,
        
        [Parameter(Mandatory = $false)]
        [int]$DelaySeconds = 5,
        
        [Parameter(Mandatory = $false)]
        [scriptblock]$OnRetry,
        
        [Parameter(Mandatory = $false)]
        [Type[]]$RetryableExceptions = @([System.Exception])
    )
    
    $attempt = 0
    $lastError = $null
    
    while ($attempt -lt $MaxAttempts) {
        $attempt++
        
        try {
            Write-PSLog -Message "Executing operation (Attempt $attempt/$MaxAttempts)" -Component 'Retry'
            $result = & $ScriptBlock
            Write-PSLog -Message "Operation succeeded on attempt $attempt" -Level 'Success' -Component 'Retry'
            return $result
        }
        catch {
            $lastError = $_
            $isRetryable = $false
            
            foreach ($exceptionType in $RetryableExceptions) {
                if ($_.Exception -is $exceptionType) {
                    $isRetryable = $true
                    break
                }
            }
            
            if (-not $isRetryable) {
                Write-PSLog -Message "Non-retryable exception encountered: $($_.Exception.GetType().Name)" -Level 'Error' -Component 'Retry'
                throw
            }
            
            if ($attempt -lt $MaxAttempts) {
                Write-PSLog -Message "Operation failed on attempt $attempt`: $($_.Exception.Message). Retrying in $DelaySeconds seconds..." -Level 'Warning' -Component 'Retry'
                
                if ($OnRetry) {
                    & $OnRetry -Attempt $attempt -Error $_
                }
                
                Start-Sleep -Seconds $DelaySeconds
            }
        }
    }
    
    Write-PSLog -Message "Operation failed after $MaxAttempts attempts" -Level 'Error' -Component 'Retry'
    throw $lastError
}
#endregion

#region Performance Monitoring
function Measure-PSPerformance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        
        [Parameter(Mandatory = $false)]
        [string]$Name = 'Operation',
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeMemory
    )
    
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $startMemory = if ($IncludeMemory) {
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        [System.GC]::Collect()
        [System.GC]::GetTotalMemory($false)
    } else { 0 }
    
    try {
        $result = & $ScriptBlock
        $stopwatch.Stop()
        
        $endMemory = if ($IncludeMemory) {
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            [System.GC]::Collect()
            [System.GC]::GetTotalMemory($false)
        } else { 0 }
        
        $metrics = @{
            Name = $Name
            Duration = $stopwatch.Elapsed
            DurationMs = $stopwatch.ElapsedMilliseconds
            StartTime = (Get-Date).AddMilliseconds(-$stopwatch.ElapsedMilliseconds)
            EndTime = Get-Date
            Success = $true
            MemoryUsedBytes = if ($IncludeMemory) { $endMemory - $startMemory } else { 0 }
            MemoryUsedMB = if ($IncludeMemory) { [Math]::Round(($endMemory - $startMemory) / 1MB, 2) } else { 0 }
        }
        
        # Store in global metrics
        if (-not $script:PSPerformanceMetrics.ContainsKey($Name)) {
            $script:PSPerformanceMetrics[$Name] = @()
        }
        $script:PSPerformanceMetrics[$Name] += $metrics
        
        Write-PSLog -Message "Performance measured for '$Name': $($metrics.DurationMs)ms" -Component 'Performance' -Context $metrics
        
        return [PSCustomObject]@{
            Result = $result
            Metrics = $metrics
        }
    }
    catch {
        $stopwatch.Stop()
        
        $metrics = @{
            Name = $Name
            Duration = $stopwatch.Elapsed
            DurationMs = $stopwatch.ElapsedMilliseconds
            StartTime = (Get-Date).AddMilliseconds(-$stopwatch.ElapsedMilliseconds)
            EndTime = Get-Date
            Success = $false
            Error = $_.Exception.Message
        }
        
        Write-PSLog -Message "Performance measurement failed for '$Name': $_" -Level 'Error' -Component 'Performance' -Context $metrics
        throw
    }
}

function Start-PSPerformanceMonitor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SessionName,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Counters = @('\Processor(_Total)\% Processor Time', '\Memory\Available MBytes', '\Process(_Total)\Working Set')
    )
    
    $session = @{
        Name = $SessionName
        StartTime = Get-Date
        Counters = $Counters
        JobId = $null
    }
    
    $scriptBlock = {
        param($Counters, $SessionName)
        
        $results = @()
        while ($true) {
            $sample = @{
                Timestamp = Get-Date
                Counters = @{}
            }
            
            foreach ($counter in $Counters) {
                try {
                    $value = (Get-Counter -Counter $counter -ErrorAction SilentlyContinue).CounterSamples[0].CookedValue
                    $sample.Counters[$counter] = $value
                } catch {
                    $sample.Counters[$counter] = $null
                }
            }
            
            $results += $sample
            Start-Sleep -Seconds 5
        }
    }
    
    $job = Start-Job -ScriptBlock $scriptBlock -ArgumentList $Counters, $SessionName
    $session.JobId = $job.Id
    
    if (-not $script:PerformanceSessions) {
        $script:PerformanceSessions = @{}
    }
    
    $script:PerformanceSessions[$SessionName] = $session
    
    Write-PSLog -Message "Performance monitoring started: $SessionName" -Component 'Performance'
    return $session
}

function Stop-PSPerformanceMonitor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SessionName
    )
    
    if (-not $script:PerformanceSessions -or -not $script:PerformanceSessions.ContainsKey($SessionName)) {
        Write-PSLog -Message "Performance session not found: $SessionName" -Level 'Warning' -Component 'Performance'
        return
    }
    
    $session = $script:PerformanceSessions[$SessionName]
    
    if ($session.JobId) {
        Stop-Job -Id $session.JobId -ErrorAction SilentlyContinue
        $results = Receive-Job -Id $session.JobId -ErrorAction SilentlyContinue
        Remove-Job -Id $session.JobId -ErrorAction SilentlyContinue
        
        $session.EndTime = Get-Date
        $session.Duration = $session.EndTime - $session.StartTime
        $session.Results = $results
        
        # Calculate statistics
        if ($results) {
            $session.Statistics = @{}
            foreach ($counter in $session.Counters) {
                $values = $results | ForEach-Object { $_.Counters[$counter] } | Where-Object { $_ -ne $null }
                if ($values) {
                    $session.Statistics[$counter] = @{
                        Average = [Math]::Round(($values | Measure-Object -Average).Average, 2)
                        Minimum = [Math]::Round(($values | Measure-Object -Minimum).Minimum, 2)
                        Maximum = [Math]::Round(($values | Measure-Object -Maximum).Maximum, 2)
                        Count = $values.Count
                    }
                }
            }
        }
        
        Write-PSLog -Message "Performance monitoring stopped: $SessionName" -Component 'Performance' -Context @{
            Duration = $session.Duration.ToString()
            SampleCount = $results.Count
        }
        
        return $session
    }
}

function Get-PSPerformanceReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [int]$TopN = 10
    )
    
    $report = @{
        GeneratedDate = Get-Date
        Operations = @{}
        Summary = @{}
    }
    
    if ($Name) {
        if ($script:PSPerformanceMetrics.ContainsKey($Name)) {
            $report.Operations[$Name] = Get-OperationStats -Metrics $script:PSPerformanceMetrics[$Name]
        }
    } else {
        foreach ($op in $script:PSPerformanceMetrics.Keys) {
            $report.Operations[$op] = Get-OperationStats -Metrics $script:PSPerformanceMetrics[$op]
        }
    }
    
    # Overall summary
    $allMetrics = $script:PSPerformanceMetrics.Values | ForEach-Object { $_ }
    if ($allMetrics) {
        $report.Summary = @{
            TotalOperations = $allMetrics.Count
            TotalDurationMs = ($allMetrics | Measure-Object -Property DurationMs -Sum).Sum
            AverageDurationMs = [Math]::Round(($allMetrics | Measure-Object -Property DurationMs -Average).Average, 2)
            SuccessRate = [Math]::Round(($allMetrics | Where-Object { $_.Success } | Measure-Object).Count / $allMetrics.Count * 100, 2)
            TopSlowest = $allMetrics | Sort-Object DurationMs -Descending | Select-Object -First $TopN | ForEach-Object {
                @{
                    Name = $_.Name
                    DurationMs = $_.DurationMs
                    Time = $_.StartTime
                }
            }
        }
    }
    
    return $report
}

function Get-OperationStats {
    param($Metrics)
    
    @{
        Count = $Metrics.Count
        TotalDurationMs = ($Metrics | Measure-Object -Property DurationMs -Sum).Sum
        AverageDurationMs = [Math]::Round(($Metrics | Measure-Object -Property DurationMs -Average).Average, 2)
        MinDurationMs = ($Metrics | Measure-Object -Property DurationMs -Minimum).Minimum
        MaxDurationMs = ($Metrics | Measure-Object -Property DurationMs -Maximum).Maximum
        SuccessRate = [Math]::Round(($Metrics | Where-Object { $_.Success } | Measure-Object).Count / $Metrics.Count * 100, 2)
        LastRun = ($Metrics | Sort-Object StartTime -Descending | Select-Object -First 1).StartTime
    }
}
#endregion

#region Validation Functions
function Test-PSParameter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Value,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('Email', 'IPAddress', 'URL', 'Path', 'ComputerName', 'NotEmpty', 'Numeric', 'AlphaNumeric', 'Regex')]
        [string]$Type,
        
        [Parameter(Mandatory = $false)]
        [string]$Pattern
    )
    
    switch ($Type) {
        'Email' {
            return $Value -match '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        }
        'IPAddress' {
            return [System.Net.IPAddress]::TryParse($Value, [ref]$null)
        }
        'URL' {
            return $Value -match '^https?://[^\s/$.?#].[^\s]*$'
        }
        'Path' {
            return Test-Path $Value -IsValid
        }
        'ComputerName' {
            return $Value -match '^[a-zA-Z0-9][a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9]$'
        }
        'NotEmpty' {
            return -not [string]::IsNullOrWhiteSpace($Value)
        }
        'Numeric' {
            return $Value -match '^\d+$'
        }
        'AlphaNumeric' {
            return $Value -match '^[a-zA-Z0-9]+$'
        }
        'Regex' {
            if (-not $Pattern) {
                throw "Pattern parameter required for Regex validation"
            }
            return $Value -match $Pattern
        }
    }
}

function Assert-PSRequirement {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Condition,
        
        [Parameter(Mandatory = $true)]
        [string]$ErrorMessage,
        
        [Parameter(Mandatory = $false)]
        [string]$ErrorId = 'RequirementNotMet'
    )
    
    $result = & $Condition
    
    if (-not $result) {
        $error = New-PSError -Message $ErrorMessage -ErrorId $ErrorId -Category 'InvalidOperation'
        throw $error
    }
}

function New-PSValidationRule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [scriptblock]$ValidationScript,
        
        [Parameter(Mandatory = $false)]
        [string]$ErrorMessage = "Validation failed for rule: $Name",
        
        [Parameter(Mandatory = $false)]
        [string]$Description
    )
    
    @{
        Name = $Name
        Description = $Description
        ValidationScript = $ValidationScript
        ErrorMessage = $ErrorMessage
        CreatedDate = Get-Date
    }
}
#endregion

#region Threading Functions
function Start-PSJob {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Parameters = @{},
        
        [Parameter(Mandatory = $false)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [int]$ThrottleLimit = 5
    )
    
    # Use ThreadJob for better performance
    if (Get-Command Start-ThreadJob -ErrorAction SilentlyContinue) {
        $jobParams = @{
            ScriptBlock = $ScriptBlock
            ThrottleLimit = $ThrottleLimit
        }
        
        if ($Name) { $jobParams['Name'] = $Name }
        if ($Parameters.Count -gt 0) {
            $jobParams['ArgumentList'] = $Parameters.Values
        }
        
        $job = Start-ThreadJob @jobParams
    } else {
        # Fallback to regular job
        $jobParams = @{
            ScriptBlock = $ScriptBlock
        }
        
        if ($Name) { $jobParams['Name'] = $Name }
        if ($Parameters.Count -gt 0) {
            $jobParams['ArgumentList'] = $Parameters.Values
        }
        
        $job = Start-Job @jobParams
    }
    
    Write-PSLog -Message "Job started: $($job.Id) - $($job.Name)" -Component 'Threading'
    return $job
}

function Wait-PSJob {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Job[]]$Job,
        
        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds,
        
        [Parameter(Mandatory = $false)]
        [switch]$ShowProgress
    )
    
    $startTime = Get-Date
    $completed = @()
    
    while ($Job.Count -gt $completed.Count) {
        if ($TimeoutSeconds -and ((Get-Date) - $startTime).TotalSeconds -gt $TimeoutSeconds) {
            Write-PSLog -Message "Job wait timeout reached" -Level 'Warning' -Component 'Threading'
            break
        }
        
        $running = $Job | Where-Object { $_.State -eq 'Running' }
        $finished = $Job | Where-Object { $_.State -ne 'Running' -and $_.Id -notin $completed.Id }
        
        foreach ($finishedJob in $finished) {
            $completed += $finishedJob
            Write-PSLog -Message "Job completed: $($finishedJob.Id) - State: $($finishedJob.State)" -Component 'Threading'
        }
        
        if ($ShowProgress -and $running.Count -gt 0) {
            $percentComplete = ($completed.Count / $Job.Count) * 100
            Write-Progress -Activity "Waiting for jobs" -Status "$($completed.Count) of $($Job.Count) completed" -PercentComplete $percentComplete
        }
        
        Start-Sleep -Milliseconds 500
    }
    
    if ($ShowProgress) {
        Write-Progress -Activity "Waiting for jobs" -Completed
    }
    
    return $completed
}

function Get-PSJobResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Job[]]$Job,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeErrors
    )
    
    $results = @()
    
    foreach ($j in $Job) {
        $result = @{
            JobId = $j.Id
            JobName = $j.Name
            State = $j.State
            StartTime = $j.PSBeginTime
            EndTime = $j.PSEndTime
            Duration = if ($j.PSEndTime -and $j.PSBeginTime) { $j.PSEndTime - $j.PSBeginTime } else { $null }
            Output = $null
            Errors = @()
            HasErrors = $false
        }
        
        if ($j.State -eq 'Completed') {
            $result.Output = Receive-Job -Job $j -ErrorAction SilentlyContinue
        }
        
        if ($IncludeErrors -or $j.State -eq 'Failed') {
            $result.Errors = $j.ChildJobs | ForEach-Object {
                $_.Error
            }
            $result.HasErrors = $result.Errors.Count -gt 0
        }
        
        $results += [PSCustomObject]$result
    }
    
    return $results
}
#endregion

#region Utility Functions
function ConvertTo-PSHashtable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$InputObject,
        
        [Parameter(Mandatory = $false)]
        [switch]$Recurse
    )
    
    process {
        if ($InputObject -is [System.Collections.IDictionary]) {
            return $InputObject
        }
        
        if ($InputObject -is [PSCustomObject] -or $InputObject -is [PSObject]) {
            $hash = @{}
            
            $InputObject.PSObject.Properties | ForEach-Object {
                $value = $_.Value
                
                if ($Recurse -and ($value -is [PSCustomObject] -or $value -is [PSObject])) {
                    $value = ConvertTo-PSHashtable -InputObject $value -Recurse
                }
                
                $hash[$_.Name] = $value
            }
            
            return $hash
        }
        
        return $InputObject
    }
}

function Get-PSEnvironment {
    [CmdletBinding()]
    param()
    
    @{
        ComputerName = $env:COMPUTERNAME
        UserName = $env:USERNAME
        UserDomain = $env:USERDOMAIN
        OperatingSystem = [System.Environment]::OSVersion.VersionString
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        CLRVersion = $PSVersionTable.CLRVersion.ToString()
        Culture = (Get-Culture).Name
        Elevation = Test-PSElevation
        ProcessId = $PID
        WorkingDirectory = $PWD.Path
        ModulePath = $env:PSModulePath
        TempPath = $env:TEMP
        SystemRoot = $env:SystemRoot
        ProgramFiles = $env:ProgramFiles
        ProgramData = $env:ProgramData
    }
}

function Test-PSElevation {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    if ($PSVersionTable.Platform -eq 'Unix') {
        # Unix/Linux elevation check
        return (id -u) -eq 0
    } else {
        # Windows elevation check
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
}

function Invoke-PSElevated {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        
        [Parameter(Mandatory = $false)]
        [object[]]$ArgumentList
    )
    
    if (Test-PSElevation) {
        # Already elevated, run directly
        return & $ScriptBlock @ArgumentList
    }
    
    # Windows elevation
    if ($PSVersionTable.Platform -ne 'Unix') {
        $encodedCommand = [Convert]::ToBase64String(
            [System.Text.Encoding]::Unicode.GetBytes($ScriptBlock.ToString())
        )
        
        $argString = if ($ArgumentList) {
            $ArgumentList | ForEach-Object { "'$_'" } | Join-String -Separator ','
        } else { '' }
        
        $startParams = @{
            FilePath = 'powershell.exe'
            ArgumentList = "-NoProfile -EncodedCommand $encodedCommand $argString"
            Verb = 'RunAs'
            Wait = $true
            PassThru = $true
        }
        
        $process = Start-Process @startParams
        return $process.ExitCode
    } else {
        # Unix/Linux elevation
        throw "Unix elevation not implemented. Run with sudo."
    }
}
#endregion

#region Module Initialization
# Create required directories
$requiredPaths = @(
    $script:PSCoreConfig.LogPath
    $script:PSCoreConfig.ConfigPath
    $script:PSCoreConfig.CredentialPath
)

foreach ($path in $requiredPaths) {
    if (-not (Test-Path $path)) {
        New-Item -Path $path -ItemType Directory -Force | Out-Null
    }
}

# Set up log buffer flush timer
$timer = New-Object System.Timers.Timer
$timer.Interval = 5000 # 5 seconds
$timer.AutoReset = $true
$timer.add_Elapsed({
    Flush-PSLogBuffer
})
$timer.Start()

# Module cleanup
$MyInvocation.MyCommand.Module.OnRemove = {
    Flush-PSLogBuffer
    if ($timer) {
        $timer.Stop()
        $timer.Dispose()
    }
}
#endregion

# Export module members with aliases
New-Alias -Name pslog -Value Write-PSLog
New-Alias -Name pscfg -Value Get-PSConfiguration
New-Alias -Name pscred -Value Get-PSCredential

Export-ModuleMember -Function * -Variable PSCoreConfig, PSLogLevel, PSPerformanceMetrics -Alias *