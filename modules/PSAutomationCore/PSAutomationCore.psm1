#Requires -Version 5.1

<#
.SYNOPSIS
    PSAutomationCore - Enterprise automation framework with SOLID architecture
.DESCRIPTION
    Core module providing dependency injection, configuration management, plugin architecture,
    security framework, and performance monitoring for enterprise PowerShell automation.
.NOTES
    Author: Enterprise Automation Team
    Version: 2.0.0
    Architecture: Service-Oriented with Dependency Injection
#>

# Module-level variables
$script:AutomationContext = $null
$script:ServiceContainer = @{}
$script:ServiceScopes = @{}
$script:PluginRegistry = @{}
$script:ConfigurationCache = @{}
$script:SecurityContexts = @{}
$script:PerformanceTraces = @{}
$script:LogTargets = @()

#region Core Architecture Functions

function Initialize-AutomationPlatform {
    <#
    .SYNOPSIS
        Initializes the automation platform with core services and configuration
    .DESCRIPTION
        Sets up the dependency injection container, loads configuration, initializes
        security context, and prepares the plugin architecture for use.
    .PARAMETER ConfigurationPath
        Path to the configuration directory
    .PARAMETER Environment
        Environment name (Development, Staging, Production)
    .PARAMETER EnablePerformanceTracking
        Enable performance monitoring
    .EXAMPLE
        Initialize-AutomationPlatform -Environment "Production"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ConfigurationPath = "$PSScriptRoot\..\..\config",
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Development', 'Staging', 'Production')]
        [string]$Environment = 'Production',
        
        [Parameter(Mandatory = $false)]
        [switch]$EnablePerformanceTracking = $true
    )
    
    try {
        Write-Verbose "Initializing automation platform for environment: $Environment"
        
        # Create automation context
        $script:AutomationContext = [PSCustomObject]@{
            Environment = $Environment
            ConfigurationPath = $ConfigurationPath
            InitializedAt = Get-Date
            Version = (Get-Module PSAutomationCore).Version
            PerformanceTracking = $EnablePerformanceTracking
            SecurityMode = 'Strict'
            ServiceScopes = @{}
            ActivePlugins = @{}
        }
        
        # Initialize core services
        Initialize-CoreServices
        
        # Load configuration
        Load-PlatformConfiguration -Path $ConfigurationPath -Environment $Environment
        
        # Initialize security context
        Initialize-SecurityFramework
        
        # Discover and load plugins
        Discover-Plugins
        
        # Initialize performance monitoring
        if ($EnablePerformanceTracking) {
            Initialize-PerformanceMonitoring
        }
        
        Write-AutomationLog -Message "Automation platform initialized successfully" -Level Information
        return $script:AutomationContext
        
    } catch {
        Write-Error "Failed to initialize automation platform: $_"
        throw
    }
}

function Get-AutomationContext {
    <#
    .SYNOPSIS
        Returns the current automation context
    .DESCRIPTION
        Retrieves the active automation context containing environment settings,
        configuration, and runtime information.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()
    
    if ($null -eq $script:AutomationContext) {
        throw "Automation platform not initialized. Call Initialize-AutomationPlatform first."
    }
    
    return $script:AutomationContext
}

function Set-AutomationContext {
    <#
    .SYNOPSIS
        Updates automation context properties
    .DESCRIPTION
        Modifies specific properties of the automation context while maintaining
        security and consistency.
    .PARAMETER Property
        Property name to update
    .PARAMETER Value
        New value for the property
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Environment', 'SecurityMode', 'PerformanceTracking')]
        [string]$Property,
        
        [Parameter(Mandatory = $true)]
        [object]$Value
    )
    
    $context = Get-AutomationContext
    
    # Validate property-specific rules
    switch ($Property) {
        'Environment' {
            if ($Value -notin @('Development', 'Staging', 'Production')) {
                throw "Invalid environment: $Value"
            }
        }
        'SecurityMode' {
            if ($Value -notin @('Strict', 'Moderate', 'Permissive')) {
                throw "Invalid security mode: $Value"
            }
        }
    }
    
    $oldValue = $context.$Property
    $context.$Property = $Value
    
    Write-AutomationLog -Message "Automation context updated: $Property changed from '$oldValue' to '$Value'" -Level Information
}

#endregion

#region Dependency Injection

function Register-Service {
    <#
    .SYNOPSIS
        Registers a service in the dependency injection container
    .DESCRIPTION
        Adds a service implementation to the DI container with specified lifetime
        and optional factory function.
    .PARAMETER ServiceType
        Type/interface name of the service
    .PARAMETER Implementation
        Implementation object or factory scriptblock
    .PARAMETER Lifetime
        Service lifetime (Singleton, Scoped, Transient)
    .PARAMETER Tags
        Tags for service categorization
    .EXAMPLE
        Register-Service -ServiceType "IBackupService" -Implementation { New-BackupService } -Lifetime Scoped
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceType,
        
        [Parameter(Mandatory = $true)]
        [object]$Implementation,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Singleton', 'Scoped', 'Transient')]
        [string]$Lifetime = 'Singleton',
        
        [Parameter(Mandatory = $false)]
        [string[]]$Tags = @()
    )
    
    try {
        $serviceDescriptor = [PSCustomObject]@{
            ServiceType = $ServiceType
            Implementation = $Implementation
            Lifetime = $Lifetime
            Tags = $Tags
            RegisteredAt = Get-Date
            Instance = $null
        }
        
        # For singleton services, create instance immediately
        if ($Lifetime -eq 'Singleton' -and $Implementation -is [scriptblock]) {
            $serviceDescriptor.Instance = & $Implementation
        } elseif ($Lifetime -eq 'Singleton' -and $Implementation -isnot [scriptblock]) {
            $serviceDescriptor.Instance = $Implementation
        }
        
        $script:ServiceContainer[$ServiceType] = $serviceDescriptor
        
        Write-AutomationLog -Message "Service registered: $ServiceType (Lifetime: $Lifetime)" -Level Debug
        
    } catch {
        Write-Error "Failed to register service '$ServiceType': $_"
        throw
    }
}

function Get-Service {
    <#
    .SYNOPSIS
        Retrieves a service from the dependency injection container
    .DESCRIPTION
        Gets a service instance based on its type and current scope, handling
        lifetime management automatically.
    .PARAMETER ServiceType
        Type/interface name of the service
    .PARAMETER Scope
        Service scope identifier (for scoped services)
    .EXAMPLE
        $backupService = Get-Service -ServiceType "IBackupService"
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceType,
        
        [Parameter(Mandatory = $false)]
        [string]$Scope = 'Default'
    )
    
    if (-not $script:ServiceContainer.ContainsKey($ServiceType)) {
        throw "Service not registered: $ServiceType"
    }
    
    $descriptor = $script:ServiceContainer[$ServiceType]
    
    switch ($descriptor.Lifetime) {
        'Singleton' {
            return $descriptor.Instance
        }
        
        'Scoped' {
            if (-not $script:ServiceScopes.ContainsKey($Scope)) {
                $script:ServiceScopes[$Scope] = @{}
            }
            
            if (-not $script:ServiceScopes[$Scope].ContainsKey($ServiceType)) {
                if ($descriptor.Implementation -is [scriptblock]) {
                    $instance = & $descriptor.Implementation
                } else {
                    $instance = $descriptor.Implementation
                }
                $script:ServiceScopes[$Scope][$ServiceType] = $instance
            }
            
            return $script:ServiceScopes[$Scope][$ServiceType]
        }
        
        'Transient' {
            if ($descriptor.Implementation -is [scriptblock]) {
                return & $descriptor.Implementation
            } else {
                return $descriptor.Implementation
            }
        }
    }
}

function New-ServiceScope {
    <#
    .SYNOPSIS
        Creates a new service scope for scoped dependencies
    .DESCRIPTION
        Establishes a new scope for services with 'Scoped' lifetime, useful
        for operation-specific isolation.
    .PARAMETER ScopeName
        Unique identifier for the scope
    .EXAMPLE
        $scope = New-ServiceScope -ScopeName "BackupOperation_001"
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ScopeName = [Guid]::NewGuid().ToString()
    )
    
    if ($script:ServiceScopes.ContainsKey($ScopeName)) {
        throw "Service scope already exists: $ScopeName"
    }
    
    $script:ServiceScopes[$ScopeName] = @{}
    
    Write-AutomationLog -Message "Service scope created: $ScopeName" -Level Debug
    return $ScopeName
}

function Dispose-ServiceScope {
    <#
    .SYNOPSIS
        Disposes a service scope and its instances
    .DESCRIPTION
        Cleans up a service scope, disposing of any IDisposable instances
        and removing the scope from memory.
    .PARAMETER ScopeName
        Scope identifier to dispose
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScopeName
    )
    
    if (-not $script:ServiceScopes.ContainsKey($ScopeName)) {
        return
    }
    
    $scope = $script:ServiceScopes[$ScopeName]
    
    foreach ($service in $scope.Values) {
        if ($service -is [System.IDisposable]) {
            try {
                $service.Dispose()
            } catch {
                Write-AutomationLog -Message "Error disposing service in scope '$ScopeName': $_" -Level Warning
            }
        }
    }
    
    $script:ServiceScopes.Remove($ScopeName)
    Write-AutomationLog -Message "Service scope disposed: $ScopeName" -Level Debug
}

#endregion

#region Configuration Management

function Get-AutomationConfig {
    <#
    .SYNOPSIS
        Retrieves configuration values
    .DESCRIPTION
        Gets configuration settings with support for nested paths, environment
        overlays, and default values.
    .PARAMETER Path
        Configuration path (dot notation supported)
    .PARAMETER DefaultValue
        Default value if configuration not found
    .PARAMETER Environment
        Override environment (uses context environment by default)
    .EXAMPLE
        $smtpServer = Get-AutomationConfig -Path "Email.SmtpServer" -DefaultValue "localhost"
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $false)]
        [object]$DefaultValue = $null,
        
        [Parameter(Mandatory = $false)]
        [string]$Environment = $null
    )
    
    $context = Get-AutomationContext
    $env = if ($Environment) { $Environment } else { $context.Environment }
    
    # Check cache first
    $cacheKey = "${env}:${Path}"
    if ($script:ConfigurationCache.ContainsKey($cacheKey)) {
        return $script:ConfigurationCache[$cacheKey]
    }
    
    # Navigate configuration hierarchy
    $segments = $Path -split '\.'
    $current = $script:Configuration
    
    # Check environment-specific configuration first
    if ($script:Configuration.ContainsKey("Environments") -and 
        $script:Configuration.Environments.ContainsKey($env)) {
        $envConfig = $script:Configuration.Environments[$env]
        $value = Get-NestedValue -Object $envConfig -Path $segments
        if ($null -ne $value) {
            $script:ConfigurationCache[$cacheKey] = $value
            return $value
        }
    }
    
    # Fall back to default configuration
    $value = Get-NestedValue -Object $current -Path $segments
    if ($null -ne $value) {
        $script:ConfigurationCache[$cacheKey] = $value
        return $value
    }
    
    return $DefaultValue
}

function Set-AutomationConfig {
    <#
    .SYNOPSIS
        Updates configuration values at runtime
    .DESCRIPTION
        Modifies configuration settings with validation and change tracking.
        Changes are not persisted to disk unless explicitly saved.
    .PARAMETER Path
        Configuration path (dot notation)
    .PARAMETER Value
        New configuration value
    .PARAMETER Environment
        Target environment (current by default)
    .PARAMETER Persist
        Save changes to configuration file
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $true)]
        [object]$Value,
        
        [Parameter(Mandatory = $false)]
        [string]$Environment = $null,
        
        [Parameter(Mandatory = $false)]
        [switch]$Persist
    )
    
    $context = Get-AutomationContext
    $env = if ($Environment) { $Environment } else { $context.Environment }
    
    # Validate against schema if available
    $schema = Get-ConfigurationSchema -Section ($Path -split '\.')[0]
    if ($schema) {
        $validationResult = Test-ConfigurationValue -Path $Path -Value $Value -Schema $schema
        if (-not $validationResult.IsValid) {
            throw "Configuration validation failed: $($validationResult.Errors -join ', ')"
        }
    }
    
    # Update configuration
    $segments = $Path -split '\.'
    $target = $script:Configuration
    
    # Ensure environment structure exists
    if ($env -ne 'Default') {
        if (-not $target.ContainsKey('Environments')) {
            $target.Environments = @{}
        }
        if (-not $target.Environments.ContainsKey($env)) {
            $target.Environments[$env] = @{}
        }
        $target = $target.Environments[$env]
    }
    
    # Navigate to parent
    for ($i = 0; $i -lt $segments.Count - 1; $i++) {
        $segment = $segments[$i]
        if (-not $target.ContainsKey($segment)) {
            $target[$segment] = @{}
        }
        $target = $target[$segment]
    }
    
    # Set value
    $oldValue = $target[$segments[-1]]
    $target[$segments[-1]] = $Value
    
    # Clear cache
    $cacheKey = "${env}:${Path}"
    if ($script:ConfigurationCache.ContainsKey($cacheKey)) {
        $script:ConfigurationCache.Remove($cacheKey)
    }
    
    Write-AutomationLog -Message "Configuration updated: $Path = $Value (Environment: $env)" -Level Information
    
    # Persist if requested
    if ($Persist) {
        Save-Configuration
    }
}

function Test-ConfigurationSchema {
    <#
    .SYNOPSIS
        Validates configuration against JSON schema
    .DESCRIPTION
        Performs comprehensive validation of configuration structure and values
        against defined JSON schemas.
    .PARAMETER Configuration
        Configuration object to validate
    .PARAMETER SchemaPath
        Path to JSON schema file
    .EXAMPLE
        Test-ConfigurationSchema -Configuration $config -SchemaPath ".\schemas\backup-config.schema.json"
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Configuration,
        
        [Parameter(Mandatory = $true)]
        [string]$SchemaPath
    )
    
    try {
        if (-not (Test-Path $SchemaPath)) {
            throw "Schema file not found: $SchemaPath"
        }
        
        $schema = Get-Content $SchemaPath -Raw | ConvertFrom-Json
        
        # Perform validation (simplified for example)
        $result = [PSCustomObject]@{
            IsValid = $true
            Errors = @()
            Warnings = @()
        }
        
        # Validate required properties
        if ($schema.required) {
            foreach ($required in $schema.required) {
                if (-not $Configuration.ContainsKey($required)) {
                    $result.IsValid = $false
                    $result.Errors += "Missing required property: $required"
                }
            }
        }
        
        # Validate property types
        if ($schema.properties) {
            foreach ($property in $schema.properties.PSObject.Properties) {
                if ($Configuration.ContainsKey($property.Name)) {
                    $expectedType = $property.Value.type
                    $actualValue = $Configuration[$property.Name]
                    
                    if (-not (Test-ValueType -Value $actualValue -ExpectedType $expectedType)) {
                        $result.IsValid = $false
                        $result.Errors += "Property '$($property.Name)' has incorrect type. Expected: $expectedType"
                    }
                }
            }
        }
        
        return $result
        
    } catch {
        Write-Error "Configuration schema validation failed: $_"
        throw
    }
}

#endregion

#region Plugin Architecture

function Register-Plugin {
    <#
    .SYNOPSIS
        Registers a plugin with the automation platform
    .DESCRIPTION
        Adds a plugin to the registry after validating its interface and
        dependencies.
    .PARAMETER PluginPath
        Path to the plugin module or script
    .PARAMETER PluginType
        Type of plugin (Backup, Security, Monitoring, etc.)
    .PARAMETER AutoLoad
        Automatically load the plugin after registration
    .EXAMPLE
        Register-Plugin -PluginPath ".\Plugins\CloudBackup" -PluginType "Backup" -AutoLoad
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PluginPath,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('Backup', 'Security', 'Monitoring', 'Reporting', 'Custom')]
        [string]$PluginType,
        
        [Parameter(Mandatory = $false)]
        [switch]$AutoLoad
    )
    
    try {
        if (-not (Test-Path $PluginPath)) {
            throw "Plugin path not found: $PluginPath"
        }
        
        # Load plugin manifest
        $manifestPath = Join-Path $PluginPath "plugin.json"
        if (-not (Test-Path $manifestPath)) {
            throw "Plugin manifest not found: $manifestPath"
        }
        
        $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
        
        # Validate plugin interface
        $interfaceValid = Test-PluginInterface -PluginPath $PluginPath -PluginType $PluginType
        if (-not $interfaceValid) {
            throw "Plugin does not implement required interface for type: $PluginType"
        }
        
        # Check dependencies
        if ($manifest.Dependencies) {
            foreach ($dependency in $manifest.Dependencies) {
                if (-not (Get-Module $dependency -ListAvailable)) {
                    throw "Plugin dependency not available: $dependency"
                }
            }
        }
        
        # Register plugin
        $pluginDescriptor = [PSCustomObject]@{
            Name = $manifest.Name
            Version = $manifest.Version
            Type = $PluginType
            Path = $PluginPath
            Manifest = $manifest
            IsLoaded = $false
            LoadedAt = $null
            Instance = $null
        }
        
        $script:PluginRegistry[$manifest.Name] = $pluginDescriptor
        
        Write-AutomationLog -Message "Plugin registered: $($manifest.Name) v$($manifest.Version)" -Level Information
        
        # Auto-load if requested
        if ($AutoLoad) {
            Load-Plugin -PluginName $manifest.Name
        }
        
        return $pluginDescriptor
        
    } catch {
        Write-Error "Failed to register plugin: $_"
        throw
    }
}

function Get-Plugin {
    <#
    .SYNOPSIS
        Retrieves a registered plugin
    .DESCRIPTION
        Gets plugin information and optionally loads it if not already loaded.
    .PARAMETER PluginName
        Name of the plugin
    .PARAMETER LoadIfNotLoaded
        Automatically load the plugin if not loaded
    .EXAMPLE
        $backupPlugin = Get-Plugin -PluginName "CloudBackup" -LoadIfNotLoaded
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PluginName,
        
        [Parameter(Mandatory = $false)]
        [switch]$LoadIfNotLoaded
    )
    
    if (-not $script:PluginRegistry.ContainsKey($PluginName)) {
        throw "Plugin not registered: $PluginName"
    }
    
    $plugin = $script:PluginRegistry[$PluginName]
    
    if ($LoadIfNotLoaded -and -not $plugin.IsLoaded) {
        Load-Plugin -PluginName $PluginName
    }
    
    return $plugin
}

function Invoke-Plugin {
    <#
    .SYNOPSIS
        Invokes a plugin method
    .DESCRIPTION
        Executes a plugin method with provided parameters and handles errors.
    .PARAMETER PluginName
        Name of the plugin
    .PARAMETER MethodName
        Method to invoke
    .PARAMETER Parameters
        Parameters to pass to the method
    .EXAMPLE
        $result = Invoke-Plugin -PluginName "CloudBackup" -MethodName "BackupToCloud" -Parameters @{Path="C:\Data"}
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PluginName,
        
        [Parameter(Mandatory = $true)]
        [string]$MethodName,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Parameters = @{}
    )
    
    try {
        $plugin = Get-Plugin -PluginName $PluginName -LoadIfNotLoaded
        
        if (-not $plugin.IsLoaded) {
            throw "Plugin not loaded: $PluginName"
        }
        
        # Get method from plugin
        $method = $plugin.Instance.PSObject.Methods[$MethodName]
        if (-not $method) {
            throw "Method not found in plugin: $MethodName"
        }
        
        # Start performance trace if enabled
        $traceId = $null
        if ((Get-AutomationContext).PerformanceTracking) {
            $traceId = Start-PerformanceTrace -OperationName "Plugin.$PluginName.$MethodName"
        }
        
        try {
            # Invoke method
            $result = $method.Invoke($Parameters)
            
            Write-AutomationLog -Message "Plugin method invoked: $PluginName.$MethodName" -Level Debug
            return $result
            
        } finally {
            if ($traceId) {
                Stop-PerformanceTrace -TraceId $traceId
            }
        }
        
    } catch {
        Write-Error "Failed to invoke plugin method '$PluginName.$MethodName': $_"
        throw
    }
}

function Test-PluginInterface {
    <#
    .SYNOPSIS
        Validates plugin interface implementation
    .DESCRIPTION
        Checks if a plugin implements the required interface for its type.
    .PARAMETER PluginPath
        Path to plugin
    .PARAMETER PluginType
        Expected plugin type
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PluginPath,
        
        [Parameter(Mandatory = $true)]
        [string]$PluginType
    )
    
    # Define required interfaces per plugin type
    $requiredInterfaces = @{
        'Backup' = @('Initialize', 'ExecuteBackup', 'ValidateBackup', 'GetStatus')
        'Security' = @('Initialize', 'PerformSecurityCheck', 'GetVulnerabilities', 'Remediate')
        'Monitoring' = @('Initialize', 'StartMonitoring', 'StopMonitoring', 'GetMetrics')
        'Reporting' = @('Initialize', 'GenerateReport', 'ExportReport', 'GetReportTypes')
        'Custom' = @('Initialize')
    }
    
    $requiredMethods = $requiredInterfaces[$PluginType]
    if (-not $requiredMethods) {
        return $false
    }
    
    # Load plugin module temporarily
    $modulePath = Join-Path $PluginPath "$((Get-Item $PluginPath).Name).psm1"
    if (-not (Test-Path $modulePath)) {
        return $false
    }
    
    try {
        $module = Import-Module $modulePath -PassThru -Force
        $exportedFunctions = $module.ExportedFunctions.Keys
        
        foreach ($method in $requiredMethods) {
            if ($method -notin $exportedFunctions) {
                return $false
            }
        }
        
        return $true
        
    } finally {
        if ($module) {
            Remove-Module $module.Name -Force -ErrorAction SilentlyContinue
        }
    }
}

#endregion

#region Security Framework

function Get-SecureCredential {
    <#
    .SYNOPSIS
        Retrieves secure credentials from the credential store
    .DESCRIPTION
        Gets credentials from the secure store with automatic decryption and
        validation.
    .PARAMETER CredentialName
        Name/identifier of the credential
    .PARAMETER Purpose
        Purpose description for audit logging
    .EXAMPLE
        $cred = Get-SecureCredential -CredentialName "BackupServiceAccount" -Purpose "Cloud backup authentication"
    #>
    [CmdletBinding()]
    [OutputType([PSCredential])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CredentialName,
        
        [Parameter(Mandatory = $true)]
        [string]$Purpose
    )
    
    try {
        $context = Get-AutomationContext
        $storePath = Join-Path $context.SecureStorePath "$CredentialName.cred"
        
        if (-not (Test-Path $storePath)) {
            throw "Credential not found: $CredentialName"
        }
        
        # Load encrypted credential
        $encryptedCred = Import-Clixml $storePath
        
        # Decrypt based on current security context
        $currentContext = Get-CurrentSecurityContext
        if ($currentContext.RequiresMFA -and -not $currentContext.MFAVerified) {
            throw "MFA verification required for credential access"
        }
        
        # Log access for audit
        Write-AutomationLog -Message "Credential accessed: $CredentialName for $Purpose by $($env:USERNAME)" -Level Security
        
        return $encryptedCred
        
    } catch {
        Write-Error "Failed to retrieve secure credential '$CredentialName': $_"
        throw
    }
}

function Set-SecureCredential {
    <#
    .SYNOPSIS
        Stores credentials securely
    .DESCRIPTION
        Saves credentials to the secure store with encryption and access control.
    .PARAMETER CredentialName
        Name/identifier for the credential
    .PARAMETER Credential
        PSCredential object to store
    .PARAMETER AllowedUsers
        Users allowed to access this credential
    .PARAMETER ExpirationDays
        Days until credential expires
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CredentialName,
        
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [string[]]$AllowedUsers = @($env:USERNAME),
        
        [Parameter(Mandatory = $false)]
        [int]$ExpirationDays = 365
    )
    
    try {
        $context = Get-AutomationContext
        $storePath = Join-Path $context.SecureStorePath "$CredentialName.cred"
        
        # Ensure secure store directory exists
        if (-not (Test-Path $context.SecureStorePath)) {
            New-Item -ItemType Directory -Path $context.SecureStorePath -Force | Out-Null
        }
        
        # Create credential metadata
        $metadata = @{
            Name = $CredentialName
            CreatedBy = $env:USERNAME
            CreatedAt = Get-Date
            ExpiresAt = (Get-Date).AddDays($ExpirationDays)
            AllowedUsers = $AllowedUsers
        }
        
        # Export encrypted credential
        $Credential | Export-Clixml $storePath
        
        # Set NTFS permissions
        $acl = Get-Acl $storePath
        $acl.SetAccessRuleProtection($true, $false)
        
        foreach ($user in $AllowedUsers) {
            $permission = "$user", "Read", "Allow"
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
            $acl.SetAccessRule($accessRule)
        }
        
        Set-Acl $storePath $acl
        
        # Save metadata
        $metadataPath = Join-Path $context.SecureStorePath "$CredentialName.meta"
        $metadata | Export-Clixml $metadataPath
        
        Write-AutomationLog -Message "Credential stored: $CredentialName (Expires: $($metadata.ExpiresAt))" -Level Security
        
    } catch {
        Write-Error "Failed to store secure credential '$CredentialName': $_"
        throw
    }
}

function Test-SecurityContext {
    <#
    .SYNOPSIS
        Validates current security context
    .DESCRIPTION
        Checks if the current security context meets requirements for an operation.
    .PARAMETER RequiredLevel
        Minimum security level required
    .PARAMETER RequiresMFA
        Whether MFA is required
    .EXAMPLE
        if (Test-SecurityContext -RequiredLevel "High" -RequiresMFA) { # Proceed }
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Low', 'Medium', 'High', 'Critical')]
        [string]$RequiredLevel,
        
        [Parameter(Mandatory = $false)]
        [switch]$RequiresMFA
    )
    
    $currentContext = Get-CurrentSecurityContext
    
    # Check security level
    $levelHierarchy = @{
        'Low' = 1
        'Medium' = 2
        'High' = 3
        'Critical' = 4
    }
    
    if ($levelHierarchy[$currentContext.Level] -lt $levelHierarchy[$RequiredLevel]) {
        Write-AutomationLog -Message "Security context insufficient. Required: $RequiredLevel, Current: $($currentContext.Level)" -Level Warning
        return $false
    }
    
    # Check MFA requirement
    if ($RequiresMFA -and -not $currentContext.MFAVerified) {
        Write-AutomationLog -Message "MFA verification required but not present" -Level Warning
        return $false
    }
    
    return $true
}

function New-SecurityContext {
    <#
    .SYNOPSIS
        Creates a new security context
    .DESCRIPTION
        Establishes a security context for operations requiring elevated privileges
        or specific security constraints.
    .PARAMETER Level
        Security level for the context
    .PARAMETER MFARequired
        Require MFA verification
    .PARAMETER TimeoutMinutes
        Context timeout in minutes
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Low', 'Medium', 'High', 'Critical')]
        [string]$Level,
        
        [Parameter(Mandatory = $false)]
        [switch]$MFARequired,
        
        [Parameter(Mandatory = $false)]
        [int]$TimeoutMinutes = 30
    )
    
    $contextId = [Guid]::NewGuid().ToString()
    
    $securityContext = [PSCustomObject]@{
        Id = $contextId
        Level = $Level
        CreatedAt = Get-Date
        ExpiresAt = (Get-Date).AddMinutes($TimeoutMinutes)
        User = $env:USERNAME
        RequiresMFA = $MFARequired
        MFAVerified = $false
        IsActive = $true
    }
    
    # Perform MFA if required
    if ($MFARequired) {
        $mfaResult = Invoke-MFAChallenge
        $securityContext.MFAVerified = $mfaResult
        
        if (-not $mfaResult) {
            Write-Error "MFA verification failed"
            return $null
        }
    }
    
    $script:SecurityContexts[$contextId] = $securityContext
    
    Write-AutomationLog -Message "Security context created: $contextId (Level: $Level, MFA: $MFARequired)" -Level Security
    return $securityContext
}

function Invoke-WithSecurityContext {
    <#
    .SYNOPSIS
        Executes a scriptblock within a security context
    .DESCRIPTION
        Runs code with specific security constraints and automatic cleanup.
    .PARAMETER ScriptBlock
        Code to execute
    .PARAMETER SecurityContext
        Security context to use
    .EXAMPLE
        Invoke-WithSecurityContext -ScriptBlock { Remove-SensitiveData } -SecurityContext $highSecContext
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$SecurityContext
    )
    
    if (-not $SecurityContext.IsActive) {
        throw "Security context is not active"
    }
    
    if ($SecurityContext.ExpiresAt -lt (Get-Date)) {
        throw "Security context has expired"
    }
    
    $previousContext = $script:CurrentSecurityContext
    $script:CurrentSecurityContext = $SecurityContext
    
    try {
        Write-AutomationLog -Message "Executing with security context: $($SecurityContext.Id)" -Level Security
        
        $result = & $ScriptBlock
        
        Write-AutomationLog -Message "Security context execution completed: $($SecurityContext.Id)" -Level Security
        return $result
        
    } catch {
        Write-AutomationLog -Message "Security context execution failed: $($SecurityContext.Id) - $_" -Level Error
        throw
    } finally {
        $script:CurrentSecurityContext = $previousContext
    }
}

#endregion

#region Performance Monitoring

function Start-PerformanceTrace {
    <#
    .SYNOPSIS
        Starts a performance trace
    .DESCRIPTION
        Begins tracking performance metrics for an operation.
    .PARAMETER OperationName
        Name of the operation being traced
    .PARAMETER Tags
        Additional tags for categorization
    .EXAMPLE
        $traceId = Start-PerformanceTrace -OperationName "BackupOperation" -Tags @("Critical", "Daily")
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OperationName,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Tags = @()
    )
    
    $traceId = [Guid]::NewGuid().ToString()
    
    $trace = [PSCustomObject]@{
        Id = $traceId
        OperationName = $OperationName
        StartTime = Get-Date
        EndTime = $null
        Duration = $null
        Tags = $Tags
        Metrics = @{}
        Status = 'Running'
        ParentTraceId = $null
    }
    
    $script:PerformanceTraces[$traceId] = $trace
    
    Write-Verbose "Performance trace started: $OperationName ($traceId)"
    return $traceId
}

function Stop-PerformanceTrace {
    <#
    .SYNOPSIS
        Stops a performance trace
    .DESCRIPTION
        Completes a performance trace and calculates final metrics.
    .PARAMETER TraceId
        Trace identifier
    .PARAMETER Status
        Final status of the operation
    .EXAMPLE
        Stop-PerformanceTrace -TraceId $traceId -Status "Success"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TraceId,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Success', 'Failed', 'Warning')]
        [string]$Status = 'Success'
    )
    
    if (-not $script:PerformanceTraces.ContainsKey($TraceId)) {
        Write-Warning "Performance trace not found: $TraceId"
        return
    }
    
    $trace = $script:PerformanceTraces[$TraceId]
    $trace.EndTime = Get-Date
    $trace.Duration = $trace.EndTime - $trace.StartTime
    $trace.Status = $Status
    
    # Log performance data
    Write-AutomationLog -Message "Performance: $($trace.OperationName) completed in $($trace.Duration.TotalMilliseconds)ms (Status: $Status)" -Level Performance
    
    # Store for analysis
    Export-PerformanceData -Trace $trace
}

function Get-PerformanceMetrics {
    <#
    .SYNOPSIS
        Retrieves performance metrics
    .DESCRIPTION
        Gets performance data for analysis and reporting.
    .PARAMETER OperationName
        Filter by operation name
    .PARAMETER StartDate
        Start date for metrics
    .PARAMETER EndDate
        End date for metrics
    .EXAMPLE
        $metrics = Get-PerformanceMetrics -OperationName "BackupOperation" -StartDate (Get-Date).AddDays(-7)
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$OperationName,
        
        [Parameter(Mandatory = $false)]
        [datetime]$StartDate = (Get-Date).AddDays(-1),
        
        [Parameter(Mandatory = $false)]
        [datetime]$EndDate = Get-Date
    )
    
    $traces = $script:PerformanceTraces.Values | Where-Object {
        $_.StartTime -ge $StartDate -and $_.StartTime -le $EndDate
    }
    
    if ($OperationName) {
        $traces = $traces | Where-Object { $_.OperationName -eq $OperationName }
    }
    
    # Calculate aggregate metrics
    $metrics = [PSCustomObject]@{
        OperationName = $OperationName
        TotalOperations = $traces.Count
        SuccessfulOperations = ($traces | Where-Object { $_.Status -eq 'Success' }).Count
        FailedOperations = ($traces | Where-Object { $_.Status -eq 'Failed' }).Count
        AverageDuration = if ($traces.Count -gt 0) {
            ($traces | Measure-Object -Property { $_.Duration.TotalMilliseconds } -Average).Average
        } else { 0 }
        MinDuration = if ($traces.Count -gt 0) {
            ($traces | Measure-Object -Property { $_.Duration.TotalMilliseconds } -Minimum).Minimum
        } else { 0 }
        MaxDuration = if ($traces.Count -gt 0) {
            ($traces | Measure-Object -Property { $_.Duration.TotalMilliseconds } -Maximum).Maximum
        } else { 0 }
        Traces = $traces
    }
    
    return $metrics
}

function Register-PerformanceCounter {
    <#
    .SYNOPSIS
        Registers a custom performance counter
    .DESCRIPTION
        Creates a performance counter for tracking specific metrics.
    .PARAMETER CounterName
        Name of the counter
    .PARAMETER Category
        Counter category
    .PARAMETER Description
        Counter description
    .PARAMETER Type
        Counter type (Increment, Average, etc.)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CounterName,
        
        [Parameter(Mandatory = $true)]
        [string]$Category,
        
        [Parameter(Mandatory = $false)]
        [string]$Description = "",
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Increment', 'Average', 'Total', 'Rate')]
        [string]$Type = 'Increment'
    )
    
    # Implementation would register Windows Performance Counters
    # For now, we'll track in memory
    if (-not $script:PerformanceCounters) {
        $script:PerformanceCounters = @{}
    }
    
    $counter = [PSCustomObject]@{
        Name = $CounterName
        Category = $Category
        Description = $Description
        Type = $Type
        Value = 0
        LastUpdated = Get-Date
    }
    
    $script:PerformanceCounters["$Category.$CounterName"] = $counter
    
    Write-Verbose "Performance counter registered: $Category.$CounterName"
}

#endregion

#region Logging and Monitoring

function Write-AutomationLog {
    <#
    .SYNOPSIS
        Writes structured log entries
    .DESCRIPTION
        Logs messages with multiple targets, structured data, and automatic
        context enrichment.
    .PARAMETER Message
        Log message
    .PARAMETER Level
        Log level
    .PARAMETER Data
        Additional structured data
    .PARAMETER Tags
        Tags for categorization
    .EXAMPLE
        Write-AutomationLog -Message "Backup completed" -Level Information -Data @{Files=100; SizeMB=500}
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Debug', 'Verbose', 'Information', 'Warning', 'Error', 'Critical', 'Security', 'Performance')]
        [string]$Level = 'Information',
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Data = @{},
        
        [Parameter(Mandatory = $false)]
        [string[]]$Tags = @()
    )
    
    $logEntry = [PSCustomObject]@{
        Timestamp = Get-Date
        Level = $Level
        Message = $Message
        Data = $Data
        Tags = $Tags
        Context = @{
            User = $env:USERNAME
            Computer = $env:COMPUTERNAME
            ProcessId = $PID
            Module = $MyInvocation.MyCommand.Module.Name
            Function = (Get-PSCallStack)[1].FunctionName
        }
    }
    
    # Apply to all registered log targets
    foreach ($target in $script:LogTargets) {
        try {
            & $target.Handler $logEntry
        } catch {
            Write-Warning "Log target failed: $($target.Name) - $_"
        }
    }
}

function Get-AutomationLog {
    <#
    .SYNOPSIS
        Retrieves log entries
    .DESCRIPTION
        Queries log entries with filtering support.
    .PARAMETER StartDate
        Start date for log query
    .PARAMETER EndDate
        End date for log query
    .PARAMETER Level
        Filter by log level
    .PARAMETER Tags
        Filter by tags
    .PARAMETER MaxEntries
        Maximum entries to return
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory = $false)]
        [datetime]$StartDate = (Get-Date).AddHours(-1),
        
        [Parameter(Mandatory = $false)]
        [datetime]$EndDate = Get-Date,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Level,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Tags,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxEntries = 1000
    )
    
    # Implementation would query from configured log stores
    # For now, return from in-memory cache
    $logs = $script:LogCache | Where-Object {
        $_.Timestamp -ge $StartDate -and $_.Timestamp -le $EndDate
    }
    
    if ($Level) {
        $logs = $logs | Where-Object { $_.Level -in $Level }
    }
    
    if ($Tags) {
        $logs = $logs | Where-Object {
            $logTags = $_.Tags
            $found = $false
            foreach ($tag in $Tags) {
                if ($tag -in $logTags) {
                    $found = $true
                    break
                }
            }
            $found
        }
    }
    
    return $logs | Select-Object -First $MaxEntries
}

function Register-LogTarget {
    <#
    .SYNOPSIS
        Registers a log target
    .DESCRIPTION
        Adds a new destination for log entries (file, event log, database, etc.).
    .PARAMETER Name
        Target name
    .PARAMETER Type
        Target type
    .PARAMETER Handler
        Scriptblock to handle log entries
    .PARAMETER Configuration
        Target-specific configuration
    .EXAMPLE
        Register-LogTarget -Name "FileLog" -Type "File" -Handler { param($entry) Add-Content "app.log" $entry }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('File', 'EventLog', 'Database', 'Custom')]
        [string]$Type,
        
        [Parameter(Mandatory = $true)]
        [scriptblock]$Handler,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Configuration = @{}
    )
    
    $target = [PSCustomObject]@{
        Name = $Name
        Type = $Type
        Handler = $Handler
        Configuration = $Configuration
        IsActive = $true
    }
    
    $script:LogTargets += $target
    
    Write-Verbose "Log target registered: $Name ($Type)"
}

function Set-LogLevel {
    <#
    .SYNOPSIS
        Sets the minimum log level
    .DESCRIPTION
        Configures the minimum severity level for log entries to be processed.
    .PARAMETER Level
        Minimum log level
    .PARAMETER TargetName
        Specific target to configure (all targets if not specified)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Debug', 'Verbose', 'Information', 'Warning', 'Error', 'Critical')]
        [string]$Level,
        
        [Parameter(Mandatory = $false)]
        [string]$TargetName
    )
    
    if ($TargetName) {
        $target = $script:LogTargets | Where-Object { $_.Name -eq $TargetName }
        if ($target) {
            $target.Configuration.MinLevel = $Level
        }
    } else {
        $script:MinLogLevel = $Level
    }
    
    Write-AutomationLog -Message "Log level set to: $Level" -Level Information
}

#endregion

#region Private Helper Functions

function Initialize-CoreServices {
    <#
    .SYNOPSIS
        Initializes core platform services
    #>
    [CmdletBinding()]
    param()
    
    # Register default log targets
    Register-LogTarget -Name "ConsoleLog" -Type "Custom" -Handler {
        param($entry)
        $color = switch ($entry.Level) {
            'Debug' { 'DarkGray' }
            'Verbose' { 'Gray' }
            'Information' { 'Cyan' }
            'Warning' { 'Yellow' }
            'Error' { 'Red' }
            'Critical' { 'Magenta' }
            'Security' { 'DarkYellow' }
            'Performance' { 'Green' }
            default { 'White' }
        }
        
        Write-Host "[$($entry.Timestamp.ToString('HH:mm:ss'))] [$($entry.Level)] $($entry.Message)" -ForegroundColor $color
    }
    
    # Register file log target
    $logPath = Join-Path $env:ProgramData "PSAutomation\Logs\automation.log"
    Register-LogTarget -Name "FileLog" -Type "File" -Handler {
        param($entry)
        $logLine = "$($entry.Timestamp.ToString('yyyy-MM-dd HH:mm:ss')) [$($entry.Level)] $($entry.Message)"
        if ($entry.Data.Count -gt 0) {
            $logLine += " | Data: $($entry.Data | ConvertTo-Json -Compress)"
        }
        Add-Content -Path $logPath -Value $logLine -ErrorAction SilentlyContinue
    }
    
    # Initialize log cache
    $script:LogCache = @()
}

function Load-PlatformConfiguration {
    <#
    .SYNOPSIS
        Loads platform configuration
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $true)]
        [string]$Environment
    )
    
    $script:Configuration = @{}
    
    # Load base configuration
    $basePath = Join-Path $Path "automation-config.json"
    if (Test-Path $basePath) {
        $script:Configuration = Get-Content $basePath -Raw | ConvertFrom-Json -AsHashtable
    }
    
    # Load environment-specific configuration
    $envPath = Join-Path $Path "automation-config.$Environment.json"
    if (Test-Path $envPath) {
        $envConfig = Get-Content $envPath -Raw | ConvertFrom-Json -AsHashtable
        $script:Configuration = Merge-Configuration -Base $script:Configuration -Override $envConfig
    }
    
    # Validate configuration
    $schemaPath = Join-Path $Path "schemas\automation-config.schema.json"
    if (Test-Path $schemaPath) {
        $validation = Test-ConfigurationSchema -Configuration $script:Configuration -SchemaPath $schemaPath
        if (-not $validation.IsValid) {
            throw "Configuration validation failed: $($validation.Errors -join ', ')"
        }
    }
}

function Initialize-SecurityFramework {
    <#
    .SYNOPSIS
        Initializes security components
    #>
    [CmdletBinding()]
    param()
    
    # Create secure store directory if needed
    $securePath = Join-Path $env:ProgramData "PSAutomation\SecureStore"
    if (-not (Test-Path $securePath)) {
        New-Item -ItemType Directory -Path $securePath -Force | Out-Null
        
        # Set restrictive permissions
        $acl = Get-Acl $securePath
        $acl.SetAccessRuleProtection($true, $false)
        
        # Add administrators group
        $admins = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
        $permission = $admins, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
        $acl.SetAccessRule($accessRule)
        
        Set-Acl $securePath $acl
    }
    
    # Initialize default security context
    $script:CurrentSecurityContext = [PSCustomObject]@{
        Level = 'Medium'
        User = $env:USERNAME
        MFAVerified = $false
    }
}

function Discover-Plugins {
    <#
    .SYNOPSIS
        Discovers available plugins
    #>
    [CmdletBinding()]
    param()
    
    $pluginPath = Join-Path $PSScriptRoot "..\Plugins"
    if (-not (Test-Path $pluginPath)) {
        return
    }
    
    $pluginFolders = Get-ChildItem $pluginPath -Directory
    
    foreach ($folder in $pluginFolders) {
        $manifestPath = Join-Path $folder.FullName "plugin.json"
        if (Test-Path $manifestPath) {
            try {
                $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
                if ($manifest.AutoRegister) {
                    Register-Plugin -PluginPath $folder.FullName -PluginType $manifest.Type
                }
            } catch {
                Write-AutomationLog -Message "Failed to auto-register plugin: $($folder.Name) - $_" -Level Warning
            }
        }
    }
}

function Initialize-PerformanceMonitoring {
    <#
    .SYNOPSIS
        Initializes performance monitoring
    #>
    [CmdletBinding()]
    param()
    
    # Register core performance counters
    Register-PerformanceCounter -CounterName "OperationsTotal" -Category "Automation" -Type "Total"
    Register-PerformanceCounter -CounterName "OperationsPerSecond" -Category "Automation" -Type "Rate"
    Register-PerformanceCounter -CounterName "AverageOperationTime" -Category "Automation" -Type "Average"
    Register-PerformanceCounter -CounterName "ErrorsTotal" -Category "Automation" -Type "Total"
}

function Get-NestedValue {
    <#
    .SYNOPSIS
        Gets nested value from object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object,
        
        [Parameter(Mandatory = $true)]
        [string[]]$Path
    )
    
    $current = $Object
    foreach ($segment in $Path) {
        if ($null -eq $current) {
            return $null
        }
        
        if ($current -is [hashtable] -and $current.ContainsKey($segment)) {
            $current = $current[$segment]
        } elseif ($current.PSObject.Properties.Name -contains $segment) {
            $current = $current.$segment
        } else {
            return $null
        }
    }
    
    return $current
}

function Test-ValueType {
    <#
    .SYNOPSIS
        Tests if value matches expected type
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Value,
        
        [Parameter(Mandatory = $true)]
        [string]$ExpectedType
    )
    
    switch ($ExpectedType) {
        'string' { return $Value -is [string] }
        'number' { return $Value -is [int] -or $Value -is [long] -or $Value -is [double] }
        'boolean' { return $Value -is [bool] }
        'array' { return $Value -is [array] }
        'object' { return $Value -is [hashtable] -or $Value -is [PSCustomObject] }
        default { return $true }
    }
}

function Get-CurrentSecurityContext {
    <#
    .SYNOPSIS
        Gets the current active security context
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()
    
    if ($null -eq $script:CurrentSecurityContext) {
        return [PSCustomObject]@{
            Level = 'Low'
            User = $env:USERNAME
            MFAVerified = $false
            RequiresMFA = $false
        }
    }
    
    return $script:CurrentSecurityContext
}

function Invoke-MFAChallenge {
    <#
    .SYNOPSIS
        Performs MFA challenge (placeholder)
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    # In a real implementation, this would integrate with MFA provider
    # For now, simulate with user prompt
    $challenge = Read-Host "Enter MFA code"
    return $challenge -eq "123456"  # Demo only
}

function Load-Plugin {
    <#
    .SYNOPSIS
        Loads a plugin into memory
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PluginName
    )
    
    $plugin = $script:PluginRegistry[$PluginName]
    if ($plugin.IsLoaded) {
        return
    }
    
    $modulePath = Join-Path $plugin.Path "$PluginName.psm1"
    $module = Import-Module $modulePath -PassThru -Force
    
    $plugin.Instance = $module
    $plugin.IsLoaded = $true
    $plugin.LoadedAt = Get-Date
    
    # Initialize plugin
    if ($module.ExportedFunctions.ContainsKey('Initialize')) {
        & $module Initialize
    }
}

function Export-PerformanceData {
    <#
    .SYNOPSIS
        Exports performance trace data
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Trace
    )
    
    # In production, this would write to performance database
    # For now, keep in memory
    if ($script:PerformanceHistory.Count -gt 10000) {
        # Remove oldest entries
        $script:PerformanceHistory = $script:PerformanceHistory | 
            Sort-Object StartTime -Descending | 
            Select-Object -First 5000
    }
    
    $script:PerformanceHistory += $Trace
}

function Save-Configuration {
    <#
    .SYNOPSIS
        Saves configuration to disk
    #>
    [CmdletBinding()]
    param()
    
    $context = Get-AutomationContext
    $configPath = Join-Path $context.ConfigurationPath "automation-config.json"
    
    $script:Configuration | ConvertTo-Json -Depth 10 | Set-Content $configPath
    
    Write-AutomationLog -Message "Configuration saved to: $configPath" -Level Information
}

function Merge-Configuration {
    <#
    .SYNOPSIS
        Merges configuration objects
    .DESCRIPTION
        Performs deep merge of configuration hashtables with override semantics.
    .PARAMETER Base
        Base configuration
    .PARAMETER Override
        Override configuration
    .EXAMPLE
        $merged = Merge-Configuration -Base $defaultConfig -Override $envConfig
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Base,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Override
    )
    
    $result = $Base.Clone()
    
    foreach ($key in $Override.Keys) {
        if ($Override[$key] -is [hashtable] -and $Base.ContainsKey($key) -and $Base[$key] -is [hashtable]) {
            $result[$key] = Merge-Configuration -Base $Base[$key] -Override $Override[$key]
        } else {
            $result[$key] = $Override[$key]
        }
    }
    
    return $result
}

#endregion

# Module initialization
$script:PerformanceHistory = @()
$script:MinLogLevel = 'Information'

# Export module members
Export-ModuleMember -Function @(
    # Core Architecture
    'Initialize-AutomationPlatform',
    'Get-AutomationContext',
    'Set-AutomationContext',
    'Register-AutomationModule',
    'Unregister-AutomationModule',
    
    # Dependency Injection
    'Register-Service',
    'Get-Service',
    'New-ServiceScope',
    'Dispose-ServiceScope',
    
    # Configuration Management
    'Get-AutomationConfig',
    'Set-AutomationConfig',
    'Test-ConfigurationSchema',
    'Get-ConfigurationSchema',
    'Merge-Configuration',
    
    # Plugin Management
    'Register-Plugin',
    'Get-Plugin',
    'Invoke-Plugin',
    'Test-PluginInterface',
    'Get-PluginMetadata',
    
    # Logging and Monitoring
    'Write-AutomationLog',
    'Get-AutomationLog',
    'Register-LogTarget',
    'Set-LogLevel',
    
    # Security
    'Get-SecureCredential',
    'Set-SecureCredential',
    'Test-SecurityContext',
    'New-SecurityContext',
    'Invoke-WithSecurityContext',
    
    # Performance
    'Start-PerformanceTrace',
    'Stop-PerformanceTrace',
    'Get-PerformanceMetrics',
    'Register-PerformanceCounter'
)