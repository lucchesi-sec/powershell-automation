#Requires -Version 5.1
#Requires -Modules PSAutomationCore

<#
.SYNOPSIS
    PSConfigurationManager - Enterprise configuration management with schema validation
.DESCRIPTION
    Provides centralized configuration management with JSON schema validation,
    environment-specific overlays, secure credential handling, and compliance checking.
.NOTES
    Author: Enterprise Automation Team
    Version: 2.0.0
#>

using module PSAutomationCore

# Module-level variables
$script:ConfigurationCache = @{}
$script:SchemaCache = @{}
$script:CurrentEnvironment = 'Production'
$script:ConfigurationProfiles = @{}

#region Configuration Loading

function Get-Configuration {
    <#
    .SYNOPSIS
        Retrieves configuration with environment overlay and validation
    .DESCRIPTION
        Gets configuration values with support for nested paths, environment-specific
        overlays, schema validation, and default values.
    .PARAMETER Section
        Configuration section name
    .PARAMETER Path
        Nested path within section (dot notation)
    .PARAMETER Environment
        Target environment (uses current if not specified)
    .PARAMETER ValidateSchema
        Perform schema validation
    .EXAMPLE
        $backupConfig = Get-Configuration -Section "Backup" -Environment "Production"
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Section,
        
        [Parameter(Mandatory = $false)]
        [string]$Path,
        
        [Parameter(Mandatory = $false)]
        [string]$Environment = $script:CurrentEnvironment,
        
        [Parameter(Mandatory = $false)]
        [switch]$ValidateSchema = $true
    )
    
    try {
        Write-AutomationLog -Message "Retrieving configuration: Section='$Section', Path='$Path', Environment='$Environment'" -Level Debug
        
        # Check cache
        $cacheKey = "$Environment|$Section|$Path"
        if ($script:ConfigurationCache.ContainsKey($cacheKey)) {
            Write-AutomationLog -Message "Configuration retrieved from cache" -Level Debug
            return $script:ConfigurationCache[$cacheKey]
        }
        
        # Load configuration
        $config = Load-ConfigurationSection -Section $Section -Environment $Environment
        
        # Validate against schema if enabled
        if ($ValidateSchema) {
            $validation = Validate-Configuration -Configuration $config -Section $Section
            if (-not $validation.IsValid) {
                Write-AutomationLog -Message "Configuration validation failed: $($validation.Errors -join ', ')" -Level Warning
            }
        }
        
        # Extract specific path if requested
        if ($Path) {
            $config = Get-ConfigurationValue -Configuration $config -Path $Path
        }
        
        # Cache result
        $script:ConfigurationCache[$cacheKey] = $config
        
        return $config
        
    } catch {
        Write-Error "Failed to retrieve configuration: $_"
        throw
    }
}

function Set-Configuration {
    <#
    .SYNOPSIS
        Updates configuration with validation
    .DESCRIPTION
        Sets configuration values with schema validation, change tracking,
        and optional persistence.
    .PARAMETER Section
        Configuration section
    .PARAMETER Path
        Nested path within section
    .PARAMETER Value
        New value
    .PARAMETER Environment
        Target environment
    .PARAMETER Persist
        Save changes to disk
    .PARAMETER Force
        Skip validation
    .EXAMPLE
        Set-Configuration -Section "Backup" -Path "RetentionDays" -Value 90 -Persist
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Section,
        
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $true)]
        [object]$Value,
        
        [Parameter(Mandatory = $false)]
        [string]$Environment = $script:CurrentEnvironment,
        
        [Parameter(Mandatory = $false)]
        [switch]$Persist,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    try {
        if ($PSCmdlet.ShouldProcess("$Section.$Path", "Update configuration value")) {
            
            # Load current configuration
            $config = Load-ConfigurationSection -Section $Section -Environment $Environment
            
            # Create backup before modification
            if ($Persist) {
                Backup-Configuration -Section $Section -Environment $Environment
            }
            
            # Validate new value against schema
            if (-not $Force) {
                $tempConfig = $config.Clone()
                Set-ConfigurationValue -Configuration $tempConfig -Path $Path -Value $Value
                
                $validation = Validate-Configuration -Configuration $tempConfig -Section $Section
                if (-not $validation.IsValid) {
                    throw "Configuration validation failed: $($validation.Errors -join ', ')"
                }
            }
            
            # Apply change
            $oldValue = Get-ConfigurationValue -Configuration $config -Path $Path
            Set-ConfigurationValue -Configuration $config -Path $Path -Value $Value
            
            # Clear cache
            $script:ConfigurationCache.Keys | Where-Object { $_ -like "$Environment|$Section|*" } | ForEach-Object {
                $script:ConfigurationCache.Remove($_)
            }
            
            # Log change
            Write-AutomationLog -Message "Configuration updated: $Section.$Path changed from '$oldValue' to '$Value' (Environment: $Environment)" -Level Information -Data @{
                Section = $Section
                Path = $Path
                OldValue = $oldValue
                NewValue = $Value
                Environment = $Environment
                User = $env:USERNAME
            }
            
            # Persist if requested
            if ($Persist) {
                Save-ConfigurationSection -Section $Section -Configuration $config -Environment $Environment
            }
            
            return $true
        }
        
    } catch {
        Write-Error "Failed to set configuration: $_"
        throw
    }
}

function Import-Configuration {
    <#
    .SYNOPSIS
        Imports configuration from file or object
    .DESCRIPTION
        Loads configuration with validation and optional environment targeting.
    .PARAMETER Path
        Path to configuration file
    .PARAMETER Configuration
        Configuration object
    .PARAMETER Section
        Target section
    .PARAMETER Environment
        Target environment
    .PARAMETER Merge
        Merge with existing configuration
    .EXAMPLE
        Import-Configuration -Path "C:\Config\backup-settings.json" -Section "Backup"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [string]$Path,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'Object')]
        [hashtable]$Configuration,
        
        [Parameter(Mandatory = $true)]
        [string]$Section,
        
        [Parameter(Mandatory = $false)]
        [string]$Environment = $script:CurrentEnvironment,
        
        [Parameter(Mandatory = $false)]
        [switch]$Merge
    )
    
    try {
        # Load configuration
        if ($PSCmdlet.ParameterSetName -eq 'File') {
            if (-not (Test-Path $Path)) {
                throw "Configuration file not found: $Path"
            }
            $newConfig = Get-Content $Path -Raw | ConvertFrom-Json -AsHashtable
        } else {
            $newConfig = $Configuration
        }
        
        # Validate configuration
        $validation = Validate-Configuration -Configuration $newConfig -Section $Section
        if (-not $validation.IsValid) {
            throw "Configuration validation failed: $($validation.Errors -join ', ')"
        }
        
        # Load existing configuration if merging
        if ($Merge) {
            $existingConfig = Load-ConfigurationSection -Section $Section -Environment $Environment
            $finalConfig = Merge-ConfigurationObjects -Base $existingConfig -Override $newConfig
        } else {
            $finalConfig = $newConfig
        }
        
        # Save configuration
        Save-ConfigurationSection -Section $Section -Configuration $finalConfig -Environment $Environment
        
        # Clear cache
        $script:ConfigurationCache.Keys | Where-Object { $_ -like "$Environment|$Section|*" } | ForEach-Object {
            $script:ConfigurationCache.Remove($_)
        }
        
        Write-AutomationLog -Message "Configuration imported: Section='$Section', Environment='$Environment', Merge=$($Merge.IsPresent)" -Level Information
        
        return $true
        
    } catch {
        Write-Error "Failed to import configuration: $_"
        throw
    }
}

function Export-Configuration {
    <#
    .SYNOPSIS
        Exports configuration to file
    .DESCRIPTION
        Saves configuration with optional filtering and formatting.
    .PARAMETER Section
        Configuration section
    .PARAMETER Path
        Export file path
    .PARAMETER Environment
        Source environment
    .PARAMETER IncludeSchema
        Include schema definition
    .PARAMETER Format
        Output format (JSON, YAML)
    .EXAMPLE
        Export-Configuration -Section "Backup" -Path "C:\Export\backup-config.json"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Section,
        
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $false)]
        [string]$Environment = $script:CurrentEnvironment,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeSchema,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('JSON', 'YAML')]
        [string]$Format = 'JSON'
    )
    
    try {
        # Load configuration
        $config = Load-ConfigurationSection -Section $Section -Environment $Environment
        
        # Create export object
        $export = @{
            Section = $Section
            Environment = $Environment
            ExportedAt = Get-Date
            ExportedBy = $env:USERNAME
            Configuration = $config
        }
        
        # Include schema if requested
        if ($IncludeSchema) {
            $schema = Get-ConfigurationSchema -Section $Section
            if ($schema) {
                $export.Schema = $schema
            }
        }
        
        # Export based on format
        switch ($Format) {
            'JSON' {
                $export | ConvertTo-Json -Depth 10 | Set-Content -Path $Path
            }
            'YAML' {
                # Would require a YAML module
                throw "YAML export not yet implemented"
            }
        }
        
        Write-AutomationLog -Message "Configuration exported: Section='$Section', Path='$Path', Format='$Format'" -Level Information
        
        return $true
        
    } catch {
        Write-Error "Failed to export configuration: $_"
        throw
    }
}

#endregion

#region Schema Management

function New-ConfigurationSchema {
    <#
    .SYNOPSIS
        Creates a new configuration schema
    .DESCRIPTION
        Generates JSON schema for configuration validation with intelligent
        type inference and constraint detection.
    .PARAMETER Section
        Configuration section name
    .PARAMETER SampleConfiguration
        Sample configuration to infer schema from
    .PARAMETER SchemaPath
        Path to save schema file
    .PARAMETER Strict
        Generate strict schema with all properties required
    .EXAMPLE
        New-ConfigurationSchema -Section "Backup" -SampleConfiguration $backupConfig
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Section,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$SampleConfiguration,
        
        [Parameter(Mandatory = $false)]
        [string]$SchemaPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$Strict
    )
    
    try {
        Write-AutomationLog -Message "Generating configuration schema for section: $Section" -Level Information
        
        # Generate schema from sample
        $schema = @{
            '$schema' = 'http://json-schema.org/draft-07/schema#'
            '$id' = "https://enterprise.com/schemas/$Section.schema.json"
            title = "$Section Configuration Schema"
            description = "Schema for $Section configuration section"
            type = 'object'
            properties = @{}
            required = @()
            additionalProperties = -not $Strict
        }
        
        # Analyze sample configuration
        foreach ($key in $SampleConfiguration.Keys) {
            $value = $SampleConfiguration[$key]
            $property = Infer-PropertySchema -Name $key -Value $value -Strict:$Strict
            $schema.properties[$key] = $property
            
            if ($Strict -or (Test-RequiredProperty -Name $key -Value $value)) {
                $schema.required += $key
            }
        }
        
        # Add common patterns
        $schema = Add-CommonSchemaPatterns -Schema $schema -Section $Section
        
        # Save schema if path provided
        if ($SchemaPath) {
            $schemaDir = Split-Path $SchemaPath -Parent
            if (-not (Test-Path $schemaDir)) {
                New-Item -ItemType Directory -Path $schemaDir -Force | Out-Null
            }
            
            $schema | ConvertTo-Json -Depth 10 | Set-Content -Path $SchemaPath
            Write-AutomationLog -Message "Schema saved to: $SchemaPath" -Level Success
        }
        
        # Cache schema
        $script:SchemaCache[$Section] = $schema
        
        return $schema
        
    } catch {
        Write-Error "Failed to create configuration schema: $_"
        throw
    }
}

function Validate-Configuration {
    <#
    .SYNOPSIS
        Validates configuration against schema
    .DESCRIPTION
        Performs comprehensive validation including type checking, constraints,
        and business rules.
    .PARAMETER Configuration
        Configuration to validate
    .PARAMETER Section
        Configuration section (for schema lookup)
    .PARAMETER Schema
        Explicit schema to use
    .EXAMPLE
        $result = Validate-Configuration -Configuration $config -Section "Backup"
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Configuration,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'Section')]
        [string]$Section,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'Schema')]
        [hashtable]$Schema
    )
    
    try {
        # Get schema
        if ($PSCmdlet.ParameterSetName -eq 'Section') {
            $Schema = Get-ConfigurationSchema -Section $Section
            if (-not $Schema) {
                Write-AutomationLog -Message "No schema found for section: $Section" -Level Warning
                return [PSCustomObject]@{
                    IsValid = $true
                    Errors = @()
                    Warnings = @("No schema defined for validation")
                }
            }
        }
        
        # Initialize validation result
        $result = [PSCustomObject]@{
            IsValid = $true
            Errors = @()
            Warnings = @()
            ValidatedProperties = @()
        }
        
        # Validate required properties
        if ($Schema.required) {
            foreach ($required in $Schema.required) {
                if (-not $Configuration.ContainsKey($required)) {
                    $result.IsValid = $false
                    $result.Errors += "Missing required property: $required"
                }
            }
        }
        
        # Validate each property
        foreach ($property in $Configuration.Keys) {
            if ($Schema.properties -and $Schema.properties.ContainsKey($property)) {
                $propSchema = $Schema.properties[$property]
                $propResult = Validate-PropertyValue -Name $property -Value $Configuration[$property] -Schema $propSchema
                
                if (-not $propResult.IsValid) {
                    $result.IsValid = $false
                    $result.Errors += $propResult.Errors
                }
                
                $result.ValidatedProperties += $property
                
            } elseif ($Schema.additionalProperties -eq $false) {
                $result.IsValid = $false
                $result.Errors += "Unexpected property: $property"
            }
        }
        
        # Apply custom validation rules
        $customResult = Invoke-CustomValidation -Configuration $Configuration -Section $Section
        if ($customResult.Errors.Count -gt 0) {
            $result.IsValid = $false
            $result.Errors += $customResult.Errors
        }
        $result.Warnings += $customResult.Warnings
        
        return $result
        
    } catch {
        Write-Error "Failed to validate configuration: $_"
        throw
    }
}

function Get-ConfigurationSchemaTemplate {
    <#
    .SYNOPSIS
        Gets a schema template for common configuration types
    .DESCRIPTION
        Returns pre-defined schema templates for common configuration patterns.
    .PARAMETER Type
        Template type
    .PARAMETER Customize
        Return customizable template
    .EXAMPLE
        $template = Get-ConfigurationSchemaTemplate -Type "ServiceEndpoint"
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('ServiceEndpoint', 'Database', 'Credentials', 'Logging', 'Performance', 'Security')]
        [string]$Type,
        
        [Parameter(Mandatory = $false)]
        [switch]$Customize
    )
    
    $templates = @{
        ServiceEndpoint = @{
            type = 'object'
            properties = @{
                url = @{
                    type = 'string'
                    format = 'uri'
                    description = 'Service endpoint URL'
                }
                port = @{
                    type = 'integer'
                    minimum = 1
                    maximum = 65535
                    default = 443
                }
                protocol = @{
                    type = 'string'
                    enum = @('http', 'https', 'tcp', 'udp')
                    default = 'https'
                }
                timeout = @{
                    type = 'integer'
                    minimum = 1000
                    maximum = 300000
                    default = 30000
                    description = 'Timeout in milliseconds'
                }
                retryPolicy = @{
                    type = 'object'
                    properties = @{
                        maxAttempts = @{ type = 'integer'; minimum = 1; maximum = 10; default = 3 }
                        backoffMultiplier = @{ type = 'number'; minimum = 1; maximum = 5; default = 2 }
                        initialDelay = @{ type = 'integer'; minimum = 100; default = 1000 }
                    }
                }
            }
            required = @('url')
        }
        
        Database = @{
            type = 'object'
            properties = @{
                connectionString = @{
                    type = 'string'
                    description = 'Database connection string'
                }
                provider = @{
                    type = 'string'
                    enum = @('SqlServer', 'PostgreSQL', 'MySQL', 'SQLite', 'Oracle')
                }
                pooling = @{
                    type = 'object'
                    properties = @{
                        enabled = @{ type = 'boolean'; default = $true }
                        minSize = @{ type = 'integer'; minimum = 0; default = 0 }
                        maxSize = @{ type = 'integer'; minimum = 1; default = 100 }
                        timeout = @{ type = 'integer'; minimum = 1000; default = 30000 }
                    }
                }
            }
            required = @('connectionString', 'provider')
        }
        
        Credentials = @{
            type = 'object'
            properties = @{
                credentialName = @{
                    type = 'string'
                    pattern = '^[a-zA-Z0-9_-]+$'
                }
                type = @{
                    type = 'string'
                    enum = @('UsernamePassword', 'Certificate', 'Token', 'Integrated')
                }
                expirationDays = @{
                    type = 'integer'
                    minimum = 1
                    maximum = 365
                    default = 90
                }
                allowedUsers = @{
                    type = 'array'
                    items = @{ type = 'string' }
                    minItems = 1
                }
            }
            required = @('credentialName', 'type')
        }
        
        Logging = @{
            type = 'object'
            properties = @{
                level = @{
                    type = 'string'
                    enum = @('Debug', 'Verbose', 'Information', 'Warning', 'Error', 'Critical')
                    default = 'Information'
                }
                targets = @{
                    type = 'array'
                    items = @{
                        type = 'object'
                        properties = @{
                            type = @{ type = 'string'; enum = @('File', 'EventLog', 'Console', 'Database') }
                            enabled = @{ type = 'boolean'; default = $true }
                            configuration = @{ type = 'object' }
                        }
                        required = @('type')
                    }
                }
                retention = @{
                    type = 'object'
                    properties = @{
                        days = @{ type = 'integer'; minimum = 1; default = 30 }
                        maxSizeMB = @{ type = 'integer'; minimum = 1; default = 1000 }
                    }
                }
            }
            required = @('level')
        }
        
        Performance = @{
            type = 'object'
            properties = @{
                monitoring = @{
                    type = 'object'
                    properties = @{
                        enabled = @{ type = 'boolean'; default = $true }
                        samplingRate = @{ type = 'number'; minimum = 0; maximum = 1; default = 0.1 }
                        metricsRetention = @{ type = 'integer'; minimum = 1; default = 7 }
                    }
                }
                limits = @{
                    type = 'object'
                    properties = @{
                        maxConcurrentOperations = @{ type = 'integer'; minimum = 1; default = 10 }
                        maxMemoryMB = @{ type = 'integer'; minimum = 100; default = 1000 }
                        maxExecutionTime = @{ type = 'integer'; minimum = 1000; default = 300000 }
                    }
                }
                optimization = @{
                    type = 'object'
                    properties = @{
                        caching = @{ type = 'boolean'; default = $true }
                        compression = @{ type = 'boolean'; default = $false }
                        parallelization = @{ type = 'boolean'; default = $true }
                    }
                }
            }
        }
        
        Security = @{
            type = 'object'
            properties = @{
                authentication = @{
                    type = 'object'
                    properties = @{
                        method = @{ type = 'string'; enum = @('Windows', 'Basic', 'OAuth', 'Certificate') }
                        requireMFA = @{ type = 'boolean'; default = $false }
                        sessionTimeout = @{ type = 'integer'; minimum = 60; default = 1800 }
                    }
                    required = @('method')
                }
                encryption = @{
                    type = 'object'
                    properties = @{
                        algorithm = @{ type = 'string'; enum = @('AES256', 'RSA2048', 'RSA4096') }
                        keyRotation = @{ type = 'boolean'; default = $true }
                        keyRotationDays = @{ type = 'integer'; minimum = 1; default = 90 }
                    }
                }
                compliance = @{
                    type = 'object'
                    properties = @{
                        frameworks = @{
                            type = 'array'
                            items = @{ type = 'string'; enum = @('SOC2', 'HIPAA', 'PCI-DSS', 'GDPR') }
                        }
                        auditLevel = @{ type = 'string'; enum = @('None', 'Basic', 'Detailed', 'Forensic') }
                    }
                }
            }
        }
    }
    
    $template = $templates[$Type]
    
    if ($Customize) {
        # Return a deep copy that can be modified
        return $template | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
    }
    
    return $template
}

function Test-ConfigurationCompliance {
    <#
    .SYNOPSIS
        Tests configuration compliance against policies
    .DESCRIPTION
        Validates configuration against security policies, best practices,
        and compliance requirements.
    .PARAMETER Section
        Configuration section
    .PARAMETER Configuration
        Configuration to test
    .PARAMETER Policy
        Compliance policy to apply
    .EXAMPLE
        $compliance = Test-ConfigurationCompliance -Section "Security" -Policy "SOC2"
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Section,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Configuration,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Default', 'SOC2', 'HIPAA', 'PCI-DSS', 'GDPR', 'Strict')]
        [string]$Policy = 'Default'
    )
    
    try {
        # Load configuration if not provided
        if (-not $Configuration) {
            $Configuration = Get-Configuration -Section $Section
        }
        
        # Initialize compliance result
        $result = [PSCustomObject]@{
            Section = $Section
            Policy = $Policy
            IsCompliant = $true
            Violations = @()
            Warnings = @()
            Recommendations = @()
            CheckedAt = Get-Date
        }
        
        # Load policy rules
        $rules = Get-ComplianceRules -Policy $Policy -Section $Section
        
        # Apply rules
        foreach ($rule in $rules) {
            $ruleResult = Test-ComplianceRule -Configuration $Configuration -Rule $rule
            
            if ($ruleResult.Severity -eq 'Error') {
                $result.IsCompliant = $false
                $result.Violations += $ruleResult.Message
            } elseif ($ruleResult.Severity -eq 'Warning') {
                $result.Warnings += $ruleResult.Message
            } elseif ($ruleResult.Severity -eq 'Info') {
                $result.Recommendations += $ruleResult.Message
            }
        }
        
        # Log compliance check
        $logLevel = if ($result.IsCompliant) { 'Information' } else { 'Warning' }
        Write-AutomationLog -Message "Configuration compliance check: Section='$Section', Policy='$Policy', Compliant=$($result.IsCompliant)" -Level $logLevel -Data @{
            Violations = $result.Violations.Count
            Warnings = $result.Warnings.Count
        }
        
        return $result
        
    } catch {
        Write-Error "Failed to test configuration compliance: $_"
        throw
    }
}

#endregion

#region Environment Management

function Get-ConfigurationEnvironment {
    <#
    .SYNOPSIS
        Gets current or available configuration environments
    .DESCRIPTION
        Retrieves information about configuration environments including
        current active environment and available environments.
    .PARAMETER ListAvailable
        List all available environments
    .EXAMPLE
        $environments = Get-ConfigurationEnvironment -ListAvailable
    #>
    [CmdletBinding()]
    [OutputType([string], [PSCustomObject[]])]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$ListAvailable
    )
    
    if ($ListAvailable) {
        $configRoot = Get-ConfigurationRoot
        $environments = @()
        
        # Add default environments
        $environments += [PSCustomObject]@{
            Name = 'Development'
            Description = 'Development environment configuration'
            IsActive = $script:CurrentEnvironment -eq 'Development'
            ConfigPath = Join-Path $configRoot 'Development'
        }
        
        $environments += [PSCustomObject]@{
            Name = 'Staging'
            Description = 'Staging environment configuration'
            IsActive = $script:CurrentEnvironment -eq 'Staging'
            ConfigPath = Join-Path $configRoot 'Staging'
        }
        
        $environments += [PSCustomObject]@{
            Name = 'Production'
            Description = 'Production environment configuration'
            IsActive = $script:CurrentEnvironment -eq 'Production'
            ConfigPath = Join-Path $configRoot 'Production'
        }
        
        # Discover custom environments
        $customEnvs = Get-ChildItem -Path $configRoot -Directory | Where-Object {
            $_.Name -notin @('Development', 'Staging', 'Production', 'Schemas', 'Backup')
        }
        
        foreach ($env in $customEnvs) {
            $environments += [PSCustomObject]@{
                Name = $env.Name
                Description = "Custom environment: $($env.Name)"
                IsActive = $script:CurrentEnvironment -eq $env.Name
                ConfigPath = $env.FullName
            }
        }
        
        return $environments
    } else {
        return $script:CurrentEnvironment
    }
}

function Set-ConfigurationEnvironment {
    <#
    .SYNOPSIS
        Sets the active configuration environment
    .DESCRIPTION
        Changes the current configuration environment and clears relevant caches.
    .PARAMETER Environment
        Target environment name
    .PARAMETER Validate
        Validate environment exists
    .EXAMPLE
        Set-ConfigurationEnvironment -Environment "Staging"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Environment,
        
        [Parameter(Mandatory = $false)]
        [switch]$Validate
    )
    
    if ($PSCmdlet.ShouldProcess($Environment, "Set configuration environment")) {
        
        # Validate environment exists
        if ($Validate) {
            $available = Get-ConfigurationEnvironment -ListAvailable
            if ($Environment -notin $available.Name) {
                throw "Environment not found: $Environment. Available: $($available.Name -join ', ')"
            }
        }
        
        # Update environment
        $oldEnvironment = $script:CurrentEnvironment
        $script:CurrentEnvironment = $Environment
        
        # Clear configuration cache
        $script:ConfigurationCache.Clear()
        
        # Update automation context if available
        if (Get-Command -Name 'Set-AutomationContext' -ErrorAction SilentlyContinue) {
            Set-AutomationContext -Property 'Environment' -Value $Environment
        }
        
        Write-AutomationLog -Message "Configuration environment changed from '$oldEnvironment' to '$Environment'" -Level Information
        
        return $true
    }
}

function New-ConfigurationEnvironment {
    <#
    .SYNOPSIS
        Creates a new configuration environment
    .DESCRIPTION
        Sets up a new environment with optional base configuration copy.
    .PARAMETER Name
        Environment name
    .PARAMETER Description
        Environment description
    .PARAMETER CopyFrom
        Source environment to copy from
    .PARAMETER Initialize
        Initialize with default structure
    .EXAMPLE
        New-ConfigurationEnvironment -Name "Testing" -CopyFrom "Development"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Description = "Custom environment: $Name",
        
        [Parameter(Mandatory = $false)]
        [string]$CopyFrom,
        
        [Parameter(Mandatory = $false)]
        [switch]$Initialize
    )
    
    try {
        if ($PSCmdlet.ShouldProcess($Name, "Create configuration environment")) {
            
            $configRoot = Get-ConfigurationRoot
            $envPath = Join-Path $configRoot $Name
            
            # Check if already exists
            if (Test-Path $envPath) {
                throw "Environment already exists: $Name"
            }
            
            # Create environment directory
            New-Item -ItemType Directory -Path $envPath -Force | Out-Null
            
            # Copy from source environment
            if ($CopyFrom) {
                $sourcePath = Join-Path $configRoot $CopyFrom
                if (-not (Test-Path $sourcePath)) {
                    throw "Source environment not found: $CopyFrom"
                }
                
                Copy-Item -Path "$sourcePath\*" -Destination $envPath -Recurse
                Write-AutomationLog -Message "Environment configuration copied from: $CopyFrom" -Level Information
            }
            
            # Initialize with defaults
            if ($Initialize -and -not $CopyFrom) {
                Initialize-EnvironmentDefaults -Environment $Name -Path $envPath
            }
            
            # Create environment metadata
            $metadata = @{
                Name = $Name
                Description = $Description
                CreatedAt = Get-Date
                CreatedBy = $env:USERNAME
                CopiedFrom = $CopyFrom
            }
            
            $metadata | ConvertTo-Json | Set-Content -Path (Join-Path $envPath '.environment')
            
            Write-AutomationLog -Message "Configuration environment created: $Name" -Level Success
            
            return [PSCustomObject]@{
                Name = $Name
                Description = $Description
                ConfigPath = $envPath
                IsActive = $false
            }
        }
        
    } catch {
        Write-Error "Failed to create configuration environment: $_"
        throw
    }
}

function Copy-ConfigurationEnvironment {
    <#
    .SYNOPSIS
        Copies configuration from one environment to another
    .DESCRIPTION
        Duplicates configuration settings between environments with
        optional filtering and transformation.
    .PARAMETER Source
        Source environment
    .PARAMETER Destination
        Destination environment
    .PARAMETER Sections
        Specific sections to copy
    .PARAMETER Transform
        Transformation rules to apply
    .EXAMPLE
        Copy-ConfigurationEnvironment -Source "Development" -Destination "Testing" -Sections @("Backup", "Monitoring")
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source,
        
        [Parameter(Mandatory = $true)]
        [string]$Destination,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Sections,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Transform
    )
    
    try {
        if ($PSCmdlet.ShouldProcess("$Source -> $Destination", "Copy configuration")) {
            
            $configRoot = Get-ConfigurationRoot
            $sourcePath = Join-Path $configRoot $Source
            $destPath = Join-Path $configRoot $Destination
            
            # Validate environments
            if (-not (Test-Path $sourcePath)) {
                throw "Source environment not found: $Source"
            }
            
            if (-not (Test-Path $destPath)) {
                New-ConfigurationEnvironment -Name $Destination
            }
            
            # Get sections to copy
            if ($Sections) {
                $configFiles = $Sections | ForEach-Object { 
                    Join-Path $sourcePath "$_.json"
                } | Where-Object { Test-Path $_ }
            } else {
                $configFiles = Get-ChildItem -Path $sourcePath -Filter "*.json"
            }
            
            # Copy each configuration file
            foreach ($file in $configFiles) {
                $section = [System.IO.Path]::GetFileNameWithoutExtension($file)
                
                # Load configuration
                $config = Get-Content $file -Raw | ConvertFrom-Json -AsHashtable
                
                # Apply transformations
                if ($Transform -and $Transform.ContainsKey($section)) {
                    $config = Apply-ConfigurationTransform -Configuration $config -Transform $Transform[$section]
                }
                
                # Save to destination
                $destFile = Join-Path $destPath "$section.json"
                $config | ConvertTo-Json -Depth 10 | Set-Content -Path $destFile
                
                Write-AutomationLog -Message "Configuration copied: $section ($Source -> $Destination)" -Level Information
            }
            
            return $true
        }
        
    } catch {
        Write-Error "Failed to copy configuration environment: $_"
        throw
    }
}

#endregion

#region Credential Management

function Get-ConfiguredCredential {
    <#
    .SYNOPSIS
        Retrieves credentials from configuration
    .DESCRIPTION
        Gets credentials with automatic rotation check and secure retrieval.
    .PARAMETER Name
        Credential name
    .PARAMETER Purpose
        Purpose for audit logging
    .PARAMETER AutoRotate
        Check and rotate if expired
    .EXAMPLE
        $cred = Get-ConfiguredCredential -Name "BackupService" -Purpose "Backup operation"
    #>
    [CmdletBinding()]
    [OutputType([PSCredential])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [string]$Purpose,
        
        [Parameter(Mandatory = $false)]
        [switch]$AutoRotate
    )
    
    try {
        # Get credential configuration
        $credConfig = Get-Configuration -Section 'Credentials' -Path $Name
        if (-not $credConfig) {
            throw "Credential configuration not found: $Name"
        }
        
        # Check expiration
        if ($credConfig.ExpiresAt) {
            $expirationDate = [DateTime]$credConfig.ExpiresAt
            if ($expirationDate -lt (Get-Date)) {
                if ($AutoRotate) {
                    Write-AutomationLog -Message "Credential expired, initiating rotation: $Name" -Level Warning
                    $credConfig = Rotate-ConfiguredCredentials -Names @($Name) | Where-Object { $_.Name -eq $Name }
                } else {
                    Write-Warning "Credential expired: $Name (Expired: $expirationDate)"
                }
            }
        }
        
        # Retrieve secure credential
        $credential = Get-SecureCredential -CredentialName $credConfig.CredentialName -Purpose $Purpose
        
        return $credential
        
    } catch {
        Write-Error "Failed to retrieve configured credential '$Name': $_"
        throw
    }
}

function Set-ConfiguredCredential {
    <#
    .SYNOPSIS
        Stores credential in configuration
    .DESCRIPTION
        Saves credential with metadata and optional expiration.
    .PARAMETER Name
        Credential name
    .PARAMETER Credential
        PSCredential object
    .PARAMETER Description
        Credential description
    .PARAMETER ExpirationDays
        Days until expiration
    .PARAMETER AllowedUsers
        Users allowed to access
    .PARAMETER Tags
        Tags for categorization
    .EXAMPLE
        Set-ConfiguredCredential -Name "BackupService" -Credential $cred -ExpirationDays 90
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [string]$Description,
        
        [Parameter(Mandatory = $false)]
        [int]$ExpirationDays = 90,
        
        [Parameter(Mandatory = $false)]
        [string[]]$AllowedUsers = @($env:USERNAME),
        
        [Parameter(Mandatory = $false)]
        [string[]]$Tags = @()
    )
    
    try {
        if ($PSCmdlet.ShouldProcess($Name, "Store configured credential")) {
            
            # Generate secure credential name
            $credentialName = "ConfigCred_${Name}_$(Get-Date -Format 'yyyyMMddHHmmss')"
            
            # Store secure credential
            Set-SecureCredential -CredentialName $credentialName -Credential $Credential -AllowedUsers $AllowedUsers -ExpirationDays $ExpirationDays
            
            # Create credential configuration
            $credConfig = @{
                Name = $Name
                CredentialName = $credentialName
                Description = $Description
                Type = 'PSCredential'
                CreatedAt = Get-Date
                CreatedBy = $env:USERNAME
                ExpiresAt = (Get-Date).AddDays($ExpirationDays)
                AllowedUsers = $AllowedUsers
                Tags = $Tags
                Username = $Credential.UserName
            }
            
            # Save to configuration
            Set-Configuration -Section 'Credentials' -Path $Name -Value $credConfig -Persist
            
            Write-AutomationLog -Message "Configured credential stored: $Name (Expires: $($credConfig.ExpiresAt))" -Level Success -Tags @('Security', 'Credential')
            
            return $credConfig
        }
        
    } catch {
        Write-Error "Failed to store configured credential '$Name': $_"
        throw
    }
}

function Test-CredentialExpiration {
    <#
    .SYNOPSIS
        Tests credentials for expiration
    .DESCRIPTION
        Checks configured credentials for expiration or upcoming expiration.
    .PARAMETER Names
        Specific credentials to check
    .PARAMETER DaysWarning
        Days before expiration to warn
    .PARAMETER IncludeValid
        Include non-expired credentials
    .EXAMPLE
        $expiring = Test-CredentialExpiration -DaysWarning 30
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$Names,
        
        [Parameter(Mandatory = $false)]
        [int]$DaysWarning = 14,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeValid
    )
    
    try {
        # Get all credentials configuration
        $credSection = Get-Configuration -Section 'Credentials'
        if (-not $credSection) {
            Write-AutomationLog -Message "No credentials configured" -Level Information
            return @()
        }
        
        $results = @()
        $warningDate = (Get-Date).AddDays($DaysWarning)
        
        # Check each credential
        $credsToCheck = if ($Names) {
            $Names | ForEach-Object { $credSection.$_ } | Where-Object { $_ }
        } else {
            $credSection.PSObject.Properties.Value
        }
        
        foreach ($cred in $credsToCheck) {
            if ($cred.ExpiresAt) {
                $expirationDate = [DateTime]$cred.ExpiresAt
                $daysUntilExpiration = ($expirationDate - (Get-Date)).Days
                
                $status = if ($expirationDate -lt (Get-Date)) {
                    'Expired'
                } elseif ($expirationDate -lt $warningDate) {
                    'Expiring'
                } else {
                    'Valid'
                }
                
                if ($IncludeValid -or $status -ne 'Valid') {
                    $results += [PSCustomObject]@{
                        Name = $cred.Name
                        Username = $cred.Username
                        Status = $status
                        ExpiresAt = $expirationDate
                        DaysUntilExpiration = $daysUntilExpiration
                        CreatedBy = $cred.CreatedBy
                        AllowedUsers = $cred.AllowedUsers
                    }
                }
            }
        }
        
        # Log summary
        $expired = ($results | Where-Object { $_.Status -eq 'Expired' }).Count
        $expiring = ($results | Where-Object { $_.Status -eq 'Expiring' }).Count
        
        if ($expired -gt 0 -or $expiring -gt 0) {
            Write-AutomationLog -Message "Credential expiration check: $expired expired, $expiring expiring soon" -Level Warning
        }
        
        return $results | Sort-Object DaysUntilExpiration
        
    } catch {
        Write-Error "Failed to test credential expiration: $_"
        throw
    }
}

function Rotate-ConfiguredCredentials {
    <#
    .SYNOPSIS
        Rotates configured credentials
    .DESCRIPTION
        Performs credential rotation with optional automatic password generation.
    .PARAMETER Names
        Credentials to rotate
    .PARAMETER GeneratePassword
        Auto-generate new passwords
    .PARAMETER NotifyUsers
        Notify affected users
    .PARAMETER Force
        Force rotation even if not expired
    .EXAMPLE
        Rotate-ConfiguredCredentials -Names @("BackupService", "MonitoringService") -GeneratePassword
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Names,
        
        [Parameter(Mandatory = $false)]
        [switch]$GeneratePassword,
        
        [Parameter(Mandatory = $false)]
        [switch]$NotifyUsers,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    try {
        $rotated = @()
        
        foreach ($name in $Names) {
            if ($PSCmdlet.ShouldProcess($name, "Rotate credential")) {
                
                # Get current credential configuration
                $credConfig = Get-Configuration -Section 'Credentials' -Path $name
                if (-not $credConfig) {
                    Write-Warning "Credential configuration not found: $name"
                    continue
                }
                
                # Check if rotation needed
                if (-not $Force) {
                    $expirationDate = [DateTime]$credConfig.ExpiresAt
                    if ($expirationDate -gt (Get-Date).AddDays(7)) {
                        Write-AutomationLog -Message "Credential rotation skipped (not expired): $name" -Level Information
                        continue
                    }
                }
                
                # Get new credential
                if ($GeneratePassword) {
                    $newPassword = New-SecurePassword -Length 20 -Complexity High
                    $securePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force
                    $newCredential = New-Object PSCredential($credConfig.Username, $securePassword)
                } else {
                    $newCredential = Get-Credential -UserName $credConfig.Username -Message "Enter new password for: $name"
                    if (-not $newCredential) {
                        Write-Warning "Credential rotation cancelled: $name"
                        continue
                    }
                }
                
                # Store new credential
                $newConfig = Set-ConfiguredCredential -Name $name -Credential $newCredential `
                    -Description $credConfig.Description -AllowedUsers $credConfig.AllowedUsers `
                    -Tags $credConfig.Tags -ExpirationDays 90
                
                $rotated += $newConfig
                
                # Notify users if requested
                if ($NotifyUsers) {
                    Send-CredentialRotationNotification -CredentialName $name -Users $credConfig.AllowedUsers
                }
                
                Write-AutomationLog -Message "Credential rotated: $name" -Level Success -Tags @('Security', 'Credential', 'Rotation')
            }
        }
        
        return $rotated
        
    } catch {
        Write-Error "Failed to rotate credentials: $_"
        throw
    }
}

#endregion

#region Configuration Profiles

function New-ConfigurationProfile {
    <#
    .SYNOPSIS
        Creates a configuration profile
    .DESCRIPTION
        Defines a reusable configuration profile for specific scenarios.
    .PARAMETER Name
        Profile name
    .PARAMETER Description
        Profile description
    .PARAMETER Configurations
        Configuration overrides
    .PARAMETER BasedOn
        Base profile to extend
    .EXAMPLE
        New-ConfigurationProfile -Name "HighSecurity" -Configurations @{Security=@{RequireMFA=$true}}
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Description,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Configurations,
        
        [Parameter(Mandatory = $false)]
        [string]$BasedOn
    )
    
    try {
        # Check if profile exists
        if ($script:ConfigurationProfiles.ContainsKey($Name)) {
            throw "Configuration profile already exists: $Name"
        }
        
        # Create profile
        $profile = [PSCustomObject]@{
            Name = $Name
            Description = $Description
            BasedOn = $BasedOn
            Configurations = $Configurations
            CreatedAt = Get-Date
            CreatedBy = $env:USERNAME
            LastModified = Get-Date
            AppliedCount = 0
        }
        
        # Merge with base profile if specified
        if ($BasedOn) {
            if (-not $script:ConfigurationProfiles.ContainsKey($BasedOn)) {
                throw "Base profile not found: $BasedOn"
            }
            
            $baseProfile = $script:ConfigurationProfiles[$BasedOn]
            $mergedConfig = Merge-ConfigurationObjects -Base $baseProfile.Configurations -Override $Configurations
            $profile.Configurations = $mergedConfig
        }
        
        # Store profile
        $script:ConfigurationProfiles[$Name] = $profile
        
        # Persist profiles
        Save-ConfigurationProfiles
        
        Write-AutomationLog -Message "Configuration profile created: $Name" -Level Success
        
        return $profile
        
    } catch {
        Write-Error "Failed to create configuration profile: $_"
        throw
    }
}

function Get-ConfigurationProfile {
    <#
    .SYNOPSIS
        Retrieves configuration profiles
    .DESCRIPTION
        Gets one or more configuration profiles with optional filtering.
    .PARAMETER Name
        Profile name
    .PARAMETER ListAvailable
        List all profiles
    .EXAMPLE
        $profiles = Get-ConfigurationProfile -ListAvailable
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject], [PSCustomObject[]])]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Name')]
        [string]$Name,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'List')]
        [switch]$ListAvailable
    )
    
    if ($PSCmdlet.ParameterSetName -eq 'Name') {
        if (-not $script:ConfigurationProfiles.ContainsKey($Name)) {
            throw "Configuration profile not found: $Name"
        }
        return $script:ConfigurationProfiles[$Name]
    } else {
        return $script:ConfigurationProfiles.Values | Sort-Object Name
    }
}

function Apply-ConfigurationProfile {
    <#
    .SYNOPSIS
        Applies a configuration profile
    .DESCRIPTION
        Applies profile settings to current configuration with optional persistence.
    .PARAMETER Name
        Profile name
    .PARAMETER Environment
        Target environment
    .PARAMETER Sections
        Specific sections to apply
    .PARAMETER Persist
        Save changes
    .EXAMPLE
        Apply-ConfigurationProfile -Name "HighSecurity" -Environment "Production" -Persist
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Environment = $script:CurrentEnvironment,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Sections,
        
        [Parameter(Mandatory = $false)]
        [switch]$Persist
    )
    
    try {
        $profile = Get-ConfigurationProfile -Name $Name
        
        if ($PSCmdlet.ShouldProcess("$Environment", "Apply configuration profile '$Name'")) {
            
            $appliedSections = @()
            
            foreach ($section in $profile.Configurations.Keys) {
                # Skip if specific sections requested and this isn't one
                if ($Sections -and $section -notin $Sections) {
                    continue
                }
                
                # Apply each configuration value
                $sectionConfig = $profile.Configurations[$section]
                foreach ($key in $sectionConfig.Keys) {
                    Set-Configuration -Section $section -Path $key -Value $sectionConfig[$key] `
                        -Environment $Environment -Persist:$Persist -Force
                }
                
                $appliedSections += $section
            }
            
            # Update profile usage
            $profile.AppliedCount++
            $profile.LastApplied = Get-Date
            $profile.LastAppliedBy = $env:USERNAME
            $profile.LastAppliedTo = $Environment
            
            Save-ConfigurationProfiles
            
            Write-AutomationLog -Message "Configuration profile applied: $Name to $Environment (Sections: $($appliedSections -join ', '))" -Level Success
            
            return [PSCustomObject]@{
                Profile = $Name
                Environment = $Environment
                AppliedSections = $appliedSections
                Persisted = $Persist
                AppliedAt = Get-Date
            }
        }
        
    } catch {
        Write-Error "Failed to apply configuration profile: $_"
        throw
    }
}

function Remove-ConfigurationProfile {
    <#
    .SYNOPSIS
        Removes a configuration profile
    .DESCRIPTION
        Deletes a configuration profile from the system.
    .PARAMETER Name
        Profile name
    .PARAMETER Force
        Skip confirmation
    .EXAMPLE
        Remove-ConfigurationProfile -Name "OldProfile" -Force
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    try {
        if (-not $script:ConfigurationProfiles.ContainsKey($Name)) {
            throw "Configuration profile not found: $Name"
        }
        
        if ($Force -or $PSCmdlet.ShouldProcess($Name, "Remove configuration profile")) {
            
            $script:ConfigurationProfiles.Remove($Name)
            Save-ConfigurationProfiles
            
            Write-AutomationLog -Message "Configuration profile removed: $Name" -Level Information
            
            return $true
        }
        
    } catch {
        Write-Error "Failed to remove configuration profile: $_"
        throw
    }
}

#endregion

#region Private Helper Functions

function Get-ConfigurationRoot {
    <#
    .SYNOPSIS
        Gets the configuration root directory
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    
    $context = Get-AutomationContext -ErrorAction SilentlyContinue
    if ($context -and $context.ConfigurationPath) {
        return $context.ConfigurationPath
    }
    
    # Fall back to module default
    $moduleConfig = Import-PowerShellDataFile -Path "$PSScriptRoot\PSConfigurationManager.psd1"
    return $ExecutionContext.InvokeCommand.ExpandString($moduleConfig.PrivateData.ModuleConfig.ConfigurationRoot)
}

function Load-ConfigurationSection {
    <#
    .SYNOPSIS
        Loads a configuration section with environment overlay
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Section,
        
        [Parameter(Mandatory = $true)]
        [string]$Environment
    )
    
    $configRoot = Get-ConfigurationRoot
    
    # Load base configuration
    $basePath = Join-Path $configRoot "$Section.json"
    $baseConfig = @{}
    
    if (Test-Path $basePath) {
        $baseConfig = Get-Content $basePath -Raw | ConvertFrom-Json -AsHashtable
    }
    
    # Load environment-specific overlay
    $envPath = Join-Path $configRoot $Environment "$Section.json"
    if (Test-Path $envPath) {
        $envConfig = Get-Content $envPath -Raw | ConvertFrom-Json -AsHashtable
        $baseConfig = Merge-ConfigurationObjects -Base $baseConfig -Override $envConfig
    }
    
    return $baseConfig
}

function Save-ConfigurationSection {
    <#
    .SYNOPSIS
        Saves configuration section to disk
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Section,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Configuration,
        
        [Parameter(Mandatory = $true)]
        [string]$Environment
    )
    
    $configRoot = Get-ConfigurationRoot
    $envPath = Join-Path $configRoot $Environment
    
    # Ensure directory exists
    if (-not (Test-Path $envPath)) {
        New-Item -ItemType Directory -Path $envPath -Force | Out-Null
    }
    
    # Save configuration
    $configPath = Join-Path $envPath "$Section.json"
    $Configuration | ConvertTo-Json -Depth 10 | Set-Content -Path $configPath
}

function Get-ConfigurationValue {
    <#
    .SYNOPSIS
        Gets nested configuration value
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Configuration,
        
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    
    $segments = $Path -split '\.'
    $current = $Configuration
    
    foreach ($segment in $segments) {
        if ($current -is [hashtable] -and $current.ContainsKey($segment)) {
            $current = $current[$segment]
        } else {
            return $null
        }
    }
    
    return $current
}

function Set-ConfigurationValue {
    <#
    .SYNOPSIS
        Sets nested configuration value
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Configuration,
        
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $true)]
        [object]$Value
    )
    
    $segments = $Path -split '\.'
    $current = $Configuration
    
    for ($i = 0; $i -lt $segments.Count - 1; $i++) {
        $segment = $segments[$i]
        if (-not $current.ContainsKey($segment)) {
            $current[$segment] = @{}
        }
        $current = $current[$segment]
    }
    
    $current[$segments[-1]] = $Value
}

function Get-ConfigurationSchema {
    <#
    .SYNOPSIS
        Gets schema for configuration section
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Section
    )
    
    # Check cache
    if ($script:SchemaCache.ContainsKey($Section)) {
        return $script:SchemaCache[$Section]
    }
    
    # Load from file
    $schemaRoot = Join-Path (Get-ConfigurationRoot) 'Schemas'
    $schemaPath = Join-Path $schemaRoot "$Section.schema.json"
    
    if (Test-Path $schemaPath) {
        $schema = Get-Content $schemaPath -Raw | ConvertFrom-Json -AsHashtable
        $script:SchemaCache[$Section] = $schema
        return $schema
    }
    
    return $null
}

function Merge-ConfigurationObjects {
    <#
    .SYNOPSIS
        Deep merges configuration objects
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Base,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Override
    )
    
    $result = $Base.Clone()
    
    foreach ($key in $Override.Keys) {
        if ($Override[$key] -is [hashtable] -and $Base.ContainsKey($key) -and $Base[$key] -is [hashtable]) {
            $result[$key] = Merge-ConfigurationObjects -Base $Base[$key] -Override $Override[$key]
        } else {
            $result[$key] = $Override[$key]
        }
    }
    
    return $result
}

function Backup-Configuration {
    <#
    .SYNOPSIS
        Creates configuration backup
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Section,
        
        [Parameter(Mandatory = $true)]
        [string]$Environment
    )
    
    $configRoot = Get-ConfigurationRoot
    $backupRoot = Join-Path $configRoot 'Backup'
    $timestamp = Get-Date -Format 'yyyyMMddHHmmss'
    
    # Ensure backup directory exists
    if (-not (Test-Path $backupRoot)) {
        New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
    }
    
    # Create backup
    $sourcePath = Join-Path $configRoot $Environment "$Section.json"
    if (Test-Path $sourcePath) {
        $backupPath = Join-Path $backupRoot "${Section}_${Environment}_${timestamp}.json"
        Copy-Item -Path $sourcePath -Destination $backupPath
        
        # Clean old backups
        $maxBackups = 10  # From module config
        $backups = Get-ChildItem -Path $backupRoot -Filter "${Section}_${Environment}_*.json" |
            Sort-Object CreationTime -Descending |
            Select-Object -Skip $maxBackups
        
        $backups | Remove-Item -Force
    }
}

function Infer-PropertySchema {
    <#
    .SYNOPSIS
        Infers schema from property value
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [object]$Value,
        
        [Parameter(Mandatory = $false)]
        [switch]$Strict
    )
    
    $schema = @{
        description = "Configuration for $Name"
    }
    
    # Determine type
    if ($null -eq $Value) {
        $schema.type = @('null', 'string')
    } elseif ($Value -is [bool]) {
        $schema.type = 'boolean'
        $schema.default = $Value
    } elseif ($Value -is [int] -or $Value -is [long]) {
        $schema.type = 'integer'
        if ($Value -ge 0) {
            $schema.minimum = 0
        }
    } elseif ($Value -is [double] -or $Value -is [decimal]) {
        $schema.type = 'number'
    } elseif ($Value -is [string]) {
        $schema.type = 'string'
        
        # Detect patterns
        if ($Value -match '^https?://') {
            $schema.format = 'uri'
        } elseif ($Value -match '^\w+@\w+\.\w+$') {
            $schema.format = 'email'
        } elseif ($Value -match '^\d{4}-\d{2}-\d{2}') {
            $schema.format = 'date-time'
        }
        
        # Add pattern for specific names
        if ($Name -match 'password|secret|key' -and -not $Strict) {
            $schema.minLength = 8
        }
    } elseif ($Value -is [array]) {
        $schema.type = 'array'
        if ($Value.Count -gt 0) {
            $schema.items = Infer-PropertySchema -Name "${Name}[0]" -Value $Value[0] -Strict:$Strict
        }
    } elseif ($Value -is [hashtable]) {
        $schema.type = 'object'
        $schema.properties = @{}
        
        foreach ($key in $Value.Keys) {
            $schema.properties[$key] = Infer-PropertySchema -Name "$Name.$key" -Value $Value[$key] -Strict:$Strict
        }
    }
    
    return $schema
}

function Test-RequiredProperty {
    <#
    .SYNOPSIS
        Determines if property should be required
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [object]$Value
    )
    
    # Common required patterns
    $requiredPatterns = @(
        'server', 'host', 'url', 'endpoint',
        'username', 'user', 'account',
        'name', 'id', 'key',
        'path', 'directory', 'folder'
    )
    
    foreach ($pattern in $requiredPatterns) {
        if ($Name -match $pattern) {
            return $true
        }
    }
    
    # Required if not null or empty
    if ($Value -and $Value -ne '') {
        return $true
    }
    
    return $false
}

function Add-CommonSchemaPatterns {
    <#
    .SYNOPSIS
        Adds common schema patterns based on section type
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Schema,
        
        [Parameter(Mandatory = $true)]
        [string]$Section
    )
    
    # Add section-specific patterns
    switch -Wildcard ($Section) {
        '*Backup*' {
            if (-not $Schema.properties.ContainsKey('retention')) {
                $Schema.properties.retention = @{
                    type = 'object'
                    properties = @{
                        days = @{ type = 'integer'; minimum = 1; default = 30 }
                        count = @{ type = 'integer'; minimum = 1; default = 10 }
                    }
                }
            }
        }
        
        '*Security*' {
            if (-not $Schema.properties.ContainsKey('encryption')) {
                $Schema.properties.encryption = @{
                    type = 'object'
                    properties = @{
                        enabled = @{ type = 'boolean'; default = $true }
                        algorithm = @{ type = 'string'; enum = @('AES256', 'RSA2048') }
                    }
                }
            }
        }
        
        '*Monitoring*' {
            if (-not $Schema.properties.ContainsKey('interval')) {
                $Schema.properties.interval = @{
                    type = 'integer'
                    minimum = 1000
                    default = 60000
                    description = 'Monitoring interval in milliseconds'
                }
            }
        }
    }
    
    return $Schema
}

function Validate-PropertyValue {
    <#
    .SYNOPSIS
        Validates a property value against schema
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [object]$Value,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Schema
    )
    
    $result = @{
        IsValid = $true
        Errors = @()
    }
    
    # Type validation
    if ($Schema.type) {
        $validType = $false
        $types = if ($Schema.type -is [array]) { $Schema.type } else { @($Schema.type) }
        
        foreach ($type in $types) {
            if (Test-ValueType -Value $Value -Type $type) {
                $validType = $true
                break
            }
        }
        
        if (-not $validType) {
            $result.IsValid = $false
            $result.Errors += "Property '$Name' has invalid type. Expected: $($types -join ' or ')"
        }
    }
    
    # Additional validations based on type
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double]) {
        if ($Schema.minimum -and $Value -lt $Schema.minimum) {
            $result.IsValid = $false
            $result.Errors += "Property '$Name' value $Value is below minimum: $($Schema.minimum)"
        }
        if ($Schema.maximum -and $Value -gt $Schema.maximum) {
            $result.IsValid = $false
            $result.Errors += "Property '$Name' value $Value exceeds maximum: $($Schema.maximum)"
        }
    }
    
    if ($Value -is [string]) {
        if ($Schema.minLength -and $Value.Length -lt $Schema.minLength) {
            $result.IsValid = $false
            $result.Errors += "Property '$Name' length is below minimum: $($Schema.minLength)"
        }
        if ($Schema.pattern -and $Value -notmatch $Schema.pattern) {
            $result.IsValid = $false
            $result.Errors += "Property '$Name' does not match pattern: $($Schema.pattern)"
        }
        if ($Schema.enum -and $Value -notin $Schema.enum) {
            $result.IsValid = $false
            $result.Errors += "Property '$Name' value '$Value' not in allowed values: $($Schema.enum -join ', ')"
        }
    }
    
    return $result
}

function Test-ValueType {
    <#
    .SYNOPSIS
        Tests if value matches schema type
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Value,
        
        [Parameter(Mandatory = $true)]
        [string]$Type
    )
    
    switch ($Type) {
        'null' { return $null -eq $Value }
        'boolean' { return $Value -is [bool] }
        'integer' { return $Value -is [int] -or $Value -is [long] }
        'number' { return $Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal] }
        'string' { return $Value -is [string] }
        'array' { return $Value -is [array] }
        'object' { return $Value -is [hashtable] -or $Value -is [PSCustomObject] }
        default { return $true }
    }
}

function Invoke-CustomValidation {
    <#
    .SYNOPSIS
        Applies custom validation rules
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Configuration,
        
        [Parameter(Mandatory = $true)]
        [string]$Section
    )
    
    $result = @{
        Errors = @()
        Warnings = @()
    }
    
    # Section-specific validations
    switch ($Section) {
        'Backup' {
            if ($Configuration.compression -and $Configuration.encryption -and 
                $Configuration.compressionLevel -eq 'Maximum') {
                $result.Warnings += "Maximum compression with encryption may impact performance"
            }
        }
        
        'Security' {
            if ($Configuration.authentication -and $Configuration.authentication.method -eq 'Basic' -and
                -not $Configuration.encryption.enabled) {
                $result.Errors += "Basic authentication requires encryption to be enabled"
            }
        }
        
        'Database' {
            if ($Configuration.pooling -and $Configuration.pooling.enabled -and
                $Configuration.pooling.maxSize -lt $Configuration.pooling.minSize) {
                $result.Errors += "Database pool maxSize must be greater than or equal to minSize"
            }
        }
    }
    
    return $result
}

function Get-ComplianceRules {
    <#
    .SYNOPSIS
        Gets compliance rules for policy
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Policy,
        
        [Parameter(Mandatory = $true)]
        [string]$Section
    )
    
    $rules = @()
    
    # Common rules for all policies
    $rules += @{
        Name = 'CredentialExpiration'
        Check = { param($config) -not $config.credentials -or $config.credentials.expirationDays -le 90 }
        Message = 'Credentials must expire within 90 days'
        Severity = 'Error'
    }
    
    # Policy-specific rules
    switch ($Policy) {
        'SOC2' {
            $rules += @{
                Name = 'EncryptionRequired'
                Check = { param($config) $config.encryption -and $config.encryption.enabled }
                Message = 'Encryption must be enabled for SOC2 compliance'
                Severity = 'Error'
            }
            $rules += @{
                Name = 'AuditLogging'
                Check = { param($config) $config.logging -and $config.logging.auditLevel -in @('Detailed', 'Forensic') }
                Message = 'Detailed audit logging required for SOC2'
                Severity = 'Error'
            }
        }
        
        'HIPAA' {
            $rules += @{
                Name = 'DataEncryption'
                Check = { param($config) $config.encryption -and $config.encryption.algorithm -in @('AES256', 'RSA4096') }
                Message = 'Strong encryption required for HIPAA compliance'
                Severity = 'Error'
            }
            $rules += @{
                Name = 'AccessControl'
                Check = { param($config) $config.security -and $config.security.requireMFA }
                Message = 'Multi-factor authentication required for HIPAA'
                Severity = 'Error'
            }
        }
    }
    
    return $rules
}

function Test-ComplianceRule {
    <#
    .SYNOPSIS
        Tests a single compliance rule
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Configuration,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Rule
    )
    
    $passed = & $Rule.Check $Configuration
    
    return @{
        RuleName = $Rule.Name
        Passed = $passed
        Message = if (-not $passed) { $Rule.Message } else { $null }
        Severity = $Rule.Severity
    }
}

function Initialize-EnvironmentDefaults {
    <#
    .SYNOPSIS
        Initializes default configuration for new environment
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Environment,
        
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    
    # Create default configuration files
    $defaults = @{
        'General' = @{
            environment = $Environment
            debug = $false
            verboseLogging = $false
        }
        
        'Logging' = @{
            level = 'Information'
            targets = @(
                @{
                    type = 'File'
                    enabled = $true
                    configuration = @{
                        path = "`$env:ProgramData\PSAutomation\Logs\$Environment"
                    }
                }
            )
        }
        
        'Performance' = @{
            monitoring = @{
                enabled = $true
                samplingRate = 0.1
            }
            limits = @{
                maxConcurrentOperations = 10
            }
        }
    }
    
    foreach ($section in $defaults.Keys) {
        $sectionPath = Join-Path $Path "$section.json"
        $defaults[$section] | ConvertTo-Json -Depth 10 | Set-Content -Path $sectionPath
    }
}

function Apply-ConfigurationTransform {
    <#
    .SYNOPSIS
        Applies transformation rules to configuration
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Configuration,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Transform
    )
    
    $result = $Configuration.Clone()
    
    foreach ($key in $Transform.Keys) {
        $value = $Transform[$key]
        
        if ($value -is [scriptblock]) {
            # Dynamic transformation
            Set-ConfigurationValue -Configuration $result -Path $key -Value (& $value $Configuration)
        } else {
            # Static replacement
            Set-ConfigurationValue -Configuration $result -Path $key -Value $value
        }
    }
    
    return $result
}

function New-SecurePassword {
    <#
    .SYNOPSIS
        Generates a secure password
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [int]$Length = 16,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Low', 'Medium', 'High')]
        [string]$Complexity = 'High'
    )
    
    $chars = @{
        Lower = 'abcdefghijklmnopqrstuvwxyz'
        Upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        Digits = '0123456789'
        Special = '!@#$%^&*()_+-=[]{}|;:,.<>?'
    }
    
    $pool = switch ($Complexity) {
        'Low' { $chars.Lower + $chars.Digits }
        'Medium' { $chars.Lower + $chars.Upper + $chars.Digits }
        'High' { $chars.Lower + $chars.Upper + $chars.Digits + $chars.Special }
    }
    
    $password = -join ((1..$Length) | ForEach-Object { $pool[(Get-Random -Maximum $pool.Length)] })
    
    return $password
}

function Send-CredentialRotationNotification {
    <#
    .SYNOPSIS
        Sends notification about credential rotation
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CredentialName,
        
        [Parameter(Mandatory = $true)]
        [string[]]$Users
    )
    
    $subject = "Credential Rotated: $CredentialName"
    $body = @"
The following credential has been rotated:

Credential: $CredentialName
Rotated At: $(Get-Date)
Rotated By: $env:USERNAME

Action Required:
- Update any applications or scripts using this credential
- Test connectivity with the new credential
- Report any issues immediately

This is an automated notification from the PowerShell Automation Platform.
"@
    
    Send-AdminNotification -Subject $subject -Body $body -Recipients $Users
}

function Save-ConfigurationProfiles {
    <#
    .SYNOPSIS
        Persists configuration profiles to disk
    #>
    [CmdletBinding()]
    param()
    
    $profilePath = Join-Path (Get-ConfigurationRoot) 'Profiles.json'
    $script:ConfigurationProfiles | ConvertTo-Json -Depth 10 | Set-Content -Path $profilePath
}

function Load-ConfigurationProfiles {
    <#
    .SYNOPSIS
        Loads configuration profiles from disk
    #>
    [CmdletBinding()]
    param()
    
    $profilePath = Join-Path (Get-ConfigurationRoot) 'Profiles.json'
    if (Test-Path $profilePath) {
        $profiles = Get-Content $profilePath -Raw | ConvertFrom-Json -AsHashtable
        $script:ConfigurationProfiles = $profiles
    }
}

#endregion

# Module initialization
Load-ConfigurationProfiles

# Export module members
Export-ModuleMember -Function @(
    # Configuration Loading
    'Get-Configuration',
    'Set-Configuration',
    'Import-Configuration',
    'Export-Configuration',
    
    # Schema Management
    'New-ConfigurationSchema',
    'Validate-Configuration',
    'Get-ConfigurationSchemaTemplate',
    'Test-ConfigurationCompliance',
    
    # Environment Management
    'Get-ConfigurationEnvironment',
    'Set-ConfigurationEnvironment',
    'New-ConfigurationEnvironment',
    'Copy-ConfigurationEnvironment',
    
    # Credential Management
    'Get-ConfiguredCredential',
    'Set-ConfiguredCredential',
    'Test-CredentialExpiration',
    'Rotate-ConfiguredCredentials',
    
    # Configuration Profiles
    'New-ConfigurationProfile',
    'Get-ConfigurationProfile',
    'Apply-ConfigurationProfile',
    'Remove-ConfigurationProfile'
)