<#
.SYNOPSIS
    PSConfiguration - Centralized configuration management module
.DESCRIPTION
    Provides comprehensive configuration management with schema validation,
    environment support, versioning, and secure value encryption.
.NOTES
    Version: 2.0.0
    Author: Enterprise Automation Team
#>

# Import dependencies
Import-Module PSCore -MinimumVersion 2.0.0

#region Module Variables
$script:PSConfigStore = @{
    BasePath = Join-Path $env:ProgramData 'PSConfiguration'
    ConfigPath = Join-Path $env:ProgramData 'PSConfiguration\Configs'
    SchemaPath = Join-Path $env:ProgramData 'PSConfiguration\Schemas'
    TemplatePath = Join-Path $env:ProgramData 'PSConfiguration\Templates'
    HistoryPath = Join-Path $env:ProgramData 'PSConfiguration\History'
    CurrentEnvironment = 'Production'
    LoadedConfigs = @{}
    ConfigCache = @{}
    SchemaCache = @{}
    ValidationRules = @{}
    EncryptionKey = $null
    Settings = @{
        EnableCaching = $true
        CacheTimeout = 300 # seconds
        EnableVersioning = $true
        MaxVersions = 10
        EnableSchemaValidation = $true
        AutoBackup = $true
        CompressHistory = $true
    }
}

$script:PSConfigEnvironment = 'Production'

# Configuration metadata
$script:ConfigMetadata = @{
    Version = '1.0.0'
    Schema = 'https://schemas.company.com/psconfig/v1'
    Created = $null
    Modified = $null
    Author = $null
    Description = $null
}
#endregion

#region Initialization
function Initialize-PSConfiguration {
    [CmdletBinding()]
    param()
    
    try {
        Write-PSLog "Initializing PSConfiguration module" -Level Info -Component 'PSConfiguration'
        
        # Create directory structure
        $directories = @(
            $script:PSConfigStore.BasePath
            $script:PSConfigStore.ConfigPath
            $script:PSConfigStore.SchemaPath
            $script:PSConfigStore.TemplatePath
            $script:PSConfigStore.HistoryPath
            (Join-Path $script:PSConfigStore.ConfigPath 'Production')
            (Join-Path $script:PSConfigStore.ConfigPath 'Staging')
            (Join-Path $script:PSConfigStore.ConfigPath 'Development')
            (Join-Path $script:PSConfigStore.ConfigPath 'Test')
        )
        
        foreach ($dir in $directories) {
            if (-not (Test-Path -Path $dir)) {
                New-Item -Path $dir -ItemType Directory -Force | Out-Null
            }
        }
        
        # Initialize encryption key if not exists
        $keyPath = Join-Path $script:PSConfigStore.BasePath 'config.key'
        if (-not (Test-Path -Path $keyPath)) {
            $key = New-Object byte[] 32
            [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($key)
            [System.IO.File]::WriteAllBytes($keyPath, $key)
            
            # Protect key file
            $acl = Get-Acl -Path $keyPath
            $acl.SetAccessRuleProtection($true, $false)
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $env:USERNAME, 'FullControl', 'Allow'
            )
            $acl.SetAccessRule($rule)
            Set-Acl -Path $keyPath -AclObject $acl
        }
        
        $script:PSConfigStore.EncryptionKey = [System.IO.File]::ReadAllBytes($keyPath)
        
        # Load default schemas
        Initialize-DefaultSchemas
        
        Write-PSLog "PSConfiguration initialization completed" -Level Info -Component 'PSConfiguration'
    }
    catch {
        Write-PSLog "Failed to initialize PSConfiguration: $_" -Level Error -Component 'PSConfiguration'
        throw
    }
}

function Initialize-DefaultSchemas {
    [CmdletBinding()]
    param()
    
    # Application configuration schema
    $appSchema = @{
        '$schema' = 'http://json-schema.org/draft-07/schema#'
        type = 'object'
        properties = @{
            application = @{
                type = 'object'
                properties = @{
                    name = @{ type = 'string'; minLength = 1 }
                    version = @{ type = 'string'; pattern = '^\d+\.\d+\.\d+$' }
                    environment = @{ type = 'string'; enum = @('Production', 'Staging', 'Development', 'Test') }
                }
                required = @('name', 'version', 'environment')
            }
            settings = @{
                type = 'object'
                additionalProperties = $true
            }
        }
        required = @('application')
    }
    
    # Database configuration schema
    $dbSchema = @{
        '$schema' = 'http://json-schema.org/draft-07/schema#'
        type = 'object'
        properties = @{
            database = @{
                type = 'object'
                properties = @{
                    server = @{ type = 'string'; minLength = 1 }
                    database = @{ type = 'string'; minLength = 1 }
                    authentication = @{ type = 'string'; enum = @('Windows', 'SQL', 'AAD') }
                    connectionTimeout = @{ type = 'integer'; minimum = 0; maximum = 300 }
                    commandTimeout = @{ type = 'integer'; minimum = 0; maximum = 3600 }
                }
                required = @('server', 'database', 'authentication')
            }
        }
        required = @('database')
    }
    
    # Service configuration schema
    $serviceSchema = @{
        '$schema' = 'http://json-schema.org/draft-07/schema#'
        type = 'object'
        properties = @{
            service = @{
                type = 'object'
                properties = @{
                    endpoint = @{ type = 'string'; format = 'uri' }
                    apiKey = @{ type = 'string'; minLength = 10 }
                    timeout = @{ type = 'integer'; minimum = 1000; maximum = 300000 }
                    retryCount = @{ type = 'integer'; minimum = 0; maximum = 10 }
                    throttleLimit = @{ type = 'integer'; minimum = 1; maximum = 1000 }
                }
                required = @('endpoint')
            }
        }
        required = @('service')
    }
    
    # Save default schemas
    @{
        'application' = $appSchema
        'database' = $dbSchema
        'service' = $serviceSchema
    } | ForEach-Object {
        $schemaPath = Join-Path $script:PSConfigStore.SchemaPath "$($_.Keys[0]).schema.json"
        if (-not (Test-Path -Path $schemaPath)) {
            $_.Values[0] | ConvertTo-Json -Depth 10 | Out-File -FilePath $schemaPath -Encoding UTF8
        }
    }
}
#endregion

#region Configuration Management
function Get-PSConfig {
    [CmdletBinding(DefaultParameterSetName = 'Name')]
    param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Name')]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Environment = $script:PSConfigEnvironment,
        
        [Parameter(Mandatory = $false)]
        [string]$Path,
        
        [Parameter(Mandatory = $false)]
        [switch]$NoCache,
        
        [Parameter(Mandatory = $false)]
        [switch]$Decrypt,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'List')]
        [switch]$ListAvailable
    )
    
    try {
        if ($ListAvailable) {
            return Get-AvailableConfigs -Environment $Environment
        }
        
        # Check cache first
        $cacheKey = "$Environment.$Name"
        if (-not $NoCache -and $script:PSConfigStore.ConfigCache.ContainsKey($cacheKey)) {
            $cached = $script:PSConfigStore.ConfigCache[$cacheKey]
            if ((Get-Date) -lt $cached.Expiry) {
                Write-PSLog "Returning cached configuration: $Name" -Level Debug -Component 'PSConfiguration'
                return $cached.Data
            }
        }
        
        # Determine config path
        if (-not $Path) {
            $Path = Join-Path $script:PSConfigStore.ConfigPath $Environment "$Name.json"
        }
        
        if (-not (Test-Path -Path $Path)) {
            throw "Configuration not found: $Name in environment $Environment"
        }
        
        # Load configuration
        $config = Get-Content -Path $Path -Raw | ConvertFrom-Json
        
        # Validate against schema if enabled
        if ($script:PSConfigStore.Settings.EnableSchemaValidation -and $config.PSObject.Properties['$schema']) {
            $schemaName = [System.IO.Path]::GetFileNameWithoutExtension($config.'$schema')
            if (Test-PSConfigSchema -Config $config -Schema $schemaName) {
                Write-PSLog "Configuration validated against schema: $schemaName" -Level Debug -Component 'PSConfiguration'
            }
        }
        
        # Decrypt secure values if requested
        if ($Decrypt) {
            $config = Unprotect-ConfigValues -Config $config
        }
        
        # Update cache
        if (-not $NoCache) {
            $script:PSConfigStore.ConfigCache[$cacheKey] = @{
                Data = $config
                Expiry = (Get-Date).AddSeconds($script:PSConfigStore.Settings.CacheTimeout)
            }
        }
        
        # Track loaded config
        $script:PSConfigStore.LoadedConfigs[$Name] = @{
            Path = $Path
            Environment = $Environment
            LoadedAt = Get-Date
        }
        
        Write-PSLog "Loaded configuration: $Name from $Environment" -Level Info -Component 'PSConfiguration'
        return $config
    }
    catch {
        Write-PSLog "Failed to get configuration '$Name': $_" -Level Error -Component 'PSConfiguration'
        throw
    }
}

function Set-PSConfig {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'Object')]
        [PSCustomObject]$Configuration,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'Path')]
        [string]$Path,
        
        [Parameter(Mandatory = $false)]
        [string]$Environment = $script:PSConfigEnvironment,
        
        [Parameter(Mandatory = $false)]
        [string]$Schema,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        
        [Parameter(Mandatory = $false)]
        [switch]$CreateBackup
    )
    
    try {
        # Load configuration from path if specified
        if ($PSCmdlet.ParameterSetName -eq 'Path') {
            if (-not (Test-Path -Path $Path)) {
                throw "Configuration file not found: $Path"
            }
            $Configuration = Get-Content -Path $Path -Raw | ConvertFrom-Json
        }
        
        # Validate schema if specified
        if ($Schema) {
            if (-not (Test-PSConfigSchema -Config $Configuration -Schema $Schema)) {
                throw "Configuration validation failed against schema: $Schema"
            }
            # Add schema reference
            $Configuration | Add-Member -NotePropertyName '$schema' -NotePropertyValue $Schema -Force
        }
        
        # Determine save path
        $savePath = Join-Path $script:PSConfigStore.ConfigPath $Environment "$Name.json"
        
        # Create backup if requested or if auto-backup is enabled
        if ($CreateBackup -or ($script:PSConfigStore.Settings.AutoBackup -and (Test-Path -Path $savePath))) {
            Backup-Configuration -Name $Name -Environment $Environment
        }
        
        # Check if exists and not forcing
        if ((Test-Path -Path $savePath) -and -not $Force) {
            if (-not $PSCmdlet.ShouldProcess($savePath, "Overwrite existing configuration")) {
                return
            }
        }
        
        # Add metadata
        $metadata = @{
            '_metadata' = @{
                version = '1.0.0'
                created = if (Test-Path -Path $savePath) { 
                    (Get-Item -Path $savePath).CreationTime 
                } else { 
                    Get-Date 
                }
                modified = Get-Date
                author = $env:USERNAME
                environment = $Environment
            }
        }
        
        # Merge metadata with configuration
        $configWithMetadata = Merge-PSConfig -Source $Configuration -Target $metadata
        
        # Save configuration
        $configWithMetadata | ConvertTo-Json -Depth 10 | Out-File -FilePath $savePath -Encoding UTF8
        
        # Clear cache for this config
        $cacheKey = "$Environment.$Name"
        if ($script:PSConfigStore.ConfigCache.ContainsKey($cacheKey)) {
            $script:PSConfigStore.ConfigCache.Remove($cacheKey)
        }
        
        Write-PSLog "Saved configuration: $Name to $Environment" -Level Info -Component 'PSConfiguration'
        
        return $configWithMetadata
    }
    catch {
        Write-PSLog "Failed to set configuration '$Name': $_" -Level Error -Component 'PSConfiguration'
        throw
    }
}

function New-PSConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Template,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Values = @{},
        
        [Parameter(Mandatory = $false)]
        [string]$Environment = $script:PSConfigEnvironment,
        
        [Parameter(Mandatory = $false)]
        [string]$Schema
    )
    
    try {
        # Check if already exists
        $configPath = Join-Path $script:PSConfigStore.ConfigPath $Environment "$Name.json"
        if (Test-Path -Path $configPath) {
            throw "Configuration already exists: $Name in environment $Environment"
        }
        
        # Create from template if specified
        if ($Template) {
            $config = Invoke-PSConfigTemplate -Template $Template -Values $Values
        }
        else {
            # Create empty configuration
            $config = [PSCustomObject]@{
                name = $Name
                environment = $Environment
                settings = [PSCustomObject]@{}
            }
        }
        
        # Set the configuration
        Set-PSConfig -Name $Name -Configuration $config -Environment $Environment -Schema $Schema -Force
        
        Write-PSLog "Created new configuration: $Name in $Environment" -Level Info -Component 'PSConfiguration'
        return $config
    }
    catch {
        Write-PSLog "Failed to create configuration '$Name': $_" -Level Error -Component 'PSConfiguration'
        throw
    }
}

function Remove-PSConfig {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Environment = $script:PSConfigEnvironment,
        
        [Parameter(Mandatory = $false)]
        [switch]$RemoveHistory
    )
    
    try {
        $configPath = Join-Path $script:PSConfigStore.ConfigPath $Environment "$Name.json"
        
        if (-not (Test-Path -Path $configPath)) {
            throw "Configuration not found: $Name in environment $Environment"
        }
        
        if ($PSCmdlet.ShouldProcess("$Name in $Environment", "Remove configuration")) {
            # Create final backup
            Backup-Configuration -Name $Name -Environment $Environment
            
            # Remove configuration file
            Remove-Item -Path $configPath -Force
            
            # Remove from cache
            $cacheKey = "$Environment.$Name"
            if ($script:PSConfigStore.ConfigCache.ContainsKey($cacheKey)) {
                $script:PSConfigStore.ConfigCache.Remove($cacheKey)
            }
            
            # Remove from loaded configs
            if ($script:PSConfigStore.LoadedConfigs.ContainsKey($Name)) {
                $script:PSConfigStore.LoadedConfigs.Remove($Name)
            }
            
            # Remove history if requested
            if ($RemoveHistory) {
                $historyPath = Join-Path $script:PSConfigStore.HistoryPath $Environment $Name
                if (Test-Path -Path $historyPath) {
                    Remove-Item -Path $historyPath -Recurse -Force
                }
            }
            
            Write-PSLog "Removed configuration: $Name from $Environment" -Level Info -Component 'PSConfiguration'
        }
    }
    catch {
        Write-PSLog "Failed to remove configuration '$Name': $_" -Level Error -Component 'PSConfiguration'
        throw
    }
}

function Test-PSConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Environment = $script:PSConfigEnvironment,
        
        [Parameter(Mandatory = $false)]
        [switch]$Detailed
    )
    
    try {
        $result = @{
            Exists = $false
            Valid = $false
            Schema = $null
            Environment = $Environment
            Path = $null
            Issues = @()
        }
        
        $configPath = Join-Path $script:PSConfigStore.ConfigPath $Environment "$Name.json"
        $result.Path = $configPath
        
        if (-not (Test-Path -Path $configPath)) {
            $result.Issues += "Configuration file not found"
            return $result
        }
        
        $result.Exists = $true
        
        try {
            $config = Get-Content -Path $configPath -Raw | ConvertFrom-Json
            
            # Check for schema
            if ($config.PSObject.Properties['$schema']) {
                $result.Schema = $config.'$schema'
                $schemaName = [System.IO.Path]::GetFileNameWithoutExtension($config.'$schema')
                
                if (Test-PSConfigSchema -Config $config -Schema $schemaName) {
                    $result.Valid = $true
                }
                else {
                    $result.Issues += "Schema validation failed"
                }
            }
            else {
                $result.Valid = $true
                $result.Issues += "No schema defined"
            }
        }
        catch {
            $result.Issues += "Invalid JSON format: $_"
        }
        
        if ($Detailed) {
            return $result
        }
        else {
            return $result.Valid
        }
    }
    catch {
        Write-PSLog "Failed to test configuration '$Name': $_" -Level Error -Component 'PSConfiguration'
        throw
    }
}

function Export-PSConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $false)]
        [string]$Environment = $script:PSConfigEnvironment,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeSchema,
        
        [Parameter(Mandatory = $false)]
        [switch]$Compress
    )
    
    try {
        $config = Get-PSConfig -Name $Name -Environment $Environment -NoCache
        
        if ($IncludeSchema -and $config.PSObject.Properties['$schema']) {
            $schemaName = [System.IO.Path]::GetFileNameWithoutExtension($config.'$schema')
            $schema = Get-PSConfigSchema -Name $schemaName
            
            $export = @{
                configuration = $config
                schema = $schema
                metadata = @{
                    exported = Get-Date
                    environment = $Environment
                    machine = $env:COMPUTERNAME
                    user = $env:USERNAME
                }
            }
            
            $content = $export | ConvertTo-Json -Depth 10
        }
        else {
            $content = $config | ConvertTo-Json -Depth 10
        }
        
        if ($Compress) {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($content)
            $ms = New-Object System.IO.MemoryStream
            $cs = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress)
            $cs.Write($bytes, 0, $bytes.Length)
            $cs.Close()
            
            [System.IO.File]::WriteAllBytes("$Path.gz", $ms.ToArray())
            $ms.Close()
            
            Write-PSLog "Exported compressed configuration to: $Path.gz" -Level Info -Component 'PSConfiguration'
        }
        else {
            $content | Out-File -FilePath $Path -Encoding UTF8
            Write-PSLog "Exported configuration to: $Path" -Level Info -Component 'PSConfiguration'
        }
    }
    catch {
        Write-PSLog "Failed to export configuration '$Name': $_" -Level Error -Component 'PSConfiguration'
        throw
    }
}

function Import-PSConfig {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $false)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Environment = $script:PSConfigEnvironment,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        
        [Parameter(Mandatory = $false)]
        [switch]$Validate
    )
    
    try {
        if (-not (Test-Path -Path $Path)) {
            throw "Import file not found: $Path"
        }
        
        # Check if compressed
        if ($Path -match '\.gz$') {
            $bytes = [System.IO.File]::ReadAllBytes($Path)
            $ms = New-Object System.IO.MemoryStream
            $ms.Write($bytes, 0, $bytes.Length)
            $ms.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null
            
            $gs = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
            $reader = New-Object System.IO.StreamReader($gs)
            $content = $reader.ReadToEnd()
            
            $reader.Close()
            $gs.Close()
            $ms.Close()
            
            $data = $content | ConvertFrom-Json
        }
        else {
            $data = Get-Content -Path $Path -Raw | ConvertFrom-Json
        }
        
        # Check if it's an export with schema
        if ($data.PSObject.Properties['configuration'] -and $data.PSObject.Properties['schema']) {
            $config = $data.configuration
            $schema = $data.schema
            
            # Import schema first
            if ($schema) {
                $schemaName = if ($Name) { $Name } else { "imported_$(Get-Date -Format 'yyyyMMddHHmmss')" }
                Set-PSConfigSchema -Name $schemaName -Schema $schema
            }
        }
        else {
            $config = $data
        }
        
        # Determine name
        if (-not $Name) {
            if ($config.PSObject.Properties['name']) {
                $Name = $config.name
            }
            else {
                $Name = [System.IO.Path]::GetFileNameWithoutExtension($Path)
            }
        }
        
        # Validate if requested
        if ($Validate -and $config.PSObject.Properties['$schema']) {
            $schemaName = [System.IO.Path]::GetFileNameWithoutExtension($config.'$schema')
            if (-not (Test-PSConfigSchema -Config $config -Schema $schemaName)) {
                throw "Configuration validation failed"
            }
        }
        
        if ($PSCmdlet.ShouldProcess("$Name in $Environment", "Import configuration")) {
            Set-PSConfig -Name $Name -Configuration $config -Environment $Environment -Force:$Force
            Write-PSLog "Imported configuration: $Name to $Environment" -Level Info -Component 'PSConfiguration'
        }
    }
    catch {
        Write-PSLog "Failed to import configuration from '$Path': $_" -Level Error -Component 'PSConfiguration'
        throw
    }
}

function Merge-PSConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Source,
        
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Target,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Overwrite', 'Preserve', 'Merge')]
        [string]$ConflictResolution = 'Overwrite'
    )
    
    function Merge-Object {
        param($Src, $Tgt, $Resolution)
        
        $result = [PSCustomObject]@{}
        
        # Add all target properties
        foreach ($prop in $Tgt.PSObject.Properties) {
            $result | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $prop.Value
        }
        
        # Merge source properties
        foreach ($prop in $Src.PSObject.Properties) {
            if ($result.PSObject.Properties[$prop.Name]) {
                # Property exists in both
                if ($prop.Value -is [PSCustomObject] -and $result.$($prop.Name) -is [PSCustomObject]) {
                    # Both are objects, merge recursively
                    $merged = Merge-Object -Src $prop.Value -Tgt $result.$($prop.Name) -Resolution $Resolution
                    $result.$($prop.Name) = $merged
                }
                elseif ($Resolution -eq 'Overwrite') {
                    $result.$($prop.Name) = $prop.Value
                }
                elseif ($Resolution -eq 'Merge' -and $prop.Value -is [Array] -and $result.$($prop.Name) -is [Array]) {
                    # Merge arrays
                    $result.$($prop.Name) = @($result.$($prop.Name)) + @($prop.Value) | Select-Object -Unique
                }
                # Preserve keeps target value
            }
            else {
                # Property only in source
                $result | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $prop.Value
            }
        }
        
        return $result
    }
    
    return Merge-Object -Src $Source -Tgt $Target -Resolution $ConflictResolution
}
#endregion

#region Environment Management
function Get-PSConfigEnvironment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$ListAvailable
    )
    
    if ($ListAvailable) {
        $environments = Get-ChildItem -Path $script:PSConfigStore.ConfigPath -Directory | 
            Select-Object -ExpandProperty Name
        
        $current = $script:PSConfigEnvironment
        
        $environments | ForEach-Object {
            [PSCustomObject]@{
                Name = $_
                IsCurrent = $_ -eq $current
                ConfigCount = (Get-ChildItem -Path (Join-Path $script:PSConfigStore.ConfigPath $_) -Filter '*.json' | Measure-Object).Count
            }
        }
    }
    else {
        return $script:PSConfigEnvironment
    }
}

function Set-PSConfigEnvironment {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Production', 'Staging', 'Development', 'Test')]
        [string]$Environment
    )
    
    if ($PSCmdlet.ShouldProcess($Environment, "Switch to environment")) {
        $script:PSConfigEnvironment = $Environment
        $script:PSConfigStore.CurrentEnvironment = $Environment
        
        # Clear cache when switching environments
        $script:PSConfigStore.ConfigCache.Clear()
        
        Write-PSLog "Switched to environment: $Environment" -Level Info -Component 'PSConfiguration'
        
        # Reload any auto-load configurations
        $autoLoadPath = Join-Path $script:PSConfigStore.ConfigPath $Environment '.autoload'
        if (Test-Path -Path $autoLoadPath) {
            $autoLoad = Get-Content -Path $autoLoadPath | Where-Object { $_ -notmatch '^\s*#' }
            foreach ($configName in $autoLoad) {
                try {
                    Get-PSConfig -Name $configName -Environment $Environment | Out-Null
                    Write-PSLog "Auto-loaded configuration: $configName" -Level Debug -Component 'PSConfiguration'
                }
                catch {
                    Write-PSLog "Failed to auto-load configuration '$configName': $_" -Level Warning -Component 'PSConfiguration'
                }
            }
        }
    }
}

function New-PSConfigEnvironment {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$CopyFrom,
        
        [Parameter(Mandatory = $false)]
        [string]$Description
    )
    
    try {
        $envPath = Join-Path $script:PSConfigStore.ConfigPath $Name
        
        if (Test-Path -Path $envPath) {
            throw "Environment already exists: $Name"
        }
        
        if ($PSCmdlet.ShouldProcess($Name, "Create new environment")) {
            New-Item -Path $envPath -ItemType Directory -Force | Out-Null
            
            # Copy configurations if source specified
            if ($CopyFrom) {
                $sourcePath = Join-Path $script:PSConfigStore.ConfigPath $CopyFrom
                if (-not (Test-Path -Path $sourcePath)) {
                    throw "Source environment not found: $CopyFrom"
                }
                
                Get-ChildItem -Path $sourcePath -Filter '*.json' | ForEach-Object {
                    Copy-Item -Path $_.FullName -Destination $envPath
                }
                
                Write-PSLog "Copied configurations from $CopyFrom to $Name" -Level Info -Component 'PSConfiguration'
            }
            
            # Create environment metadata
            $metadata = @{
                name = $Name
                created = Get-Date
                description = $Description
                createdBy = $env:USERNAME
            }
            
            $metadataPath = Join-Path $envPath '.environment'
            $metadata | ConvertTo-Json | Out-File -FilePath $metadataPath -Encoding UTF8
            
            Write-PSLog "Created new environment: $Name" -Level Info -Component 'PSConfiguration'
        }
    }
    catch {
        Write-PSLog "Failed to create environment '$Name': $_" -Level Error -Component 'PSConfiguration'
        throw
    }
}

function Switch-PSConfigEnvironment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Environment,
        
        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )
    
    # Alias for Set-PSConfigEnvironment
    Set-PSConfigEnvironment -Environment $Environment
    
    if ($PassThru) {
        Get-PSConfigEnvironment
    }
}
#endregion

#region Schema Management
function New-PSConfigSchema {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'Definition')]
        [hashtable]$Definition,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'FromConfig')]
        [PSCustomObject]$FromConfiguration,
        
        [Parameter(Mandatory = $false)]
        [string]$Description,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    try {
        $schemaPath = Join-Path $script:PSConfigStore.SchemaPath "$Name.schema.json"
        
        if ((Test-Path -Path $schemaPath) -and -not $Force) {
            throw "Schema already exists: $Name"
        }
        
        if ($PSCmdlet.ParameterSetName -eq 'FromConfig') {
            # Generate schema from configuration
            $schema = Generate-SchemaFromConfig -Config $FromConfiguration
        }
        else {
            # Use provided definition
            $schema = $Definition
        }
        
        # Ensure required properties
        if (-not $schema['$schema']) {
            $schema['$schema'] = 'http://json-schema.org/draft-07/schema#'
        }
        
        if ($Description) {
            $schema['description'] = $Description
        }
        
        # Save schema
        $schema | ConvertTo-Json -Depth 10 | Out-File -FilePath $schemaPath -Encoding UTF8
        
        # Clear schema cache
        if ($script:PSConfigStore.SchemaCache.ContainsKey($Name)) {
            $script:PSConfigStore.SchemaCache.Remove($Name)
        }
        
        Write-PSLog "Created schema: $Name" -Level Info -Component 'PSConfiguration'
        return $schema
    }
    catch {
        Write-PSLog "Failed to create schema '$Name': $_" -Level Error -Component 'PSConfiguration'
        throw
    }
}

function Get-PSConfigSchema {
    [CmdletBinding(DefaultParameterSetName = 'Name')]
    param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Name')]
        [string]$Name,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'List')]
        [switch]$ListAvailable
    )
    
    try {
        if ($ListAvailable) {
            $schemas = Get-ChildItem -Path $script:PSConfigStore.SchemaPath -Filter '*.schema.json' |
                ForEach-Object {
                    $schemaName = [System.IO.Path]::GetFileNameWithoutExtension($_.BaseName)
                    $schema = Get-Content -Path $_.FullName -Raw | ConvertFrom-Json
                    
                    [PSCustomObject]@{
                        Name = $schemaName
                        Description = $schema.description
                        Type = $schema.type
                        Path = $_.FullName
                    }
                }
            
            return $schemas
        }
        
        # Check cache
        if ($script:PSConfigStore.SchemaCache.ContainsKey($Name)) {
            return $script:PSConfigStore.SchemaCache[$Name]
        }
        
        $schemaPath = Join-Path $script:PSConfigStore.SchemaPath "$Name.schema.json"
        
        if (-not (Test-Path -Path $schemaPath)) {
            throw "Schema not found: $Name"
        }
        
        $schema = Get-Content -Path $schemaPath -Raw | ConvertFrom-Json
        
        # Cache schema
        $script:PSConfigStore.SchemaCache[$Name] = $schema
        
        return $schema
    }
    catch {
        Write-PSLog "Failed to get schema '$Name': $_" -Level Error -Component 'PSConfiguration'
        throw
    }
}

function Set-PSConfigSchema {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Schema,
        
        [Parameter(Mandatory = $false)]
        [switch]$UpdateConfigurations
    )
    
    try {
        $schemaPath = Join-Path $script:PSConfigStore.SchemaPath "$Name.schema.json"
        
        if ($PSCmdlet.ShouldProcess($Name, "Update schema")) {
            # Validate schema format
            if (-not $Schema.'$schema') {
                $Schema | Add-Member -NotePropertyName '$schema' -NotePropertyValue 'http://json-schema.org/draft-07/schema#'
            }
            
            # Save schema
            $Schema | ConvertTo-Json -Depth 10 | Out-File -FilePath $schemaPath -Encoding UTF8
            
            # Clear cache
            if ($script:PSConfigStore.SchemaCache.ContainsKey($Name)) {
                $script:PSConfigStore.SchemaCache.Remove($Name)
            }
            
            Write-PSLog "Updated schema: $Name" -Level Info -Component 'PSConfiguration'
            
            # Update configurations if requested
            if ($UpdateConfigurations) {
                $environments = Get-ChildItem -Path $script:PSConfigStore.ConfigPath -Directory
                $updated = 0
                
                foreach ($env in $environments) {
                    $configs = Get-ChildItem -Path $env.FullName -Filter '*.json'
                    
                    foreach ($configFile in $configs) {
                        try {
                            $config = Get-Content -Path $configFile.FullName -Raw | ConvertFrom-Json
                            
                            if ($config.'$schema' -and $config.'$schema' -match $Name) {
                                # Update schema reference
                                $config.'$schema' = $Name
                                $config | ConvertTo-Json -Depth 10 | Out-File -FilePath $configFile.FullName -Encoding UTF8
                                $updated++
                            }
                        }
                        catch {
                            Write-PSLog "Failed to update configuration '$($configFile.Name)': $_" -Level Warning -Component 'PSConfiguration'
                        }
                    }
                }
                
                Write-PSLog "Updated $updated configurations with new schema" -Level Info -Component 'PSConfiguration'
            }
        }
    }
    catch {
        Write-PSLog "Failed to set schema '$Name': $_" -Level Error -Component 'PSConfiguration'
        throw
    }
}

function Test-PSConfigSchema {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config,
        
        [Parameter(Mandatory = $true)]
        [string]$Schema,
        
        [Parameter(Mandatory = $false)]
        [switch]$Detailed
    )
    
    try {
        # Load schema
        $schemaObj = if ($Schema -match '\.json$') {
            Get-Content -Path $Schema -Raw | ConvertFrom-Json
        }
        else {
            Get-PSConfigSchema -Name $Schema
        }
        
        # Simple validation (would use a proper JSON Schema validator in production)
        $valid = $true
        $errors = @()
        
        # Check required properties
        if ($schemaObj.required) {
            foreach ($req in $schemaObj.required) {
                if (-not $Config.PSObject.Properties[$req]) {
                    $valid = $false
                    $errors += "Missing required property: $req"
                }
            }
        }
        
        # Check property types
        if ($schemaObj.properties) {
            foreach ($prop in $Config.PSObject.Properties) {
                if ($schemaObj.properties.PSObject.Properties[$prop.Name]) {
                    $schemaProp = $schemaObj.properties.$($prop.Name)
                    
                    # Type validation
                    if ($schemaProp.type) {
                        $actualType = switch ($prop.Value.GetType().Name) {
                            'String' { 'string' }
                            'Int32' { 'integer' }
                            'Int64' { 'integer' }
                            'Double' { 'number' }
                            'Boolean' { 'boolean' }
                            'PSCustomObject' { 'object' }
                            'Object[]' { 'array' }
                            default { 'unknown' }
                        }
                        
                        if ($actualType -ne $schemaProp.type -and $actualType -ne 'unknown') {
                            $valid = $false
                            $errors += "Property '$($prop.Name)' type mismatch: expected $($schemaProp.type), got $actualType"
                        }
                    }
                    
                    # Enum validation
                    if ($schemaProp.enum -and $prop.Value -notin $schemaProp.enum) {
                        $valid = $false
                        $errors += "Property '$($prop.Name)' value '$($prop.Value)' not in allowed values: $($schemaProp.enum -join ', ')"
                    }
                    
                    # Pattern validation
                    if ($schemaProp.pattern -and $prop.Value -is [string]) {
                        if ($prop.Value -notmatch $schemaProp.pattern) {
                            $valid = $false
                            $errors += "Property '$($prop.Name)' value does not match pattern: $($schemaProp.pattern)"
                        }
                    }
                }
            }
        }
        
        if ($Detailed) {
            return @{
                Valid = $valid
                Errors = $errors
                Schema = $Schema
            }
        }
        else {
            if (-not $valid) {
                Write-PSLog "Schema validation failed: $($errors -join '; ')" -Level Warning -Component 'PSConfiguration'
            }
            return $valid
        }
    }
    catch {
        Write-PSLog "Failed to validate against schema '$Schema': $_" -Level Error -Component 'PSConfiguration'
        throw
    }
}

function Export-PSConfigSchema {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeExamples
    )
    
    try {
        $schema = Get-PSConfigSchema -Name $Name
        
        if ($IncludeExamples) {
            # Find configurations using this schema
            $examples = @()
            $environments = Get-ChildItem -Path $script:PSConfigStore.ConfigPath -Directory
            
            foreach ($env in $environments) {
                $configs = Get-ChildItem -Path $env.FullName -Filter '*.json'
                
                foreach ($configFile in $configs) {
                    try {
                        $config = Get-Content -Path $configFile.FullName -Raw | ConvertFrom-Json
                        
                        if ($config.'$schema' -and $config.'$schema' -match $Name) {
                            $examples += @{
                                name = [System.IO.Path]::GetFileNameWithoutExtension($configFile.Name)
                                environment = $env.Name
                                content = $config
                            }
                        }
                    }
                    catch {
                        # Skip invalid configs
                    }
                }
            }
            
            $export = @{
                schema = $schema
                examples = $examples
            }
            
            $export | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
        }
        else {
            $schema | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
        }
        
        Write-PSLog "Exported schema '$Name' to: $Path" -Level Info -Component 'PSConfiguration'
    }
    catch {
        Write-PSLog "Failed to export schema '$Name': $_" -Level Error -Component 'PSConfiguration'
        throw
    }
}
#endregion

#region Template Management
function New-PSConfigTemplate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Template,
        
        [Parameter(Mandatory = $false)]
        [string]$Description,
        
        [Parameter(Mandatory = $false)]
        [string[]]$RequiredValues,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$DefaultValues = @{}
    )
    
    try {
        $templatePath = Join-Path $script:PSConfigStore.TemplatePath "$Name.template.json"
        
        if (Test-Path -Path $templatePath) {
            throw "Template already exists: $Name"
        }
        
        # Create template metadata
        $templateData = @{
            metadata = @{
                name = $Name
                description = $Description
                created = Get-Date
                author = $env:USERNAME
                requiredValues = $RequiredValues
                defaultValues = $DefaultValues
            }
            template = $Template
        }
        
        $templateData | ConvertTo-Json -Depth 10 | Out-File -FilePath $templatePath -Encoding UTF8
        
        Write-PSLog "Created template: $Name" -Level Info -Component 'PSConfiguration'
    }
    catch {
        Write-PSLog "Failed to create template '$Name': $_" -Level Error -Component 'PSConfiguration'
        throw
    }
}

function Get-PSConfigTemplate {
    [CmdletBinding(DefaultParameterSetName = 'Name')]
    param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Name')]
        [string]$Name,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'List')]
        [switch]$ListAvailable
    )
    
    try {
        if ($ListAvailable) {
            $templates = Get-ChildItem -Path $script:PSConfigStore.TemplatePath -Filter '*.template.json' |
                ForEach-Object {
                    $templateName = [System.IO.Path]::GetFileNameWithoutExtension($_.BaseName)
                    $templateData = Get-Content -Path $_.FullName -Raw | ConvertFrom-Json
                    
                    [PSCustomObject]@{
                        Name = $templateName
                        Description = $templateData.metadata.description
                        RequiredValues = $templateData.metadata.requiredValues
                        Created = $templateData.metadata.created
                        Author = $templateData.metadata.author
                    }
                }
            
            return $templates
        }
        
        $templatePath = Join-Path $script:PSConfigStore.TemplatePath "$Name.template.json"
        
        if (-not (Test-Path -Path $templatePath)) {
            throw "Template not found: $Name"
        }
        
        $templateData = Get-Content -Path $templatePath -Raw | ConvertFrom-Json
        return $templateData
    }
    catch {
        Write-PSLog "Failed to get template '$Name': $_" -Level Error -Component 'PSConfiguration'
        throw
    }
}

function Invoke-PSConfigTemplate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Template,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Values = @{},
        
        [Parameter(Mandatory = $false)]
        [switch]$ValidateOnly
    )
    
    try {
        $templateData = Get-PSConfigTemplate -Name $Template
        
        # Merge with default values
        $mergedValues = @{}
        if ($templateData.metadata.defaultValues) {
            foreach ($key in $templateData.metadata.defaultValues.Keys) {
                $mergedValues[$key] = $templateData.metadata.defaultValues[$key]
            }
        }
        
        foreach ($key in $Values.Keys) {
            $mergedValues[$key] = $Values[$key]
        }
        
        # Check required values
        if ($templateData.metadata.requiredValues) {
            foreach ($required in $templateData.metadata.requiredValues) {
                if (-not $mergedValues.ContainsKey($required)) {
                    throw "Missing required value: $required"
                }
            }
        }
        
        if ($ValidateOnly) {
            return $true
        }
        
        # Process template
        $config = Process-Template -Template $templateData.template -Values $mergedValues
        
        return $config
    }
    catch {
        Write-PSLog "Failed to invoke template '$Template': $_" -Level Error -Component 'PSConfiguration'
        throw
    }
}

function Process-Template {
    param($Template, $Values)
    
    if ($Template -is [string]) {
        # Replace placeholders
        $result = $Template
        foreach ($key in $Values.Keys) {
            $result = $result -replace "\{\{$key\}\}", $Values[$key]
        }
        return $result
    }
    elseif ($Template -is [PSCustomObject]) {
        $result = [PSCustomObject]@{}
        
        foreach ($prop in $Template.PSObject.Properties) {
            $processedValue = Process-Template -Template $prop.Value -Values $Values
            $result | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $processedValue
        }
        
        return $result
    }
    elseif ($Template -is [Array]) {
        return $Template | ForEach-Object { Process-Template -Template $_ -Values $Values }
    }
    else {
        return $Template
    }
}
#endregion

#region Secure Configuration
function Protect-PSConfigValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Value,
        
        [Parameter(Mandatory = $false)]
        [string]$Purpose = 'PSConfiguration'
    )
    
    process {
        try {
            $secureString = ConvertTo-SecureString -String $Value -AsPlainText -Force
            $encrypted = ConvertFrom-SecureString -SecureString $secureString
            
            return @{
                _encrypted = $true
                _purpose = $Purpose
                _value = $encrypted
                _timestamp = Get-Date
                _user = $env:USERNAME
            }
        }
        catch {
            Write-PSLog "Failed to protect value: $_" -Level Error -Component 'PSConfiguration'
            throw
        }
    }
}

function Unprotect-PSConfigValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        $EncryptedValue
    )
    
    process {
        try {
            if ($EncryptedValue -is [PSCustomObject] -and $EncryptedValue._encrypted) {
                $secureString = ConvertTo-SecureString -String $EncryptedValue._value
                $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
                $value = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                
                return $value
            }
            else {
                return $EncryptedValue
            }
        }
        catch {
            Write-PSLog "Failed to unprotect value: $_" -Level Error -Component 'PSConfiguration'
            throw
        }
    }
}

function New-PSConfigSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [securestring]$SecureValue,
        
        [Parameter(Mandatory = $false)]
        [string]$Description,
        
        [Parameter(Mandatory = $false)]
        [datetime]$ExpiresOn
    )
    
    try {
        $secretPath = Join-Path $script:PSConfigStore.BasePath 'Secrets'
        if (-not (Test-Path -Path $secretPath)) {
            New-Item -Path $secretPath -ItemType Directory -Force | Out-Null
        }
        
        $secretFile = Join-Path $secretPath "$Name.secret"
        
        $secret = @{
            name = $Name
            description = $Description
            created = Get-Date
            expires = $ExpiresOn
            value = ConvertFrom-SecureString -SecureString $SecureValue
            creator = $env:USERNAME
        }
        
        $secret | Export-Clixml -Path $secretFile
        
        # Protect file
        $acl = Get-Acl -Path $secretFile
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $env:USERNAME, 'FullControl', 'Allow'
        )
        $acl.SetAccessRule($rule)
        Set-Acl -Path $secretFile -AclObject $acl
        
        Write-PSLog "Created secret: $Name" -Level Info -Component 'PSConfiguration'
    }
    catch {
        Write-PSLog "Failed to create secret '$Name': $_" -Level Error -Component 'PSConfiguration'
        throw
    }
}

function Get-PSConfigSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [switch]$AsPlainText
    )
    
    try {
        $secretFile = Join-Path $script:PSConfigStore.BasePath 'Secrets' "$Name.secret"
        
        if (-not (Test-Path -Path $secretFile)) {
            throw "Secret not found: $Name"
        }
        
        $secret = Import-Clixml -Path $secretFile
        
        # Check expiration
        if ($secret.expires -and (Get-Date) -gt $secret.expires) {
            Write-PSLog "Secret '$Name' has expired" -Level Warning -Component 'PSConfiguration'
            throw "Secret has expired"
        }
        
        $secureString = ConvertTo-SecureString -String $secret.value
        
        if ($AsPlainText) {
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
            $plainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            return $plainText
        }
        else {
            return $secureString
        }
    }
    catch {
        Write-PSLog "Failed to get secret '$Name': $_" -Level Error -Component 'PSConfiguration'
        throw
    }
}

function Unprotect-ConfigValues {
    param($Config)
    
    if ($Config -is [PSCustomObject]) {
        $result = [PSCustomObject]@{}
        
        foreach ($prop in $Config.PSObject.Properties) {
            if ($prop.Value -is [PSCustomObject] -and $prop.Value._encrypted) {
                $decrypted = Unprotect-PSConfigValue -EncryptedValue $prop.Value
                $result | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $decrypted
            }
            else {
                $unprotected = Unprotect-ConfigValues -Config $prop.Value
                $result | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $unprotected
            }
        }
        
        return $result
    }
    elseif ($Config -is [Array]) {
        return $Config | ForEach-Object { Unprotect-ConfigValues -Config $_ }
    }
    else {
        return $Config
    }
}
#endregion

#region Configuration History
function Get-PSConfigHistory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Environment = $script:PSConfigEnvironment,
        
        [Parameter(Mandatory = $false)]
        [int]$Last = 10
    )
    
    try {
        $historyPath = Join-Path $script:PSConfigStore.HistoryPath $Environment $Name
        
        if (-not (Test-Path -Path $historyPath)) {
            Write-PSLog "No history found for configuration: $Name" -Level Warning -Component 'PSConfiguration'
            return @()
        }
        
        $versions = Get-ChildItem -Path $historyPath -Filter '*.json' | 
            Sort-Object -Property LastWriteTime -Descending |
            Select-Object -First $Last
        
        $history = $versions | ForEach-Object {
            $version = Get-Content -Path $_.FullName -Raw | ConvertFrom-Json
            
            [PSCustomObject]@{
                Version = [System.IO.Path]::GetFileNameWithoutExtension($_.Name)
                Modified = $_.LastWriteTime
                ModifiedBy = $version._metadata.author
                Size = $_.Length
                Path = $_.FullName
            }
        }
        
        return $history
    }
    catch {
        Write-PSLog "Failed to get history for '$Name': $_" -Level Error -Component 'PSConfiguration'
        throw
    }
}

function Restore-PSConfigVersion {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [string]$Version,
        
        [Parameter(Mandatory = $false)]
        [string]$Environment = $script:PSConfigEnvironment
    )
    
    try {
        $historyPath = Join-Path $script:PSConfigStore.HistoryPath $Environment $Name "$Version.json"
        
        if (-not (Test-Path -Path $historyPath)) {
            throw "Version not found: $Version for configuration $Name"
        }
        
        if ($PSCmdlet.ShouldProcess("$Name version $Version", "Restore configuration")) {
            # Backup current version first
            Backup-Configuration -Name $Name -Environment $Environment
            
            # Restore version
            $config = Get-Content -Path $historyPath -Raw | ConvertFrom-Json
            Set-PSConfig -Name $Name -Configuration $config -Environment $Environment -Force
            
            Write-PSLog "Restored configuration '$Name' to version: $Version" -Level Info -Component 'PSConfiguration'
        }
    }
    catch {
        Write-PSLog "Failed to restore version '$Version' for '$Name': $_" -Level Error -Component 'PSConfiguration'
        throw
    }
}

function Compare-PSConfigVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [string]$Version1,
        
        [Parameter(Mandatory = $true)]
        [string]$Version2,
        
        [Parameter(Mandatory = $false)]
        [string]$Environment = $script:PSConfigEnvironment
    )
    
    try {
        $historyPath = Join-Path $script:PSConfigStore.HistoryPath $Environment $Name
        
        # Handle 'current' as a special version
        if ($Version1 -eq 'current') {
            $config1 = Get-PSConfig -Name $Name -Environment $Environment -NoCache
        }
        else {
            $path1 = Join-Path $historyPath "$Version1.json"
            if (-not (Test-Path -Path $path1)) {
                throw "Version not found: $Version1"
            }
            $config1 = Get-Content -Path $path1 -Raw | ConvertFrom-Json
        }
        
        if ($Version2 -eq 'current') {
            $config2 = Get-PSConfig -Name $Name -Environment $Environment -NoCache
        }
        else {
            $path2 = Join-Path $historyPath "$Version2.json"
            if (-not (Test-Path -Path $path2)) {
                throw "Version not found: $Version2"
            }
            $config2 = Get-Content -Path $path2 -Raw | ConvertFrom-Json
        }
        
        # Compare configurations
        $differences = Compare-Configurations -Config1 $config1 -Config2 $config2
        
        return $differences
    }
    catch {
        Write-PSLog "Failed to compare versions: $_" -Level Error -Component 'PSConfiguration'
        throw
    }
}

function Backup-Configuration {
    param(
        [string]$Name,
        [string]$Environment
    )
    
    try {
        $configPath = Join-Path $script:PSConfigStore.ConfigPath $Environment "$Name.json"
        if (-not (Test-Path -Path $configPath)) {
            return
        }
        
        $historyPath = Join-Path $script:PSConfigStore.HistoryPath $Environment $Name
        if (-not (Test-Path -Path $historyPath)) {
            New-Item -Path $historyPath -ItemType Directory -Force | Out-Null
        }
        
        # Generate version number
        $timestamp = Get-Date -Format 'yyyyMMddHHmmss'
        $version = "v$timestamp"
        
        # Copy to history
        $backupPath = Join-Path $historyPath "$version.json"
        Copy-Item -Path $configPath -Destination $backupPath
        
        # Clean up old versions if needed
        if ($script:PSConfigStore.Settings.MaxVersions -gt 0) {
            $versions = Get-ChildItem -Path $historyPath -Filter '*.json' | 
                Sort-Object -Property LastWriteTime -Descending
            
            if ($versions.Count -gt $script:PSConfigStore.Settings.MaxVersions) {
                $toDelete = $versions | Select-Object -Skip $script:PSConfigStore.Settings.MaxVersions
                $toDelete | Remove-Item -Force
            }
        }
        
        Write-PSLog "Created backup version $version for configuration: $Name" -Level Debug -Component 'PSConfiguration'
    }
    catch {
        Write-PSLog "Failed to backup configuration '$Name': $_" -Level Warning -Component 'PSConfiguration'
    }
}

function Compare-Configurations {
    param($Config1, $Config2, $Path = '')
    
    $differences = @()
    
    # Get all properties from both configs
    $allProps = @()
    if ($Config1 -is [PSCustomObject]) {
        $allProps += $Config1.PSObject.Properties.Name
    }
    if ($Config2 -is [PSCustomObject]) {
        $allProps += $Config2.PSObject.Properties.Name
    }
    $allProps = $allProps | Select-Object -Unique
    
    foreach ($prop in $allProps) {
        $currentPath = if ($Path) { "$Path.$prop" } else { $prop }
        
        $val1 = if ($Config1 -is [PSCustomObject] -and $Config1.PSObject.Properties[$prop]) { 
            $Config1.$prop 
        } else { 
            $null 
        }
        
        $val2 = if ($Config2 -is [PSCustomObject] -and $Config2.PSObject.Properties[$prop]) { 
            $Config2.$prop 
        } else { 
            $null 
        }
        
        if ($null -eq $val1 -and $null -ne $val2) {
            $differences += [PSCustomObject]@{
                Path = $currentPath
                Type = 'Added'
                Value1 = $null
                Value2 = $val2
            }
        }
        elseif ($null -ne $val1 -and $null -eq $val2) {
            $differences += [PSCustomObject]@{
                Path = $currentPath
                Type = 'Removed'
                Value1 = $val1
                Value2 = $null
            }
        }
        elseif ($val1 -is [PSCustomObject] -and $val2 -is [PSCustomObject]) {
            # Recurse into objects
            $differences += Compare-Configurations -Config1 $val1 -Config2 $val2 -Path $currentPath
        }
        elseif ($val1 -ne $val2) {
            $differences += [PSCustomObject]@{
                Path = $currentPath
                Type = 'Changed'
                Value1 = $val1
                Value2 = $val2
            }
        }
    }
    
    return $differences
}
#endregion

#region Validation
function Test-PSConfigValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Value,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('String', 'Integer', 'Number', 'Boolean', 'Array', 'Object', 'Email', 'Url', 'Path', 'IPAddress', 'FQDN')]
        [string]$Type,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Constraints = @{}
    )
    
    try {
        $valid = $true
        $errors = @()
        
        # Type validation
        switch ($Type) {
            'String' {
                if ($Value -isnot [string]) {
                    $valid = $false
                    $errors += "Value is not a string"
                }
                else {
                    if ($Constraints.MinLength -and $Value.Length -lt $Constraints.MinLength) {
                        $valid = $false
                        $errors += "String length is less than minimum: $($Constraints.MinLength)"
                    }
                    if ($Constraints.MaxLength -and $Value.Length -gt $Constraints.MaxLength) {
                        $valid = $false
                        $errors += "String length exceeds maximum: $($Constraints.MaxLength)"
                    }
                    if ($Constraints.Pattern -and $Value -notmatch $Constraints.Pattern) {
                        $valid = $false
                        $errors += "String does not match pattern: $($Constraints.Pattern)"
                    }
                }
            }
            
            'Integer' {
                if ($Value -isnot [int] -and $Value -isnot [long]) {
                    $valid = $false
                    $errors += "Value is not an integer"
                }
                else {
                    if ($Constraints.Minimum -and $Value -lt $Constraints.Minimum) {
                        $valid = $false
                        $errors += "Value is less than minimum: $($Constraints.Minimum)"
                    }
                    if ($Constraints.Maximum -and $Value -gt $Constraints.Maximum) {
                        $valid = $false
                        $errors += "Value exceeds maximum: $($Constraints.Maximum)"
                    }
                }
            }
            
            'Number' {
                if ($Value -isnot [double] -and $Value -isnot [decimal] -and $Value -isnot [int]) {
                    $valid = $false
                    $errors += "Value is not a number"
                }
            }
            
            'Boolean' {
                if ($Value -isnot [bool]) {
                    $valid = $false
                    $errors += "Value is not a boolean"
                }
            }
            
            'Array' {
                if ($Value -isnot [array]) {
                    $valid = $false
                    $errors += "Value is not an array"
                }
                else {
                    if ($Constraints.MinItems -and $Value.Count -lt $Constraints.MinItems) {
                        $valid = $false
                        $errors += "Array has fewer items than minimum: $($Constraints.MinItems)"
                    }
                    if ($Constraints.MaxItems -and $Value.Count -gt $Constraints.MaxItems) {
                        $valid = $false
                        $errors += "Array has more items than maximum: $($Constraints.MaxItems)"
                    }
                }
            }
            
            'Object' {
                if ($Value -isnot [PSCustomObject] -and $Value -isnot [hashtable]) {
                    $valid = $false
                    $errors += "Value is not an object"
                }
            }
            
            'Email' {
                if ($Value -notmatch '^[\w\.-]+@[\w\.-]+\.\w+$') {
                    $valid = $false
                    $errors += "Value is not a valid email address"
                }
            }
            
            'Url' {
                if ($Value -notmatch '^https?://') {
                    $valid = $false
                    $errors += "Value is not a valid URL"
                }
            }
            
            'Path' {
                if ($Constraints.MustExist -and -not (Test-Path -Path $Value)) {
                    $valid = $false
                    $errors += "Path does not exist: $Value"
                }
            }
            
            'IPAddress' {
                try {
                    [System.Net.IPAddress]::Parse($Value) | Out-Null
                }
                catch {
                    $valid = $false
                    $errors += "Value is not a valid IP address"
                }
            }
            
            'FQDN' {
                if ($Value -notmatch '^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$') {
                    $valid = $false
                    $errors += "Value is not a valid FQDN"
                }
            }
        }
        
        return @{
            Valid = $valid
            Errors = $errors
        }
    }
    catch {
        Write-PSLog "Failed to validate value: $_" -Level Error -Component 'PSConfiguration'
        throw
    }
}

function Get-PSConfigValidation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    
    if ($script:PSConfigStore.ValidationRules.ContainsKey($Name)) {
        return $script:PSConfigStore.ValidationRules[$Name]
    }
    else {
        return @()
    }
}

function Add-PSConfigValidation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [string]$Property,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('String', 'Integer', 'Number', 'Boolean', 'Array', 'Object', 'Email', 'Url', 'Path', 'IPAddress', 'FQDN')]
        [string]$Type,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Constraints = @{},
        
        [Parameter(Mandatory = $false)]
        [scriptblock]$CustomValidation
    )
    
    try {
        if (-not $script:PSConfigStore.ValidationRules.ContainsKey($Name)) {
            $script:PSConfigStore.ValidationRules[$Name] = @()
        }
        
        $rule = @{
            Property = $Property
            Type = $Type
            Constraints = $Constraints
            CustomValidation = $CustomValidation
        }
        
        $script:PSConfigStore.ValidationRules[$Name] += $rule
        
        Write-PSLog "Added validation rule for '$Name.$Property'" -Level Info -Component 'PSConfiguration'
    }
    catch {
        Write-PSLog "Failed to add validation rule: $_" -Level Error -Component 'PSConfiguration'
        throw
    }
}
#endregion

#region Helper Functions
function Get-AvailableConfigs {
    param([string]$Environment)
    
    $configPath = Join-Path $script:PSConfigStore.ConfigPath $Environment
    
    if (-not (Test-Path -Path $configPath)) {
        return @()
    }
    
    $configs = Get-ChildItem -Path $configPath -Filter '*.json' | ForEach-Object {
        $config = Get-Content -Path $_.FullName -Raw | ConvertFrom-Json
        
        [PSCustomObject]@{
            Name = [System.IO.Path]::GetFileNameWithoutExtension($_.Name)
            Environment = $Environment
            Schema = if ($config.PSObject.Properties['$schema']) { $config.'$schema' } else { $null }
            Modified = $_.LastWriteTime
            Size = $_.Length
            Path = $_.FullName
        }
    }
    
    return $configs
}

function Generate-SchemaFromConfig {
    param($Config)
    
    $schema = @{
        '$schema' = 'http://json-schema.org/draft-07/schema#'
        type = 'object'
        properties = @{}
        required = @()
    }
    
    foreach ($prop in $Config.PSObject.Properties) {
        $propSchema = @{}
        
        # Determine type
        $type = switch ($prop.Value.GetType().Name) {
            'String' { 'string' }
            'Int32' { 'integer' }
            'Int64' { 'integer' }
            'Double' { 'number' }
            'Boolean' { 'boolean' }
            'PSCustomObject' { 'object' }
            'Object[]' { 'array' }
            default { 'string' }
        }
        
        $propSchema['type'] = $type
        
        # Add constraints based on value
        if ($type -eq 'string' -and $prop.Value) {
            $propSchema['minLength'] = 1
        }
        
        if ($type -eq 'object' -and $prop.Value -is [PSCustomObject]) {
            # Recursively generate schema for nested objects
            $nestedSchema = Generate-SchemaFromConfig -Config $prop.Value
            $propSchema = $nestedSchema
        }
        
        $schema.properties[$prop.Name] = $propSchema
        
        # Assume all properties are required
        $schema.required += $prop.Name
    }
    
    return $schema
}
#endregion

#region Module Initialization
Initialize-PSConfiguration

# Export module members
Export-ModuleMember -Function @(
    # Configuration Management
    'Get-PSConfig'
    'Set-PSConfig'
    'New-PSConfig'
    'Remove-PSConfig'
    'Test-PSConfig'
    'Export-PSConfig'
    'Import-PSConfig'
    'Merge-PSConfig'
    
    # Environment Management
    'Get-PSConfigEnvironment'
    'Set-PSConfigEnvironment'
    'New-PSConfigEnvironment'
    'Switch-PSConfigEnvironment'
    
    # Schema Management
    'New-PSConfigSchema'
    'Get-PSConfigSchema'
    'Set-PSConfigSchema'
    'Test-PSConfigSchema'
    'Export-PSConfigSchema'
    
    # Template Management
    'New-PSConfigTemplate'
    'Get-PSConfigTemplate'
    'Invoke-PSConfigTemplate'
    
    # Secure Configuration
    'Protect-PSConfigValue'
    'Unprotect-PSConfigValue'
    'New-PSConfigSecret'
    'Get-PSConfigSecret'
    
    # Configuration History
    'Get-PSConfigHistory'
    'Restore-PSConfigVersion'
    'Compare-PSConfigVersion'
    
    # Validation
    'Test-PSConfigValue'
    'Get-PSConfigValidation'
    'Add-PSConfigValidation'
) -Variable @(
    'PSConfigStore'
    'PSConfigEnvironment'
) -Alias @(
    'getconfig'
    'setconfig'
    'switchenv'
)
#endregion