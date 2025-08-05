function Get-AdminConfig {
    <#
    .SYNOPSIS
        Retrieves configuration from JSON files in the config directory.
    .DESCRIPTION
        Loads and caches configuration from JSON files. Supports both repository-relative
        and system-wide configuration paths. Returns default configurations if files don't exist.
    .PARAMETER ConfigName
        Name of the configuration file (without .json extension).
    .PARAMETER Force
        Forces reload of configuration even if cached.
    .PARAMETER ConfigPath
        Optional custom path to configuration directory.
    .EXAMPLE
        $emailConfig = Get-AdminConfig -ConfigName "email"
    .EXAMPLE
        $backupConfig = Get-AdminConfig -ConfigName "backup-config" -Force
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigName,

        [Parameter(Mandatory = $false)]
        [switch]$Force,

        [Parameter(Mandatory = $false)]
        [string]$ConfigPath
    )

    # Check cache first unless Force is specified
    if (-not $Force -and $script:ConfigCache.ContainsKey($ConfigName)) {
        Write-Verbose "Returning cached configuration for: $ConfigName"
        return $script:ConfigCache[$ConfigName]
    }

    # Determine config file path
    $configFileName = "$ConfigName.json"
    $configFilePath = $null

    # Priority order for config file locations
    $searchPaths = @()

    # 1. Custom path if provided
    if ($ConfigPath) {
        $searchPaths += Join-Path $ConfigPath $configFileName
    }

    # 2. Repository config directory (relative to module)
    $repoConfigPath = Join-Path $script:ModuleRoot '..\..\config' $configFileName
    if (Test-Path $repoConfigPath) {
        $searchPaths += (Resolve-Path $repoConfigPath).Path
    }

    # 3. System-wide config directory
    $systemConfigPath = Join-Path $env:ProgramData 'PSAutomation\config' $configFileName
    $searchPaths += $systemConfigPath

    # 4. User config directory
    $userConfigPath = Join-Path $env:APPDATA 'PSAutomation\config' $configFileName
    $searchPaths += $userConfigPath

    # Find first existing config file
    foreach ($path in $searchPaths) {
        if ($path -and (Test-Path $path)) {
            $configFilePath = $path
            Write-Verbose "Found configuration file at: $configFilePath"
            break
        }
    }

    if (-not $configFilePath) {
        # Return default configuration structure based on config name
        Write-Warning "Configuration file '$configFileName' not found. Using default configuration."
        
        $defaultConfig = switch ($ConfigName) {
            'email' {
                @{
                    SmtpServer = 'smtp.example.com'
                    SmtpPort = 587
                    UseSsl = $true
                    From = 'automation@example.com'
                    To = @('admin@example.com')
                    Cc = @()
                    Priority = 'Normal'
                }
            }
            'backup-config' {
                @{
                    Jobs = @(
                        @{
                            Name = 'DefaultBackup'
                            Type = 'FileSystem'
                            Source = 'C:\Data'
                            Destination = 'C:\Backups'
                            Compression = $true
                            Retention = 30
                        }
                    )
                }
            }
            'group-mappings' {
                @{
                    Mappings = @()
                }
            }
            default {
                @{}
            }
        }
        
        $script:ConfigCache[$ConfigName] = $defaultConfig
        return $defaultConfig
    }

    try {
        # Load configuration from JSON file
        $configContent = Get-Content -Path $configFilePath -Raw -ErrorAction Stop
        $config = $configContent | ConvertFrom-Json -ErrorAction Stop

        # Convert PSCustomObject to hashtable for easier manipulation
        $configHashtable = @{}
        $config.PSObject.Properties | ForEach-Object {
            $configHashtable[$_.Name] = $_.Value
        }

        # Cache the configuration
        $script:ConfigCache[$ConfigName] = $configHashtable
        
        Write-Verbose "Successfully loaded configuration from: $configFilePath"
        return $configHashtable
    }
    catch {
        Write-Error "Failed to load configuration from '$configFilePath': $_"
        return @{}
    }
}