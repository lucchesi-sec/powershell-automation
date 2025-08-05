function Set-AdminConfig {
    <#
    .SYNOPSIS
        Sets or updates configuration values.
    .DESCRIPTION
        Updates configuration settings in JSON files or creates new configuration files.
        Supports both updating existing configurations and creating new ones.
    .PARAMETER ConfigName
        Name of the configuration file (without .json extension).
    .PARAMETER Settings
        Hashtable of settings to update or set.
    .PARAMETER ConfigPath
        Optional custom path to configuration directory.
    .PARAMETER Force
        Overwrites existing configuration completely instead of merging.
    .EXAMPLE
        Set-AdminConfig -ConfigName "email" -Settings @{SmtpServer="mail.example.com"; SmtpPort=587}
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigName,

        [Parameter(Mandatory = $true)]
        [hashtable]$Settings,

        [Parameter(Mandatory = $false)]
        [string]$ConfigPath,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    try {
        Write-AdminLog -Message "Updating configuration: $ConfigName" -Level Info

        # Determine config file path
        $configFileName = "$ConfigName.json"
        $configFilePath = $null

        if ($ConfigPath) {
            $configFilePath = Join-Path $ConfigPath $configFileName
        } else {
            # Default to system-wide config directory
            $systemConfigDir = Join-Path $env:ProgramData 'PSAutomation\config'
            if (-not (Test-Path $systemConfigDir)) {
                New-Item -Path $systemConfigDir -ItemType Directory -Force | Out-Null
            }
            $configFilePath = Join-Path $systemConfigDir $configFileName
        }

        # Load existing configuration if it exists and Force is not specified
        $currentConfig = @{}
        if ((Test-Path $configFilePath) -and -not $Force) {
            try {
                $currentConfig = Get-Content -Path $configFilePath -Raw | ConvertFrom-Json -AsHashtable
            }
            catch {
                Write-AdminLog -Message "Could not parse existing config, will create new" -Level Warning
            }
        }

        # Merge or replace settings
        if ($Force) {
            $finalConfig = $Settings
        } else {
            # Merge new settings with existing
            $finalConfig = $currentConfig
            foreach ($key in $Settings.Keys) {
                $finalConfig[$key] = $Settings[$key]
            }
        }

        # Save configuration
        if ($PSCmdlet.ShouldProcess($configFilePath, "Save configuration")) {
            $finalConfig | ConvertTo-Json -Depth 10 | Out-File -FilePath $configFilePath -Encoding UTF8
            
            # Update cache
            $script:ConfigCache[$ConfigName] = $finalConfig
            
            Write-AdminLog -Message "Configuration saved successfully: $configFilePath" -Level Success
            return $true
        }
    }
    catch {
        Write-AdminLog -Message "Failed to set configuration: $_" -Level Error
        throw
    }
}