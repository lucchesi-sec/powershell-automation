function Initialize-AdminEnvironment {
    <#
    .SYNOPSIS
        Initializes the PSAdminCore module environment.
    .DESCRIPTION
        Sets up the module environment including log paths, configuration paths,
        and validates prerequisites. This function is automatically called when
        the module is imported.
    .PARAMETER LogPath
        Custom path for log files.
    .PARAMETER ConfigPath
        Custom path for configuration files.
    .PARAMETER Quiet
        Suppresses initialization messages.
    .EXAMPLE
        Initialize-AdminEnvironment -LogPath "C:\Logs" -Quiet
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$LogPath,

        [Parameter(Mandatory = $false)]
        [string]$ConfigPath,

        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )

    try {
        if (-not $Quiet) {
            Write-Host "Initializing PSAdminCore environment..." -ForegroundColor Cyan
        }

        # Set custom log path if provided
        if ($LogPath) {
            $script:LogPath = Join-Path $LogPath "PSAdminCore_$(Get-Date -Format 'yyyyMMdd').log"
            if (-not $Quiet) {
                Write-Host "  Log path set to: $LogPath" -ForegroundColor Gray
            }
        }

        # Initialize credential cache
        if (-not $script:CredentialCache) {
            $script:CredentialCache = @{}
        }

        # Initialize config cache
        if (-not $script:ConfigCache) {
            $script:ConfigCache = @{}
        }

        # Create default directories if they don't exist
        $defaultPaths = @(
            (Join-Path $env:ProgramData 'PSAutomation\config'),
            (Join-Path $env:ProgramData 'PSAutomation\logs'),
            (Join-Path $env:APPDATA 'PSAutomation\config')
        )

        foreach ($path in $defaultPaths) {
            if (-not (Test-Path $path)) {
                try {
                    New-Item -Path $path -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
                    if (-not $Quiet) {
                        Write-Host "  Created directory: $path" -ForegroundColor Gray
                    }
                }
                catch {
                    # Silently continue if we can't create system directories
                }
            }
        }

        # Check for optional modules and provide recommendations
        $recommendedModules = @{
            'ActiveDirectory' = 'Required for AD-related scripts'
            'CredentialManager' = 'Enhanced credential management'
            'Microsoft.PowerShell.SecretManagement' = 'Secure secret storage'
            'Pester' = 'Testing framework'
        }

        $missingModules = @()
        foreach ($module in $recommendedModules.Keys) {
            if (-not (Get-Module -ListAvailable -Name $module)) {
                $missingModules += $module
            }
        }

        if ($missingModules.Count -gt 0 -and -not $Quiet) {
            Write-Host "`n  Optional modules not installed:" -ForegroundColor Yellow
            foreach ($module in $missingModules) {
                Write-Host "    - $module`: $($recommendedModules[$module])" -ForegroundColor Gray
            }
            Write-Host "    Install with: Install-Module <ModuleName> -Scope CurrentUser" -ForegroundColor Gray
        }

        # Set execution policy warning if needed
        $executionPolicy = Get-ExecutionPolicy
        if ($executionPolicy -in @('Restricted', 'AllSigned') -and -not $Quiet) {
            Write-Host "`n  Warning: Execution policy is '$executionPolicy'" -ForegroundColor Yellow
            Write-Host "    Some scripts may not run. Consider: Set-ExecutionPolicy RemoteSigned -Scope CurrentUser" -ForegroundColor Gray
        }

        if (-not $Quiet) {
            Write-Host "`nPSAdminCore environment initialized successfully!" -ForegroundColor Green
            Write-Host "Module version: $((Get-Module PSAdminCore).Version)" -ForegroundColor Gray
        }

        return $true
    }
    catch {
        Write-Error "Failed to initialize PSAdminCore environment: $_"
        return $false
    }
}