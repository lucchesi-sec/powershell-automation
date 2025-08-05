#Requires -Version 5.1
<#
.SYNOPSIS
    PSAdminCore - Core module for PowerShell Automation Platform
.DESCRIPTION
    This module provides essential functions for logging, notifications, credential management,
    and administrative tasks used throughout the PowerShell Automation Platform.
#>

# Module script scope variables
if ($PSScriptRoot) {
    $script:ModuleRoot = $PSScriptRoot
} elseif ($MyInvocation.MyCommand.Path) {
    $script:ModuleRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
} else {
    # Fallback - try to find the module in the current directory structure
    $script:ModuleRoot = Join-Path (Get-Location).Path 'modules/PSAdminCore'
}
$script:ConfigCache = @{}
$tempPath = if ($env:TEMP) { $env:TEMP } elseif ($env:TMPDIR) { $env:TMPDIR } else { '/tmp' }
$script:LogPath = Join-Path $tempPath "PSAdminCore_$(Get-Date -Format 'yyyyMMdd').log"

# Import all public functions
$PublicPath = Join-Path $script:ModuleRoot 'Public'
if (Test-Path $PublicPath) {
    Get-ChildItem -Path $PublicPath -Filter '*.ps1' -File | ForEach-Object {
        try {
            . $_.FullName
            Write-Verbose "Imported public function: $($_.BaseName)"
        }
        catch {
            Write-Warning "Failed to import public function $($_.FullName): $_"
        }
    }
}

# Import all private functions
$PrivatePath = Join-Path $script:ModuleRoot 'Private'
if (Test-Path $PrivatePath) {
    Get-ChildItem -Path $PrivatePath -Filter '*.ps1' -File | ForEach-Object {
        try {
            . $_.FullName
            Write-Verbose "Imported private function: $($_.BaseName)"
        }
        catch {
            Write-Warning "Failed to import private function $($_.FullName): $_"
        }
    }
}

# Check for SecretManagement prerequisites on module load
try {
    if (Get-Command Test-SecretManagementPrerequisites -ErrorAction SilentlyContinue) {
        Test-SecretManagementPrerequisites
    }
} catch {
    Write-Warning "SecretManagement prerequisites not met. Some security features may be unavailable."
    Write-Warning "Run: Install-Module Microsoft.PowerShell.SecretManagement, Microsoft.PowerShell.SecretStore -Force"
}

# Initialize module
Initialize-AdminEnvironment -Quiet

# Export module member (functions are exported via manifest)
Export-ModuleMember -Function * -Alias * -Variable @()