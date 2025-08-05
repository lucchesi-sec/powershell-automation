#Requires -Version 7.0
<#
.SYNOPSIS
    Installs PSScriptAnalyzer module from PowerShell Gallery with robust error handling.

.DESCRIPTION
    This script installs the PSScriptAnalyzer module required for static code analysis
    in the CI/CD pipeline. It handles various failure scenarios including network issues,
    permission problems, and module repository availability.

.PARAMETER Force
    Forces reinstallation even if the module is already present.

.PARAMETER RequiredVersion
    Specifies a specific version of PSScriptAnalyzer to install.

.PARAMETER SkipPublisherCheck
    Skips publisher validation (useful in CI environments).

.EXAMPLE
    .\Install-PSScriptAnalyzer.ps1
    Installs the latest version of PSScriptAnalyzer.

.EXAMPLE
    .\Install-PSScriptAnalyzer.ps1 -Force -RequiredVersion "1.21.0"
    Forces installation of a specific version.

.NOTES
    Exit Codes:
    0 - Success
    1 - Module installation failed
    2 - PowerShell Gallery unavailable
    3 - Insufficient permissions
    4 - Unknown error
#>

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$Force,
    
    [Parameter()]
    [string]$RequiredVersion,
    
    [Parameter()]
    [switch]$SkipPublisherCheck
)

# Import required modules

if (Test-Path $modulePath) {
    Import-Module $modulePath -Force
} else {
    # Fall back to installed module
    Import-Module PSAdminCore -Force -ErrorAction Stop
}

# Set strict mode for better error detection
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Initialize exit code
$exitCode = 0

# Function to write GitHub Actions compatible output
function Write-GitHubOutput {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Error', 'Warning', 'Notice', 'Debug')]
        [string]$Level,
        
        [Parameter(Mandatory)]
        [string]$Message,
        
        [Parameter()]
        [string]$File,
        
        [Parameter()]
        [int]$Line,
        
        [Parameter()]
        [int]$Column
    )
    
    $annotation = "::$($Level.ToLower())"
    
    if ($File) {
        $annotation += " file=$File"
        if ($Line -gt 0) {
            $annotation += ",line=$Line"
            if ($Column -gt 0) {
                $annotation += ",col=$Column"
            }
        }
    }
    
    $annotation += "::$Message"
    Write-Host $annotation
}

# Function to test repository connectivity
function Test-PSGalleryConnectivity {
    try {
        Write-Host "Testing PowerShell Gallery connectivity..."
        $gallery = Get-PSRepository -Name PSGallery -ErrorAction Stop
        
        if ($gallery.InstallationPolicy -eq 'Untrusted' -and -not $SkipPublisherCheck) {
            Write-GitHubOutput -Level Warning -Message "PSGallery is untrusted. Consider using -SkipPublisherCheck in CI environments."
        }
        
        # Test actual connectivity
        $null = Find-Module -Name PSScriptAnalyzer -Repository PSGallery -ErrorAction Stop
        Write-Host "✓ PowerShell Gallery is accessible"
        return $true
    }
    catch {
        Write-GitHubOutput -Level Error -Message "PowerShell Gallery connectivity test failed: $_"
        return $false
    }
}

# Function to check if running with sufficient privileges
function Test-InstallationPrivileges {
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]$currentUser
        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
        # On Linux/macOS, check if we can write to module path
        if ($PSVersionTable.Platform -eq 'Unix') {
            $modulePaths = $env:PSModulePath -split ':'
            $userModulePath = $modulePaths | Where-Object { $_ -like "*$HOME*" } | Select-Object -First 1
            
            if ($userModulePath -and (Test-Path $userModulePath)) {
                return $true
            }
        }
        
        return $isAdmin
    }
    catch {
        # If we can't determine privileges, attempt installation anyway
        Write-GitHubOutput -Level Warning -Message "Could not determine installation privileges: $_"
        return $true
    }
}

# Main installation logic
try {
    Write-Host "=== PSScriptAnalyzer Installation Script ==="
    Write-Host "PowerShell Version: $($PSVersionTable.PSVersion)"
    Write-Host "Platform: $($PSVersionTable.Platform ?? 'Windows')"
    Write-Host ""
    
    # Check if module is already installed
    $existingModule = Get-Module -ListAvailable -Name PSScriptAnalyzer | 
        Sort-Object Version -Descending | 
        Select-Object -First 1
    
    if ($existingModule -and -not $Force) {
        Write-Host "✓ PSScriptAnalyzer version $($existingModule.Version) is already installed"
        Write-GitHubOutput -Level Notice -Message "PSScriptAnalyzer $($existingModule.Version) already installed at $($existingModule.ModuleBase)"
        
        # Import module to verify it works
        try {
            Import-Module PSScriptAnalyzer -ErrorAction Stop
            Write-Host "✓ Module imported successfully"
            exit 0
        }
        catch {
            Write-GitHubOutput -Level Warning -Message "Module exists but failed to import: $_"
            # Continue with reinstallation
        }
    }
    
    # Test connectivity to PowerShell Gallery
    if (-not (Test-PSGalleryConnectivity)) {
        Write-GitHubOutput -Level Error -Message "Cannot connect to PowerShell Gallery. Check network connectivity and proxy settings."
        exit 2
    }
    
    # Check installation privileges
    if (-not (Test-InstallationPrivileges)) {
        Write-GitHubOutput -Level Warning -Message "Running without administrator privileges. Installation will use CurrentUser scope."
        $scope = 'CurrentUser'
    }
    else {
        $scope = 'AllUsers'
    }
    
    # Prepare installation parameters
    $installParams = @{
        Name = 'PSScriptAnalyzer'
        Scope = $scope
        Force = $Force
        AllowClobber = $true
        ErrorAction = 'Stop'
    }
    
    if ($RequiredVersion) {
        $installParams['RequiredVersion'] = $RequiredVersion
        Write-Host "Installing PSScriptAnalyzer version $RequiredVersion..."
    }
    else {
        Write-Host "Installing latest version of PSScriptAnalyzer..."
    }
    
    if ($SkipPublisherCheck) {
        $installParams['SkipPublisherCheck'] = $true
    }
    
    # Attempt installation
    try {
        Install-Module @installParams
        Write-Host "✓ PSScriptAnalyzer installed successfully"
    }
    catch [System.UnauthorizedAccessException] {
        # Retry with CurrentUser scope
        Write-GitHubOutput -Level Warning -Message "Access denied with $scope scope. Retrying with CurrentUser scope..."
        $installParams['Scope'] = 'CurrentUser'
        Install-Module @installParams
        Write-Host "✓ PSScriptAnalyzer installed successfully (CurrentUser scope)"
    }
    
    # Verify installation
    $installedModule = Get-Module -ListAvailable -Name PSScriptAnalyzer | 
        Sort-Object Version -Descending | 
        Select-Object -First 1
    
    if (-not $installedModule) {
        throw "PSScriptAnalyzer module not found after installation"
    }
    
    Write-Host ""
    Write-Host "Installation Summary:"
    Write-Host "  Module: $($installedModule.Name)"
    Write-Host "  Version: $($installedModule.Version)"
    Write-Host "  Path: $($installedModule.ModuleBase)"
    
    # Import and test the module
    Import-Module PSScriptAnalyzer -ErrorAction Stop
    $rules = Get-ScriptAnalyzerRule | Measure-Object
    Write-Host "  Available Rules: $($rules.Count)"
    
    Write-GitHubOutput -Level Notice -Message "PSScriptAnalyzer $($installedModule.Version) installed successfully with $($rules.Count) rules available"
}
catch {
    $exitCode = 1
    $errorMessage = $_.Exception.Message
    
    # Provide specific error codes for common scenarios
    if ($_ -match 'network|connectivity|repository|gallery') {
        $exitCode = 2
    }
    elseif ($_ -match 'access|permission|unauthorized') {
        $exitCode = 3
    }
    elseif ($exitCode -eq 1 -and $_ -match 'unknown|unexpected') {
        $exitCode = 4
    }
    
    Write-GitHubOutput -Level Error -Message "Installation failed: $errorMessage"
    Write-Error "Failed to install PSScriptAnalyzer: $_" -ErrorAction Continue
}

exit $exitCode
