@{
    # Module Manifest
    RootModule = 'PSAutomationCore.psm1'
    ModuleVersion = '2.0.0'
    GUID = 'f47d3c62-8b91-4a5c-9e2d-1a8b3c4d5e6f'
    Author = 'Enterprise Automation Team'
    CompanyName = 'Enterprise IT'
    Copyright = '(c) 2024 Enterprise IT. All rights reserved.'
    Description = 'Core automation framework providing architectural foundation, dependency injection, configuration management, and plugin infrastructure for enterprise PowerShell automation'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    
    # Dependencies
    RequiredModules = @()
    RequiredAssemblies = @()
    
    # Exports
    FunctionsToExport = @(
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
    
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    
    # Module Metadata
    PrivateData = @{
        PSData = @{
            Tags = @('Automation', 'Enterprise', 'Core', 'Framework', 'Architecture')
            LicenseUri = 'https://github.com/enterprise/ps-automation/LICENSE'
            ProjectUri = 'https://github.com/enterprise/ps-automation'
            IconUri = ''
            ReleaseNotes = @'
# Release Notes for PSAutomationCore 2.0.0

## Major Changes
- Complete architectural redesign following SOLID principles
- Implemented dependency injection container
- Added plugin architecture with interface validation
- Enhanced configuration management with JSON schema support
- Comprehensive security framework with context isolation
- Performance monitoring and metrics collection

## Breaking Changes
- Module renamed from PSAdminCore to PSAutomationCore
- All function names updated to follow new naming convention
- Configuration structure updated to support environments

## New Features
- Service container with scoped lifetime management
- Plugin discovery and dynamic loading
- Configuration schema validation
- Security context management
- Performance tracing infrastructure
'@
            Prerelease = ''
            RequireLicenseAcceptance = $false
            ExternalModuleDependencies = @()
        }
        
        # Module Configuration
        ModuleConfig = @{
            DefaultLogLevel = 'Information'
            ConfigurationPath = '$PSScriptRoot\..\..\config'
            PluginPath = '$PSScriptRoot\..\Plugins'
            LogPath = '$env:ProgramData\PSAutomation\Logs'
            SecureStorePath = '$env:ProgramData\PSAutomation\SecureStore'
            PerformanceTracking = $true
            SecurityValidation = $true
        }
    }
}