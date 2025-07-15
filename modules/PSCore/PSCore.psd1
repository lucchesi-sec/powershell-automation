@{
    RootModule = 'PSCore.psm1'
    ModuleVersion = '2.0.0'
    GUID = 'a4e7b3c9-8f2d-4a1b-9c5e-6d8f7e2a3b1c'
    Author = 'Enterprise Automation Team'
    CompanyName = 'Enterprise Corporation'
    Copyright = '(c) Enterprise Corporation. All rights reserved.'
    Description = 'Core module providing foundational functionality for the PowerShell Enterprise Automation Platform'
    PowerShellVersion = '5.1'
    
    # Functions to export
    FunctionsToExport = @(
        # Logging
        'Write-PSLog'
        'Initialize-PSLogContext'
        'Get-PSLogHistory'
        'Clear-PSLogHistory'
        
        # Configuration
        'Get-PSConfiguration'
        'Set-PSConfiguration'
        'Test-PSConfiguration'
        'Export-PSConfiguration'
        'Import-PSConfiguration'
        'New-PSConfigurationSchema'
        
        # Credential Management
        'Get-PSCredential'
        'Set-PSCredential'
        'Remove-PSCredential'
        'Test-PSCredential'
        'New-PSCredentialStore'
        
        # Module Management
        'Import-PSModule'
        'Test-PSModuleDependency'
        'Get-PSModuleManifest'
        'Update-PSModulePath'
        'Resolve-PSModuleDependencies'
        
        # Error Handling
        'New-PSError'
        'Write-PSErrorLog'
        'Get-PSErrorContext'
        'Invoke-PSRetry'
        
        # Performance
        'Measure-PSPerformance'
        'Start-PSPerformanceMonitor'
        'Stop-PSPerformanceMonitor'
        'Get-PSPerformanceReport'
        
        # Validation
        'Test-PSParameter'
        'Assert-PSRequirement'
        'Get-PSValidationRule'
        'New-PSValidationRule'
        
        # Threading
        'Start-PSJob'
        'Wait-PSJob'
        'Get-PSJobResult'
        'Stop-PSJob'
        
        # Utilities
        'ConvertTo-PSHashtable'
        'ConvertFrom-PSHashtable'
        'Get-PSEnvironment'
        'Test-PSElevation'
        'Invoke-PSElevated'
    )
    
    # Variables to export
    VariablesToExport = @(
        'PSCoreConfig'
        'PSLogLevel'
        'PSPerformanceMetrics'
    )
    
    # Aliases to export
    AliasesToExport = @(
        'pslog'
        'pscfg'
        'pscred'
    )
    
    # Private data
    PrivateData = @{
        PSData = @{
            Tags = @('Enterprise', 'Automation', 'Core', 'Framework')
            LicenseUri = 'https://company.com/license'
            ProjectUri = 'https://company.com/psautomation'
            ReleaseNotes = @"
## Version 2.0.0
- Complete modular architecture rewrite
- Enhanced performance monitoring
- Improved credential management
- Better error handling and retry logic
- Thread-safe operations
"@
        }
    }
}