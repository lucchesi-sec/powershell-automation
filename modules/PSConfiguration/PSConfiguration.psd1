@{
    RootModule = 'PSConfiguration.psm1'
    ModuleVersion = '2.0.0'
    GUID = 'd7b0e6f2-1c5g-7d4e-2f8h-0a1c6e4d7f4f'
    Author = 'Enterprise Automation Team'
    CompanyName = 'Enterprise Corporation'
    Copyright = '(c) Enterprise Corporation. All rights reserved.'
    Description = 'Centralized configuration management module with schema validation and environment support'
    PowerShellVersion = '5.1'
    
    # Required modules
    RequiredModules = @(
        @{ModuleName = 'PSCore'; ModuleVersion = '2.0.0'; GUID = 'a4e7b3c9-8f2d-4a1b-9c5e-6d8f7e2a3b1c'}
    )
    
    # Functions to export
    FunctionsToExport = @(
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
    )
    
    # Variables to export
    VariablesToExport = @(
        'PSConfigStore'
        'PSConfigEnvironment'
    )
    
    # Aliases to export
    AliasesToExport = @(
        'getconfig'
        'setconfig'
        'switchenv'
    )
    
    # Private data
    PrivateData = @{
        PSData = @{
            Tags = @('Configuration', 'Settings', 'Environment', 'Schema', 'Validation')
            LicenseUri = 'https://company.com/license'
            ProjectUri = 'https://company.com/psautomation'
            ReleaseNotes = @"
## Version 2.0.0
- Complete modular architecture
- Advanced schema validation
- Environment-specific configurations
- Configuration versioning
- Secure value encryption
- Template system
"@
        }
    }
}