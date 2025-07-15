@{
    # Module Manifest
    RootModule = 'PSConfigurationManager.psm1'
    ModuleVersion = '2.0.0'
    GUID = 'a8c9d0e1-2f34-56b7-8901-234567890abc'
    Author = 'Enterprise Automation Team'
    CompanyName = 'Enterprise IT'
    Copyright = '(c) 2024 Enterprise IT. All rights reserved.'
    Description = 'Configuration management module with schema validation, environment support, and secure credential handling for enterprise PowerShell automation'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    
    # Dependencies
    RequiredModules = @(
        @{ModuleName = 'PSAutomationCore'; ModuleVersion = '2.0.0'}
    )
    
    # Exports
    FunctionsToExport = @(
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
    
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    
    # Module Metadata
    PrivateData = @{
        PSData = @{
            Tags = @('Configuration', 'Schema', 'Environment', 'Enterprise', 'Security')
            LicenseUri = 'https://github.com/enterprise/ps-automation/LICENSE'
            ProjectUri = 'https://github.com/enterprise/ps-automation'
            IconUri = ''
            ReleaseNotes = @'
# Release Notes for PSConfigurationManager 2.0.0

## Features
- Comprehensive configuration management with JSON schema validation
- Environment-specific configuration overlays
- Secure credential storage and rotation
- Configuration profiles for different scenarios
- Automatic configuration migration and versioning
- Built-in compliance checking

## Schema Support
- JSON Schema Draft 7 validation
- Custom validation rules
- Schema generation from existing configurations
- Schema versioning and migration
'@
            Prerelease = ''
            RequireLicenseAcceptance = $false
        }
        
        # Module Configuration
        ModuleConfig = @{
            ConfigurationRoot = '$env:ProgramData\PSAutomation\Config'
            SchemaRoot = '$env:ProgramData\PSAutomation\Schemas'
            DefaultEnvironment = 'Production'
            EnableValidation = $true
            AutoBackup = $true
            MaxBackupVersions = 10
        }
    }
}