@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'PSAdminCore.psm1'

    # Version number of this module.
    ModuleVersion = '1.0.0'

    # Supported PSEditions
    CompatiblePSEditions = @('Desktop', 'Core')

    # ID used to uniquely identify this module
    GUID = 'a7f4db4b-8b9c-4d3e-9f2a-1c5d6e7f8a9b'

    # Author of this module
    Author = 'Automation Team'

    # Company or vendor of this module
    CompanyName = 'PowerShell Automation Platform'

    # Copyright statement for this module
    Copyright = '(c) 2024 Automation Team. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'Core module providing essential functions for logging, notifications, credential management, and administrative tasks for the PowerShell Automation Platform.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Functions to export from this module
    FunctionsToExport = @(
        'Write-AdminLog',
        'Test-AdminPrivileges',
        'Send-AdminNotification',
        'Get-AdminCredential',
        'New-AdminReport',
        'Test-AdminParameter',
        'Test-AdminConnectivity',
        'Get-AdminConfig',
        'Set-AdminConfig',
        'Initialize-AdminEnvironment',
        'Get-SecureCredential',
        'Test-SecureString',
        'ConvertTo-SecureText',
        'ConvertFrom-SecureText',
        'Protect-Configuration',
        'Unprotect-Configuration',
        'Test-SecurityCompliance',
        'Test-SecretManagementPrerequisites',
        'Get-PSAdminCredential',
        'Get-PSAdminCoreAesKey',
        'Protect-PSAdminConfiguration',
        'Unprotect-PSAdminConfiguration',
        'Test-PSAdminSecurityCompliance'
    )

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @('Administration', 'Automation', 'Logging', 'Notification', 'Windows', 'ActiveDirectory')

            # A URL to the license for this module.
            LicenseUri = 'https://github.com/lucchesi-sec/powershell-automation/blob/main/LICENSE'

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/lucchesi-sec/powershell-automation'

            # A URL to an icon representing this module.
            IconUri = 'https://raw.githubusercontent.com/lucchesi-sec/powershell-automation/main/powershell-logo.svg'

            # ReleaseNotes
            ReleaseNotes = @'
## Version 1.0.0
Initial release of PSAdminCore module with the following features:
- Structured logging with severity levels
- Administrative privilege checking
- Email notification system
- Secure credential management
- Report generation framework
- Parameter validation utilities
- Network connectivity testing
- Configuration management
'@
        }
    }

    # HelpInfo URI of this module
    HelpInfoURI = 'https://lucchesi-sec.github.io/powershell-automation/api/PSAdminCore/'
}