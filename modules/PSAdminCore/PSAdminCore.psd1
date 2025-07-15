@{
    RootModule = 'PSAdminCore.psm1'
    ModuleVersion = '1.0.0'
    GUID = 'a1b2c3d4-e5f6-7890-1234-567890abcdef'
    Author = 'System Administrator'
    CompanyName = 'Enterprise IT'
    Copyright = '(c) 2024 Enterprise IT. All rights reserved.'
    Description = 'Core administrative functions for PowerShell automation scripts'
    PowerShellVersion = '5.1'
    RequiredModules = @()
    FunctionsToExport = @(
        'Write-AdminLog',
        'Test-AdminPrivileges', 
        'Get-AdminCredential',
        'Send-AdminNotification',
        'New-AdminReport',
        'Test-AdminConnectivity',
        'Test-AdminParameter'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('Administration', 'Automation', 'Enterprise', 'Core')
            LicenseUri = ''
            ProjectUri = ''
            IconUri = ''
            ReleaseNotes = 'Initial release of PSAdminCore module'
        }
    }
}