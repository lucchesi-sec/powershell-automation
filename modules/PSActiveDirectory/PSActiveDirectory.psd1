@{
    RootModule = 'PSActiveDirectory.psm1'
    ModuleVersion = '2.0.0'
    GUID = 'b5f8c4d0-9a3e-5b2c-0d6f-8e9a4c2b5d2d'
    Author = 'Enterprise Automation Team'
    CompanyName = 'Enterprise Corporation'
    Copyright = '(c) Enterprise Corporation. All rights reserved.'
    Description = 'Enhanced Active Directory management module for PowerShell Enterprise Automation Platform'
    PowerShellVersion = '5.1'
    
    # Required modules
    RequiredModules = @(
        @{ModuleName = 'PSCore'; ModuleVersion = '2.0.0'; GUID = 'a4e7b3c9-8f2d-4a1b-9c5e-6d8f7e2a3b1c'}
        'ActiveDirectory'
    )
    
    # Functions to export
    FunctionsToExport = @(
        # User Management
        'New-PSADUser'
        'Set-PSADUser'
        'Remove-PSADUser'
        'Get-PSADUser'
        'Enable-PSADUser'
        'Disable-PSADUser'
        'Unlock-PSADUser'
        'Reset-PSADUserPassword'
        'Set-PSADUserLifecycle'
        'Get-PSADUserActivity'
        
        # Group Management
        'New-PSADGroup'
        'Set-PSADGroup'
        'Remove-PSADGroup'
        'Get-PSADGroup'
        'Add-PSADGroupMember'
        'Remove-PSADGroupMember'
        'Sync-PSADGroupMembership'
        'Get-PSADGroupNesting'
        
        # Computer Management
        'New-PSADComputer'
        'Set-PSADComputer'
        'Remove-PSADComputer'
        'Get-PSADComputer'
        'Test-PSADComputerConnectivity'
        'Get-PSADComputerInventory'
        
        # Organizational Unit Management
        'New-PSADOU'
        'Set-PSADOU'
        'Remove-PSADOU'
        'Get-PSADOU'
        'Move-PSADObject'
        
        # Security and Permissions
        'Get-PSADPermission'
        'Set-PSADPermission'
        'Test-PSADPermission'
        'Get-PSADDelegation'
        'Set-PSADDelegation'
        
        # Reporting and Analysis
        'Get-PSADReport'
        'Get-PSADStatistics'
        'Get-PSADHealthCheck'
        'Export-PSADData'
        
        # Bulk Operations
        'Import-PSADUsers'
        'Export-PSADUsers'
        'Invoke-PSADBulkOperation'
        
        # Advanced Features
        'Find-PSADObject'
        'Compare-PSADObject'
        'Backup-PSADObject'
        'Restore-PSADObject'
        'Watch-PSADChanges'
    )
    
    # Variables to export
    VariablesToExport = @(
        'PSADConfig'
        'PSADDefaultProperties'
    )
    
    # Aliases to export
    AliasesToExport = @(
        'psaduser'
        'psadgroup'
        'psadcomp'
    )
    
    # Private data
    PrivateData = @{
        PSData = @{
            Tags = @('ActiveDirectory', 'AD', 'Enterprise', 'UserManagement', 'Automation')
            LicenseUri = 'https://company.com/license'
            ProjectUri = 'https://company.com/psautomation'
            ReleaseNotes = @"
## Version 2.0.0
- Complete rewrite with modular architecture
- Enhanced bulk operations
- Improved error handling and logging
- Advanced search and filtering
- Lifecycle management automation
- Performance optimizations
"@
        }
    }
}