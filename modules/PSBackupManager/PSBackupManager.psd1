@{
    RootModule = 'PSBackupManager.psm1'
    ModuleVersion = '2.0.0'
    GUID = 'c6a9d5e1-0b4f-6c3d-1e7g-9f0b5d3c6e3e'
    Author = 'Enterprise Automation Team'
    CompanyName = 'Enterprise Corporation'
    Copyright = '(c) Enterprise Corporation. All rights reserved.'
    Description = 'Enterprise-grade backup management module with cloud integration and advanced features'
    PowerShellVersion = '5.1'
    
    # Required modules
    RequiredModules = @(
        @{ModuleName = 'PSCore'; ModuleVersion = '2.0.0'; GUID = 'a4e7b3c9-8f2d-4a1b-9c5e-6d8f7e2a3b1c'}
    )
    
    # Functions to export
    FunctionsToExport = @(
        # Backup Operations
        'Start-PSBackup'
        'Stop-PSBackup'
        'Resume-PSBackup'
        'Get-PSBackupStatus'
        
        # Backup Jobs
        'New-PSBackupJob'
        'Set-PSBackupJob'
        'Remove-PSBackupJob'
        'Get-PSBackupJob'
        'Test-PSBackupJob'
        
        # Backup Policies
        'New-PSBackupPolicy'
        'Set-PSBackupPolicy'
        'Get-PSBackupPolicy'
        'Remove-PSBackupPolicy'
        
        # Restore Operations
        'Start-PSRestore'
        'Get-PSRestorePoint'
        'Test-PSRestorePoint'
        
        # Cloud Integration
        'Connect-PSBackupCloud'
        'Disconnect-PSBackupCloud'
        'Sync-PSBackupToCloud'
        'Get-PSBackupCloudStatus'
        
        # Backup Validation
        'Test-PSBackupIntegrity'
        'Repair-PSBackupIntegrity'
        'Get-PSBackupVerification'
        
        # Reporting
        'Get-PSBackupReport'
        'Get-PSBackupStatistics'
        'Export-PSBackupReport'
        
        # Maintenance
        'Optimize-PSBackupStorage'
        'Clean-PSBackupStorage'
        'Update-PSBackupCatalog'
        
        # Scheduling
        'New-PSBackupSchedule'
        'Set-PSBackupSchedule'
        'Get-PSBackupSchedule'
        'Enable-PSBackupSchedule'
        'Disable-PSBackupSchedule'
    )
    
    # Variables to export
    VariablesToExport = @(
        'PSBackupConfig'
        'PSBackupProviders'
    )
    
    # Aliases to export
    AliasesToExport = @(
        'backup'
        'restore'
        'backupjob'
    )
    
    # Private data
    PrivateData = @{
        PSData = @{
            Tags = @('Backup', 'Restore', 'Cloud', 'Storage', 'Enterprise', 'Automation')
            LicenseUri = 'https://company.com/license'
            ProjectUri = 'https://company.com/psautomation'
            ReleaseNotes = @"
## Version 2.0.0
- Complete modular rewrite
- Enhanced cloud provider support
- Improved compression algorithms
- Advanced integrity verification
- Real-time backup monitoring
- Parallel backup operations
"@
        }
    }
}