#
# Module manifest for PSBackupService
#
# Service module for enterprise backup automation with exceptional user experience
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'PSBackupService.psm1'

# Version number of this module.
ModuleVersion = '2.0.0'

# Supported PSEditions
CompatiblePSEditions = @('Desktop', 'Core')

# ID used to uniquely identify this module
GUID = 'b5e9d4f2-8a3c-4d7e-9f1b-2c6d8e5a3b7f'

# Author of this module
Author = 'Enterprise Automation Team'

# Company or vendor of this module
CompanyName = 'Enterprise IT'

# Copyright statement for this module
Copyright = '(c) Enterprise IT. All rights reserved.'

# Description of the functionality provided by this module
Description = @'
PSBackupService provides a delightful backup automation experience with:
- Interactive backup job creation wizards
- Real-time progress visualization
- Smart scheduling with conflict detection
- Intelligent file selection and filtering
- Cloud storage integration (Azure, AWS, Google)
- Automated testing and validation
- Self-healing backup jobs
- Comprehensive reporting with insights
'@

# Minimum version of the PowerShell engine required by this module
PowerShellVersion = '5.1'

# Modules that must be imported into the global environment prior to importing this module
RequiredModules = @('PSAutomationCore')

# Functions to export from this module
FunctionsToExport = @(
    # Interactive Backup Management
    'New-BackupJob',
    'Start-BackupJob', 
    'Stop-BackupJob',
    'Get-BackupJob',
    'Set-BackupJob',
    'Remove-BackupJob',
    
    # Backup Operations
    'Start-Backup',
    'Restore-Backup',
    'Test-Backup',
    'Compare-Backup',
    
    # Scheduling and Automation
    'New-BackupSchedule',
    'Get-BackupSchedule',
    'Set-BackupSchedule',
    'Enable-BackupSchedule',
    'Disable-BackupSchedule',
    
    # Monitoring and Reporting
    'Get-BackupStatus',
    'Get-BackupHistory',
    'Get-BackupReport',
    'Watch-BackupProgress',
    
    # Cloud Integration
    'Connect-BackupCloud',
    'Sync-BackupToCloud',
    'Get-CloudBackupStatus',
    
    # Maintenance
    'Optimize-BackupStorage',
    'Test-BackupIntegrity',
    'Repair-BackupJob'
)

# Cmdlets to export from this module
CmdletsToExport = @()

# Variables to export from this module
VariablesToExport = @()

# Aliases to export from this module
AliasesToExport = @(
    'backup',      # Start-Backup
    'restore',     # Restore-Backup
    'backupnow',   # Start-BackupJob
    'backupwatch', # Watch-BackupProgress
)

# Private data to pass to the module specified in RootModule
PrivateData = @{

    PSData = @{
        Tags = @('Backup', 'Automation', 'Enterprise', 'Cloud', 'Storage', 'Archive')
        LicenseUri = ''
        ProjectUri = ''
        IconUri = ''
        
        ReleaseNotes = @'
Version 2.0.0 - Enhanced User Experience
- New interactive backup job wizard
- Real-time progress visualization
- Smart scheduling with recommendations
- Cloud provider auto-detection
- Self-healing backup capabilities
- Enhanced reporting with insights
'@
    }
    
    # Default settings
    DefaultSettings = @{
        DefaultCompressionLevel = 'Optimal'
        DefaultRetentionDays = 30
        EnableDeduplication = $true
        EnableVerification = $true
        ParallelStreams = 4
        ChunkSizeMB = 64
    }
}

# HelpInfo URI of this module
HelpInfoURI = ''

}