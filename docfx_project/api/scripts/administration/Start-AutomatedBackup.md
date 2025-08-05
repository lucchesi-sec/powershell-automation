---
uid: api.scripts.administration.start-automatedbackup
name: Start-AutomatedBackup
---

# Start-AutomatedBackup

## Synopsis
Initiates automated backup operations with comprehensive configuration and monitoring.

## Description
This script provides a complete automated backup solution with support for multiple backup types, encryption, compression, and cloud synchronization. It includes comprehensive logging, error handling, and notification capabilities for production backup operations.

## Syntax
```powershell
.\Start-AutomatedBackup.ps1 [[-BackupType] <String>] [[-Source] <String>] [[-Destination] <String>] [[-Schedule] <String>] [-Compress] [-Encrypt] [-CloudSync] [-EmailNotification] [<CommonParameters>]
```

## Parameters

### -BackupType
Specifies the type of backup to perform (Full, Incremental, Differential).

### -Source
Source directory or system to backup.

### -Destination
Destination path for backup files.

### -Schedule
Backup schedule configuration.

### -Compress
Enables compression for backup files.

### -Encrypt
Enables encryption for backup files.

### -CloudSync
Enables synchronization to cloud storage.

### -EmailNotification
Sends email notifications upon completion.

## Examples

### Example 1: Full backup with encryption
```powershell
PS C:\> .\Start-AutomatedBackup.ps1 -BackupType "Full" -Source "C:\Data" -Encrypt -EmailNotification
```

## Notes
- **Author:** Automation Team
- **Requires:** PSAdminCore module, appropriate backup permissions

## Related Links
- [Write-AdminLog](../../PSAdminCore/Write-AdminLog.md)
- [Send-AdminNotification](../../PSAdminCore/Send-AdminNotification.md)