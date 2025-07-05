---
uid: api.scripts.administration.restore-datafrombackup
name: Restore-DataFromBackup
---

# Restore-DataFromBackup

## Synopsis
Restores data from backup archives with integrity verification and security controls.

## Description
This script provides comprehensive data restoration capabilities from backup archives. It includes integrity verification, encryption handling, rollback point management, and detailed audit logging. Supports various backup formats and includes safety mechanisms to prevent accidental data overwrites.

## Syntax
```powershell
.\Restore-DataFromBackup.ps1 [-BackupPath] <String> [-RestoreTarget] <String> [[-RestorePoint] <DateTime>] [-VerifyIntegrity] [-PreservePermissions] [-DryRun] [<CommonParameters>]
```

## Parameters

### -BackupPath
Path to the backup archive or backup location.

### -RestoreTarget
Target directory where data will be restored.

### -RestorePoint
Specific point-in-time to restore from (for incremental backups).

### -VerifyIntegrity
Performs integrity verification before restoration.

### -PreservePermissions
Maintains original file permissions and security attributes.

### -DryRun
Shows what would be restored without performing actual restoration.

## Examples

### Example 1: Restore with integrity verification
```powershell
PS C:\> .\Restore-DataFromBackup.ps1 -BackupPath "C:\Backups\Data_20250704.zip" -RestoreTarget "C:\Restored" -VerifyIntegrity
```

## Notes
- **Author:** Enterprise Automation Team
- **Requires:** PSAdminCore module, appropriate file system permissions
- **Security:** Includes encryption key management and access logging

## Related Links
- [Write-AdminLog](../../PSAdminCore/Write-AdminLog.md)
- [Test-AdminPrivileges](../../PSAdminCore/Test-AdminPrivileges.md)