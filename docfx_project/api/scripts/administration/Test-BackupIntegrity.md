---
uid: api.scripts.administration.test-backupintegrity
name: Test-BackupIntegrity
---

# Test-BackupIntegrity

## Synopsis
Validates the integrity and completeness of backup files and archives.

## Description
This script performs comprehensive integrity testing of backup files including checksum verification, archive validation, and restoration testing. It ensures backup files are reliable and can be successfully restored when needed, which is critical for enterprise data protection strategies.

## Syntax
```powershell
.\Test-BackupIntegrity.ps1 [[-BackupPath] <String>] [[-TestType] <String>] [-GenerateReport] [-EmailResults] [-FixCorruption] [<CommonParameters>]
```

## Parameters

### -BackupPath
Path to backup files or directory to test for integrity.

### -TestType
Type of integrity test to perform (Quick, Full, Deep).

### -GenerateReport
Creates detailed integrity test report.

### -EmailResults
Sends test results via email to administrators.

### -FixCorruption
Attempts to repair minor backup file corruption when detected.

## Examples

### Example 1: Full integrity test with report
```powershell
PS C:\> .\Test-BackupIntegrity.ps1 -BackupPath "C:\Backups" -TestType "Full" -GenerateReport -EmailResults
```

## Notes
- **Author:** Enterprise Automation Team
- **Requires:** PSAdminCore module, backup file access permissions
- **Performance:** Deep testing may take significant time for large backup sets

## Related Links
- [New-AdminReport](../../PSAdminCore/New-AdminReport.md)
- [Send-AdminNotification](../../PSAdminCore/Send-AdminNotification.md)