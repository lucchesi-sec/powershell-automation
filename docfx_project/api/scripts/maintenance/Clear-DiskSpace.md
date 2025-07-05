---
uid: api.scripts.maintenance.clear-diskspace
name: Clear-DiskSpace
---

# Clear-DiskSpace

## Synopsis
Automated disk space cleanup script for Windows systems.

## Description
This script performs comprehensive disk cleanup operations including:
- Temporary files cleanup
- Log file rotation and cleanup
- Recycle bin emptying
- Windows update cleanup
- IIS log cleanup (if applicable)
- Event log archival

## Syntax
```powershell
.\Clear-DiskSpace.ps1 [[-DriveLetter] <String>] [[-LogRetentionDays] <Int32>] [-WhatIf] [<CommonParameters>]
```

## Parameters

### -DriveLetter
Target drive letter to clean.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| String | false | 1 | C |

### -LogRetentionDays
Number of days to retain log files.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| Int32 | false | 2 | 30 |

### -WhatIf
Show what would be cleaned without actually performing cleanup.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| SwitchParameter | false | named | False |

## Examples

### Example 1: Default cleanup
```powershell
PS C:\> .\Clear-DiskSpace.ps1
```
Performs cleanup on C: drive with default settings.

### Example 2: Custom drive and retention
```powershell
PS C:\> .\Clear-DiskSpace.ps1 -DriveLetter D -LogRetentionDays 14
```
Cleans D: drive and retains logs for 14 days.

## Notes
- **Author:** PowerShell Automation Project
- **Requires:** Administrator privileges for full functionality

## Related Links
- [Test-AdminPrivileges](../../PSAdminCore/Test-AdminPrivileges.md)
- [Write-AdminLog](../../PSAdminCore/Write-AdminLog.md)