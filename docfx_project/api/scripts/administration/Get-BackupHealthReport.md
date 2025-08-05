---
uid: api.scripts.administration.get-backuphealthreport
name: Get-BackupHealthReport
---

# Get-BackupHealthReport

## Synopsis
Generates comprehensive health reports for backup operations and infrastructure.

## Description
This script analyzes backup systems, schedules, and recent operations to provide detailed health reports. It monitors backup success rates, identifies failed operations, checks storage capacity, and validates backup integrity to ensure reliable data protection in production environments.

## Syntax
```powershell
.\Get-BackupHealthReport.ps1 [[-Days] <Int32>] [[-OutputPath] <String>] [[-Format] <String>] [-IncludeDetails] [-EmailReport] [<CommonParameters>]
```

## Parameters

### -Days
Number of days to analyze for backup operations.

### -OutputPath
Directory where the health report will be saved.

### -Format
Output format for the report (HTML, CSV, JSON).

### -IncludeDetails
Includes detailed information for each backup operation.

### -EmailReport
Sends the report via email to configured recipients.

## Examples

### Example 1: Weekly backup health report
```powershell
PS C:\> .\Get-BackupHealthReport.ps1 -Days 7 -Format "HTML" -EmailReport
```

## Notes
- **Author:** Automation Team
- **Requires:** PSAdminCore module, backup system access permissions

## Related Links
- [New-AdminReport](../../PSAdminCore/New-AdminReport.md)
- [Send-AdminNotification](../../PSAdminCore/Send-AdminNotification.md)