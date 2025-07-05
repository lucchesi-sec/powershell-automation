---
uid: api.psadmincore.write-adminlog
name: Write-AdminLog
---

# Write-AdminLog

## Synopsis
Writes structured log entries to a centralized admin log file.

## Description
This function provides a standardized mechanism for writing log entries, which is critical for maintaining audit trails and troubleshooting automated processes in an enterprise setting.

By logging to a common directory in %ProgramData%, it ensures that log data from all scripts using this platform is collected in one place. The structured log entries include timestamps, severity levels, and categories, allowing for easier parsing, filtering, and analysis, which is essential for security incident response and operational monitoring.

## Syntax
```powershell
Write-AdminLog [-Message] <String> [[-Level] <String>] [[-Category] <String>] [<CommonParameters>]
```

## Parameters

### -Message
The core content of the log entry. This should be a descriptive message explaining the event that occurred. This parameter is mandatory.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| String | true | 1 | none |

### -Level
Specifies the severity of the log entry, which helps in prioritizing and filtering logs.
- Information: For routine events and status updates.
- Warning: For potential issues that do not impede execution but should be noted.
- Error: For failures or critical issues that require attention.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| String | false | 2 | Information |

**Valid values:** Information, Warning, Error

### -Category
A string used to classify the log entry (e.g., 'UserLifecycle', 'Backup', 'SystemCheck'). This allows for filtering logs by functional area, which simplifies troubleshooting and reporting.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| String | false | 3 | General |

## Examples

### Example 1: Error logging
```powershell
PS C:\> Write-AdminLog -Message "Failed to connect to server XYZ." -Level Error -Category "Connectivity"
```

This command writes an error-level log entry with the specified message and category to the daily admin log file (e.g., C:\ProgramData\PowerShellAutomation\Logs\AdminLog_20250704.log).

### Example 2: System health monitoring
```powershell
PS C:\> Get-Service | ForEach-Object {
    if ($_.Status -eq 'Stopped') {
        Write-AdminLog -Message "Service '$($_.Name)' is stopped." -Level Warning -Category 'SystemCheck'
    }
}
```

This command iterates through all system services and writes a warning log entry for each service that is found in a 'Stopped' state. This is useful for automated system health checks.

## Notes
- **Author:** Enterprise Automation Team
- **Version:** 1.2.0
- **Prerequisites:** The script must have write permissions to the log directory located at %ProgramData%\PowerShellAutomation\Logs.

## Related Links
- [Get-Content](https://docs.microsoft.com/powershell/module/microsoft.powershell.management/get-content)
- [Out-File](https://docs.microsoft.com/powershell/module/microsoft.powershell.utility/out-file)