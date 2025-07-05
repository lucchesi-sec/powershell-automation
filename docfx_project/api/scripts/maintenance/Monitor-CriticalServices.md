---
uid: api.scripts.maintenance.monitor-criticalservices
name: Monitor-CriticalServices
---

# Monitor-CriticalServices

## Synopsis
Monitors critical Windows services and automatically restarts them if they stop.

## Description
This script continuously monitors a configurable list of critical services and automatically restarts them if they are found to be stopped. It includes:
- Service status monitoring
- Automatic restart with retry logic
- Dependency chain management
- Email notifications (optional)
- Comprehensive logging
- Health check reporting

## Syntax
```powershell
.\Monitor-CriticalServices.ps1 [[-ConfigPath] <String>] [[-CheckInterval] <Int32>] [[-MaxRetries] <Int32>] [-EmailNotifications] [-ReportOnly] [<CommonParameters>]
```

## Parameters

### -ConfigPath
Path to JSON configuration file containing service definitions.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| String | false | 1 | none |

### -CheckInterval
Interval in seconds between service checks.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| Int32 | false | 2 | 300 |

### -MaxRetries
Maximum number of restart attempts per service.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| Int32 | false | 3 | 3 |

### -EmailNotifications
Enable email notifications for service failures.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| SwitchParameter | false | named | False |

### -ReportOnly
Run in report-only mode without performing any restart actions.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| SwitchParameter | false | named | False |

## Examples

### Example 1: Default monitoring
```powershell
PS C:\> .\Monitor-CriticalServices.ps1
```
Runs with default settings and built-in service list.

### Example 2: Custom configuration
```powershell
PS C:\> .\Monitor-CriticalServices.ps1 -ConfigPath ".\service-config.json" -CheckInterval 180
```
Uses custom configuration and checks every 3 minutes.

## Notes
- **Author:** PowerShell Automation Project
- **Requires:** Administrator privileges to restart services

## Related Links
- [Get-Service](https://docs.microsoft.com/powershell/module/microsoft.powershell.management/get-service)
- [Send-AdminNotification](../../PSAdminCore/Send-AdminNotification.md)