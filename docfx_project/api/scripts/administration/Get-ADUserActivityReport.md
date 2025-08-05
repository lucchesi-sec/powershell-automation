---
uid: api.scripts.administration.get-aduseractivityreport
name: Get-ADUserActivityReport
---

# Get-ADUserActivityReport

## Synopsis
Generates comprehensive Active Directory user activity reports with security insights.

## Description
This script creates detailed reports on user activity, including logon patterns, failed attempts, account changes, and security events. It supports multiple output formats and can be scheduled for regular execution to provide insights for security monitoring, compliance auditing, and user behavior analysis in a production environment.

## Syntax
```powershell
.\Get-ADUserActivityReport.ps1 [[-ReportType] <String>] [[-Days] <Int32>] [[-OutputPath] <String>] [[-Format] <String>] [-IncludeInactive] [[-SecurityThreshold] <Int32>] [-EmailReport] [<CommonParameters>]
```

## Parameters

### -ReportType
Specifies the type of report to generate.
- Summary: A high-level overview of user account statistics.
- Detailed: In-depth information for each user account.
- SecurityFocus: Highlights potential security issues like lockouts and stale accounts.
- Compliance: Focuses on password policy and account expiration.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| String | false | 1 | Summary |

**Valid values:** Summary, Detailed, SecurityFocus, Compliance

### -Days
The number of days to look back for activity data. For example, a value of 30 will include all activity within the last 30 days.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| Int32 | false | 2 | 30 |

### -OutputPath
The directory where the generated reports will be saved. If not specified, it defaults to `$env:TEMP\ADReports`.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| String | false | 3 | $env:TEMP\ADReports |

### -Format
The output format for the report.
- JSON: A structured data file suitable for integration with other tools.
- CSV: A comma-separated file for use in spreadsheets.
- HTML: A human-readable web page.
- All: Generates the report in all available formats.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| String | false | 4 | JSON |

**Valid values:** JSON, CSV, HTML, All

### -IncludeInactive
If specified, the report will include a dedicated section analyzing inactive user accounts.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| SwitchParameter | false | named | False |

### -SecurityThreshold
The number of failed logon attempts to flag as suspicious. Any user with a `BadPwdCount` greater than or equal to this value will be included in the 'SuspiciousUsers' section of the SecurityFocus report.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| Int32 | false | 5 | 5 |

### -EmailReport
If specified, the script will email the generated report to the recipients configured in `config/email.json`.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| SwitchParameter | false | named | False |

## Examples

### Example 1: Security-focused report
```powershell
PS C:\> .\Get-ADUserActivityReport.ps1 -ReportType "SecurityFocus" -Days 7 -Format "HTML"
```

This command generates a security-focused HTML report for the last 7 days of activity.

### Example 2: Compliance report with email
```powershell
PS C:\> .\Get-ADUserActivityReport.ps1 -ReportType "Compliance" -Days 90 -EmailReport
```

This command generates a compliance report for the last 90 days and emails it to the configured recipients.

## Notes
- **Author:** Automation Team
- **Version:** 1.1.0
- **Requires:** ActiveDirectory module, PSAdminCore module, and appropriate permissions to read Active Directory user properties and security event logs from domain controllers.

## Related Links
- [Get-ADUser](https://docs.microsoft.com/powershell/module/activedirectory/get-aduser)
- [Write-AdminLog](../../PSAdminCore/Write-AdminLog.md)
- [New-AdminReport](../../PSAdminCore/New-AdminReport.md)