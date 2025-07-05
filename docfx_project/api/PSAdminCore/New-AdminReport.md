---
uid: api.psadmincore.new-adminreport
name: New-AdminReport
---

# New-AdminReport

## Synopsis
Creates standardized administrative reports in various formats (HTML, CSV, JSON).

## Description
This function is a versatile reporting engine for creating standardized administrative reports from any PowerShell object data. In an enterprise context, this is essential for compliance, auditing, and operational visibility.

It supports multiple output formats to serve different needs:
- HTML: For human-readable reports suitable for management.
- CSV: For easy import into spreadsheets or other data analysis tools.
- JSON: For integration with other applications and services.

## Syntax
```powershell
New-AdminReport [-Title] <String> [-Data] <Object> [[-Format] <String>] [[-OutputPath] <String>] [<CommonParameters>]
```

## Parameters

### -Title
The main title of the report, which is used in the HTML document title and as a filename component. This parameter is mandatory.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| String | true | 1 | none |

### -Data
The dataset for the report, which should be an array of PowerShell objects. The properties of these objects will become the columns in the report. This parameter is mandatory.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| Object | true | 2 | none |

### -Format
The output format of the report. 'HTML' generates a styled web page, 'CSV' creates a comma-separated file, and 'JSON' produces a structured data file.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| String | false | 3 | HTML |

**Valid values:** HTML, CSV, JSON

### -OutputPath
The file system path where the generated report will be saved. If not provided, it defaults to the central reports directory at %ProgramData%\PowerShellAutomation\Reports.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| String | false | 4 | none |

## Outputs
**PSCustomObject**

Returns an object containing report metadata including Title, Format, Path, and GeneratedDate.

## Examples

### Example 1: CSV user report
```powershell
PS C:\> $users = Get-ADUser -Filter 'enabled -eq $false' | Select-Object Name,SamAccountName
PS C:\> New-AdminReport -Title "Disabled AD Users" -Data $users -Format CSV -OutputPath "C:\Reports"
```

This command generates a CSV report of all disabled Active Directory users and saves it to C:\Reports.

### Example 2: HTML process report
```powershell
PS C:\> $processData = Get-Process | Sort-Object -Property WS -Descending | Select-Object -First 10 Name, WS, CPU
PS C:\> New-AdminReport -Title "Top 10 Memory-Consuming Processes" -Data $processData -Format HTML
```

This command gathers data on the top 10 memory-consuming processes and generates a formatted HTML report. The report is saved to the default reports directory for easy access and review.

## Notes
- **Author:** Enterprise Automation Team
- **Version:** 1.2.0
- **Prerequisites:** The data provided to this function may come from other modules, such as the ActiveDirectory module, which would need to be installed and available on the system.

## Related Links
- [ConvertTo-Html](https://docs.microsoft.com/powershell/module/microsoft.powershell.utility/convertto-html)
- [Export-Csv](https://docs.microsoft.com/powershell/module/microsoft.powershell.utility/export-csv)
- [ConvertTo-Json](https://docs.microsoft.com/powershell/module/microsoft.powershell.utility/convertto-json)