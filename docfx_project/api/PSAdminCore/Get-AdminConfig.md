---
uid: PSAdminCore.Get-AdminConfig
name: Get-AdminConfig
summary: Retrieves configuration values from JSON configuration files.
---

# Get-AdminConfig

## SYNOPSIS
Retrieves configuration values from JSON configuration files.

## SYNTAX

```powershell
Get-AdminConfig [-ConfigPath] <String> [-Section] <String> [[-Key] <String>] [<CommonParameters>]
```

## DESCRIPTION
The `Get-AdminConfig` function reads configuration values from JSON files stored in the configuration directory. It provides a standardized way to access configuration settings across all scripts and modules.

## PARAMETERS

### -ConfigPath <String>
The path to the configuration file relative to the configuration directory.

| Type | Required | Position | Default Value |
|------|----------|----------|---------------|
| String | True | 0 | None |

### -Section <String>
The configuration section to retrieve.

| Type | Required | Position | Default Value |
|------|----------|----------|---------------|
| String | True | 1 | None |

### -Key <String>
The specific configuration key to retrieve. If not provided, returns the entire section.

| Type | Required | Position | Default Value |
|------|----------|----------|---------------|
| String | False | 2 | None |

## EXAMPLES

### Example 1: Get entire email configuration section
```powershell
PS> Get-AdminConfig -ConfigPath "email.json" -Section "smtp"
```

### Example 2: Get specific SMTP server setting
```powershell
PS> Get-AdminConfig -ConfigPath "email.json" -Section "smtp" -Key "server"
smtp.company.com
```

### Example 3: Get backup configuration
```powershell
PS> Get-AdminConfig -ConfigPath "backup-config.json" -Section "azure"
```

## INPUTS

### System.String
You can pipe a string that contains the configuration path to `Get-AdminConfig`.

## OUTPUTS

### System.Object
Returns the configuration value(s) as PowerShell objects.

## NOTES
The configuration directory is determined by the `Initialize-AdminEnvironment` function and defaults to `$env:ProgramData\PSAutomation\config`.

## RELATED LINKS
[Set-AdminConfig](Set-AdminConfig.md)
[Initialize-AdminEnvironment](Initialize-AdminEnvironment.md)