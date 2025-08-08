---
uid: PSAdminCore.Set-AdminConfig
name: Set-AdminConfig
summary: Sets configuration values in JSON configuration files.
---

# Set-AdminConfig

## SYNOPSIS
Sets configuration values in JSON configuration files.

## SYNTAX

```powershell
Set-AdminConfig [-ConfigPath] <String> [-Section] <String> [-Key] <String> [-Value] <Object> [-Force] [<CommonParameters>]
```

## DESCRIPTION
The `Set-AdminConfig` function writes configuration values to JSON files in the configuration directory. It ensures proper formatting and creates backup copies before making changes.

## PARAMETERS

### -ConfigPath <String>
The path to the configuration file relative to the configuration directory.

| Type | Required | Position | Default Value |
|------|----------|----------|---------------|
| String | True | 0 | None |

### -Section <String>
The configuration section to update.

| Type | Required | Position | Default Value |
|------|----------|----------|---------------|
| String | True | 1 | None |

### -Key <String>
The configuration key to set.

| Type | Required | Position | Default Value |
|------|----------|----------|---------------|
| String | True | 2 | None |

### -Value <Object>
The value to set for the specified key.

| Type | Required | Position | Default Value |
|------|----------|----------|---------------|
| Object | True | 3 | None |

### -Force <SwitchParameter>
Overwrite existing configuration without prompting.

| Type | Required | Position | Default Value |
|------|----------|----------|---------------|
| SwitchParameter | False | Named | False |

## EXAMPLES

### Example 1: Set SMTP server configuration
```powershell
PS> Set-AdminConfig -ConfigPath "email.json" -Section "smtp" -Key "server" -Value "smtp.company.com"
```

### Example 2: Update backup retention policy
```powershell
PS> Set-AdminConfig -ConfigPath "backup-config.json" -Section "retention" -Key "days" -Value 30
```

### Example 3: Force update without confirmation
```powershell
PS> Set-AdminConfig -ConfigPath "email.json" -Section "recipients" -Key "admin" -Value "admin@company.com" -Force
```

## INPUTS

### System.String, System.Object
You can pipe objects to `Set-AdminConfig`.

## OUTPUTS

### None
This cmdlet does not return any output.

## NOTES
The function creates a backup of the original configuration file before making changes.

## RELATED LINKS
[Get-AdminConfig](Get-AdminConfig.md)
[Initialize-AdminEnvironment](Initialize-AdminEnvironment.md)