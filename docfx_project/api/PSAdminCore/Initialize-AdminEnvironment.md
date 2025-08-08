---
uid: PSAdminCore.Initialize-AdminEnvironment
name: Initialize-AdminEnvironment
summary: Initializes the PowerShell automation environment with required directories and configuration.
---

# Initialize-AdminEnvironment

## SYNOPSIS
Initializes the PowerShell automation environment with required directories and configuration.

## SYNTAX

```powershell
Initialize-AdminEnvironment [[-ConfigPath] <String>] [[-LogPath] <String>] [-Force] [<CommonParameters>]
```

## DESCRIPTION
The `Initialize-AdminEnvironment` function sets up the necessary directory structure and configuration files for the PowerShell automation platform. It creates default configuration files if they don't exist and validates the environment.

## PARAMETERS

### -ConfigPath <String>
The path to the configuration directory. Defaults to `$env:ProgramData\PSAutomation\config`.

| Type | Required | Position | Default Value |
|------|----------|----------|---------------|
| String | False | 0 | `$env:ProgramData\PSAutomation\config` |

### -LogPath <String>
The path to the log directory. Defaults to `$env:ProgramData\PSAutomation\logs`.

| Type | Required | Position | Default Value |
|------|----------|----------|---------------|
| String | False | 1 | `$env:ProgramData\PSAutomation\logs` |

### -Force <SwitchParameter>
Recreate the environment even if it already exists.

| Type | Required | Position | Default Value |
|------|----------|----------|---------------|
| SwitchParameter | False | Named | False |

## EXAMPLES

### Example 1: Initialize with default paths
```powershell
PS> Initialize-AdminEnvironment
```

### Example 2: Initialize with custom paths
```powershell
PS> Initialize-AdminEnvironment -ConfigPath "C:\Automation\Config" -LogPath "C:\Automation\Logs"
```

### Example 3: Force reinitialization
```powershell
PS> Initialize-AdminEnvironment -Force
```

## INPUTS

### System.String
You can pipe strings to `Initialize-AdminEnvironment`.

## OUTPUTS

### System.Object
Returns an object containing the initialized paths and configuration.

## NOTES
This function must be run with administrative privileges to create directories in the ProgramData folder.

## RELATED LINKS
[Get-AdminConfig](Get-AdminConfig.md)
[Write-AdminLog](Write-AdminLog.md)