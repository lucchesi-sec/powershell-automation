---
uid: PSAdminCore.Test-AdminConnectivity
name: Test-AdminConnectivity
summary: Tests connectivity to required services and systems.
---

# Test-AdminConnectivity

## SYNOPSIS
Tests connectivity to required services and systems.

## SYNTAX

```powershell
Test-AdminConnectivity [-Service] <String> [[-Timeout] <Int32>] [[-Retries] <Int32>] [<CommonParameters>]
```

## DESCRIPTION
The `Test-AdminConnectivity` function validates connectivity to critical services such as Active Directory, SMTP servers, cloud storage, and other dependencies required by automation scripts.

## PARAMETERS

### -Service <String>
The service to test connectivity for. Valid values are: "ActiveDirectory", "SMTP", "Azure", "AWS", "GoogleCloud", "Network".

| Type | Required | Position | Default Value |
|------|----------|----------|---------------|
| String | True | 0 | None |

### -Timeout <Int32>
The timeout in seconds for each connection attempt. Default is 30 seconds.

| Type | Required | Position | Default Value |
|------|----------|----------|---------------|
| Int32 | False | 1 | 30 |

### -Retries <Int32>
The number of retry attempts. Default is 3.

| Type | Required | Position | Default Value |
|------|----------|----------|---------------|
| Int32 | False | 2 | 3 |

## EXAMPLES

### Example 1: Test Active Directory connectivity
```powershell
PS> Test-AdminConnectivity -Service "ActiveDirectory"
True
```

### Example 2: Test SMTP with custom timeout
```powershell
PS> Test-AdminConnectivity -Service "SMTP" -Timeout 10
True
```

### Example 3: Test cloud storage connectivity
```powershell
PS> Test-AdminConnectivity -Service "Azure"
WARNING: Azure storage connectivity test failed
False
```

## INPUTS

### System.String
You can pipe service names to `Test-AdminConnectivity`.

## OUTPUTS

### System.Boolean
Returns $true if connectivity is successful, $false otherwise.

## NOTES
This function uses different testing methods depending on the service type:
- Active Directory: LDAP bind test
- SMTP: TCP connection to port 25/587
- Cloud: API endpoint test with authentication
- Network: ICMP ping test

## RELATED LINKS
[Get-AdminConfig](Get-AdminConfig.md)
[Test-AdminPrivileges](Test-AdminPrivileges.md)