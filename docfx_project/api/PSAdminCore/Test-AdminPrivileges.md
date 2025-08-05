---
uid: api.psadmincore.test-adminprivileges
name: Test-AdminPrivileges
---

# Test-AdminPrivileges

## Synopsis
Tests if the current PowerShell session has administrative privileges.

## Description
In a production environment, it is critical to ensure that scripts performing sensitive operations (e.g., modifying system configurations, accessing restricted resources) do so only when explicitly run with elevated permissions. This function provides a reliable way to check for these privileges.

It determines if the current user's security principal is a member of the built-in 'Administrator' role using the .NET [System.Security.Principal.WindowsPrincipal] class. This method is more robust than checking the process elevation token, as it verifies role membership directly.

## Syntax
```powershell
Test-AdminPrivileges [<CommonParameters>]
```

## Parameters
This function does not accept any parameters.

## Outputs
**System.Boolean**

Returns `$true` if the current session has administrative privileges, otherwise `$false`.

## Examples

### Example 1: Basic privilege check
```powershell
PS C:\> if (Test-AdminPrivileges) { Write-Host "Running with admin rights." } else { Write-Host "Running with standard user rights." }
```

This command checks for admin rights and prints a message indicating the privilege level. The function returns $true if elevated, otherwise $false.

### Example 2: Script security validation
```powershell
PS C:\> if (-not (Test-AdminPrivileges)) {
    Write-Error "This script requires administrative privileges. Please run it in an elevated PowerShell session."
    exit 1
}
# Proceed with administrative tasks...
```

This command is a security best practice used at the beginning of a script to ensure it stops execution if not run with administrative rights, preventing errors and enforcing security policies.

## Notes
- **Author:** Automation Team
- **Version:** 1.2.0
- **Prerequisites:** Requires a Windows environment to access the WindowsPrincipal class. No special permissions are needed to run the check itself.

## Related Links
- [about_Comment_Based_Help](https://docs.microsoft.com/powershell/module/microsoft.powershell.core/about/about_comment_based_help)