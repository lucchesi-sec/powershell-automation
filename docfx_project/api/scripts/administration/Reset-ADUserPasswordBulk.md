---
uid: api.scripts.administration.reset-aduserpasswordbulk
name: Reset-ADUserPasswordBulk
---

# Reset-ADUserPasswordBulk

## Synopsis
Performs bulk password resets for Active Directory users with security controls.

## Description
This script provides secure bulk password reset capabilities for Active Directory users. It includes security validation, audit logging, and notification features. Supports exclusion lists for privileged accounts and includes comprehensive error handling for enterprise password management operations.

## Syntax
```powershell
.\Reset-ADUserPasswordBulk.ps1 [-UserList] <String[]> [[-NewPassword] <String>] [-RandomPasswords] [-ExcludePrivileged] [-NotifyUsers] [-AuditOnly] [<CommonParameters>]
```

## Parameters

### -UserList
Array of usernames or path to file containing usernames for password reset.

### -NewPassword
New password to set for all users (if not using random passwords).

### -RandomPasswords
Generates unique random passwords for each user.

### -ExcludePrivileged
Excludes privileged accounts from bulk password reset operations.

### -NotifyUsers
Sends password reset notifications to users or their managers.

### -AuditOnly
Performs validation and logging without actually resetting passwords.

## Examples

### Example 1: Bulk password reset with random passwords
```powershell
PS C:\> .\Reset-ADUserPasswordBulk.ps1 -UserList "C:\Users.txt" -RandomPasswords -ExcludePrivileged -NotifyUsers
```

## Notes
- **Author:** Enterprise Automation Team
- **Requires:** ActiveDirectory module, PSAdminCore module, privileged AD permissions
- **Security:** Always excludes domain administrator accounts from bulk operations

## Related Links
- [Set-ADAccountPassword](https://docs.microsoft.com/powershell/module/activedirectory/set-adaccountpassword)
- [Write-AdminLog](../../PSAdminCore/Write-AdminLog.md)