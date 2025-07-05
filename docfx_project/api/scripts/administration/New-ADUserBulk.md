---
uid: api.scripts.administration.new-aduserbulk
name: New-ADUserBulk
---

# New-ADUserBulk

## Synopsis
Creates multiple Active Directory users from a CSV file with comprehensive configuration options.

## Description
This script automates the bulk creation of Active Directory user accounts from a CSV file. It includes password generation, group membership assignment, and organizational unit placement. Supports dry-run mode for testing and comprehensive error handling.

## Syntax
```powershell
.\New-ADUserBulk.ps1 [-CsvPath] <String> [[-OrganizationalUnit] <String>] [[-DefaultPassword] <String>] [[-Domain] <String>] [-DryRun] [-SendPasswordEmail] [<CommonParameters>]
```

## Parameters

### -CsvPath
Path to the CSV file containing user information.
Required columns: FirstName, LastName, Username, Department, Title
Optional columns: Email, Manager, Groups, OU, Password

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| String | true | 1 | none |

### -OrganizationalUnit
Default OU where users will be created if not specified in CSV.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| String | false | 2 | none |

### -DefaultPassword
Default password for users if not specified in CSV. If not provided, random passwords are generated.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| String | false | 3 | none |

### -Domain
Domain name for user principal names. Defaults to current domain.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| String | false | 4 | none |

### -DryRun
If specified, shows what would be created without actually creating users.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| SwitchParameter | false | named | False |

### -SendPasswordEmail
If specified, sends password information to managers (requires email configuration).

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| SwitchParameter | false | named | False |

## Examples

### Example 1: Basic bulk user creation
```powershell
PS C:\> .\New-ADUserBulk.ps1 -CsvPath "C:\NewUsers.csv" -OrganizationalUnit "OU=Users,DC=company,DC=com"
```

### Example 2: Dry run test
```powershell
PS C:\> .\New-ADUserBulk.ps1 -CsvPath "C:\NewUsers.csv" -DryRun
```

## Notes
- **Author:** System Administrator
- **Requires:** ActiveDirectory module, PSAdminCore module
- **CSV Format Example:**
  ```
  FirstName,LastName,Username,Department,Title,Email,Manager,Groups,OU
  John,Doe,jdoe,IT,Administrator,jdoe@company.com,jane.smith,IT-Admins;Users,"OU=IT,DC=company,DC=com"
  ```

## Related Links
- [New-ADUser](https://docs.microsoft.com/powershell/module/activedirectory/new-aduser)
- [Test-AdminParameter](../../PSAdminCore/Test-AdminParameter.md)
- [Write-AdminLog](../../PSAdminCore/Write-AdminLog.md)