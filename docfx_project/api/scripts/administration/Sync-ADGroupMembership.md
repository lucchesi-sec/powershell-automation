---
uid: api.scripts.administration.sync-adgroupmembership
name: Sync-ADGroupMembership
---

# Sync-ADGroupMembership

## Synopsis
Synchronizes Active Directory group memberships based on organizational data and business rules.

## Description
This script automates the synchronization of Active Directory group memberships with external data sources such as HR systems, organizational charts, or role-based access control matrices. It ensures group memberships remain current with organizational changes while maintaining security and compliance requirements.

## Syntax
```powershell
.\Sync-ADGroupMembership.ps1 [[-DataSource] <String>] [[-MappingFile] <String>] [-DryRun] [-RemoveOrphans] [-AuditChanges] [-EmailReport] [<CommonParameters>]
```

## Parameters

### -DataSource
Path to external data source (CSV, database connection, or API endpoint).

### -MappingFile
Configuration file defining group membership rules and mappings.

### -DryRun
Preview changes without applying them to Active Directory.

### -RemoveOrphans
Removes users from groups when they no longer meet membership criteria.

### -AuditChanges
Enables detailed audit logging of all membership changes.

### -EmailReport
Sends summary report of synchronization results via email.

## Examples

### Example 1: Sync with HR data
```powershell
PS C:\> .\Sync-ADGroupMembership.ps1 -DataSource "C:\HR_Export.csv" -MappingFile "C:\GroupMappings.json" -AuditChanges
```

## Notes
- **Author:** Automation Team
- **Requires:** ActiveDirectory module, PSAdminCore module, data source access permissions
- **Security:** Validates all changes against business rules before applying

## Related Links
- [Add-ADGroupMember](https://docs.microsoft.com/powershell/module/activedirectory/add-adgroupmember)
- [Write-AdminLog](../../PSAdminCore/Write-AdminLog.md)