---
uid: api.scripts.administration.set-aduserlifecycle
name: Set-ADUserLifecycle
---

# Set-ADUserLifecycle

## Synopsis
Manages Active Directory user account lifecycle operations including onboarding and offboarding.

## Description
This script automates user lifecycle management in Active Directory, including new user onboarding, account modifications, and secure offboarding procedures. It handles group memberships, access rights, data archival, and compliance requirements for enterprise user management.

## Syntax
```powershell
.\Set-ADUserLifecycle.ps1 [-Username] <String> [-Action] <String> [[-EffectiveDate] <DateTime>] [-ArchiveData] [-NotifyManager] [-ComplianceMode] [<CommonParameters>]
```

## Parameters

### -Username
Active Directory username for lifecycle management.

### -Action
Lifecycle action to perform (Onboard, Modify, Disable, Offboard, Archive).

### -EffectiveDate
Date when the lifecycle action should take effect.

### -ArchiveData
Archives user data during offboarding process.

### -NotifyManager
Sends notifications to user's manager about lifecycle changes.

### -ComplianceMode
Enables additional compliance logging and verification.

## Examples

### Example 1: User offboarding with data archival
```powershell
PS C:\> .\Set-ADUserLifecycle.ps1 -Username "jdoe" -Action "Offboard" -ArchiveData -NotifyManager
```

## Notes
- **Author:** Enterprise Automation Team
- **Requires:** ActiveDirectory module, PSAdminCore module, HR system integration
- **Compliance:** Includes audit logging for regulatory requirements

## Related Links
- [Disable-ADAccount](https://docs.microsoft.com/powershell/module/activedirectory/disable-adaccount)
- [Write-AdminLog](../../PSAdminCore/Write-AdminLog.md)