---
uid: api.scripts.maintenance.update-systempatches
name: Update-SystemPatches
---

# Update-SystemPatches

## Synopsis
Automates system patch management including download, testing, and installation.

## Description
This script provides comprehensive patch management capabilities for Windows systems including automatic patch detection, download, testing in staged environments, and controlled installation. It includes rollback capabilities, maintenance window scheduling, and detailed reporting for production patch management operations.

## Syntax
```powershell
.\Update-SystemPatches.ps1 [[-UpdateType] <String>] [[-MaintenanceWindow] <DateTime>] [-TestFirst] [-AutoReboot] [-DownloadOnly] [-GenerateReport] [<CommonParameters>]
```

## Parameters

### -UpdateType
Type of updates to install (Critical, Important, Optional, All).

### -MaintenanceWindow
Scheduled maintenance window for patch installation.

### -TestFirst
Install patches in test environment before production.

### -AutoReboot
Automatically reboot system after patch installation if required.

### -DownloadOnly
Download patches without installing them.

### -GenerateReport
Create detailed patch installation report.

## Examples

### Example 1: Critical patches with automatic reboot
```powershell
PS C:\> .\Update-SystemPatches.ps1 -UpdateType "Critical" -AutoReboot -GenerateReport
```

### Example 2: Download patches for scheduled maintenance
```powershell
PS C:\> .\Update-SystemPatches.ps1 -UpdateType "All" -DownloadOnly -MaintenanceWindow "2025-07-05 02:00:00"
```

## Notes
- **Author:** Automation Team
- **Requires:** PSAdminCore module, Windows Update service, administrator privileges
- **Caution:** Always test patches in non-production environment first

## Related Links
- [Get-WindowsUpdate](https://docs.microsoft.com/powershell/module/pswindowsupdate/get-windowsupdate)
- [Test-AdminPrivileges](../../PSAdminCore/Test-AdminPrivileges.md)