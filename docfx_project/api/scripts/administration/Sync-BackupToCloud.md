---
uid: api.scripts.administration.sync-backuptocloud
name: Sync-BackupToCloud
---

# Sync-BackupToCloud

## Synopsis
Synchronizes local backup files to cloud storage with encryption and verification.

## Description
This script provides secure synchronization of backup files to cloud storage providers. It includes encryption, compression, bandwidth throttling, and integrity verification. Supports multiple cloud providers and includes comprehensive logging for production backup-to-cloud operations.

## Syntax
```powershell
.\Sync-BackupToCloud.ps1 [[-LocalPath] <String>] [[-CloudProvider] <String>] [[-Container] <String>] [-Encrypt] [-Compress] [-BandwidthLimit] [-VerifySync] [<CommonParameters>]
```

## Parameters

### -LocalPath
Local directory containing backup files to synchronize.

### -CloudProvider
Cloud storage provider (Azure, AWS, Google Cloud).

### -Container
Cloud storage container or bucket name.

### -Encrypt
Enables encryption for cloud-stored backup files.

### -Compress
Compresses backup files before uploading to reduce transfer time.

### -BandwidthLimit
Limits bandwidth usage for cloud synchronization.

### -VerifySync
Verifies integrity of synchronized files in cloud storage.

## Examples

### Example 1: Encrypted sync to Azure
```powershell
PS C:\> .\Sync-BackupToCloud.ps1 -LocalPath "C:\Backups" -CloudProvider "Azure" -Container "backups" -Encrypt -VerifySync
```

## Notes
- **Author:** Automation Team
- **Requires:** PSAdminCore module, cloud provider credentials, network connectivity
- **Security:** Includes client-side encryption and secure credential management

## Related Links
- [Get-AdminCredential](../../PSAdminCore/Get-AdminCredential.md)
- [Write-AdminLog](../../PSAdminCore/Write-AdminLog.md)