---
uid: articles.configuration
---
# Configuration

Several scripts in the `powershell-automation` project rely on external JSON configuration files for their operation. This article details the structure and purpose of these files.

All configuration files are located in the `config` directory at the root of the project.

## Email Notifications (`config/email.json`)

The `Send-AdminNotification` function uses this file to configure email settings.

**Structure:**

```json
{
  "SmtpServer": "smtp.example.com",
  "Port": 587,
  "UseSsl": true,
  "UseCredentials": true,
  "From": "automation@example.com",
  "DefaultRecipients": [
    "admin1@example.com",
    "admin2@example.com"
  ]
}
```

-   `SmtpServer`: The address of your SMTP server.
-   `Port`: The port number for the SMTP server.
-   `UseSsl`: Set to `true` to use SSL/TLS.
-   `UseCredentials`: Set to `true` if your SMTP server requires authentication. The script will use `Get-AdminCredential` to securely retrieve the necessary credentials.
-   `From`: The email address that notifications will be sent from.
-   `DefaultRecipients`: A list of email addresses that will receive notifications by default.

## Backup Jobs (`config/backup-config.json`)

The `Start-AutomatedBackup.ps1` script can be configured with a JSON file to define multiple backup jobs.

**Structure:**

```json
{
  "jobs": [
    {
      "name": "CriticalFiles",
      "type": "FileSystem",
      "sources": [
        "C:\\Important",
        "D:\\Data"
      ],
      "destination": "\\\\backup-server\\backups",
      "compression": true,
      "encryption": true,
      "schedule": "Daily",
      "retention": 30
    },
    {
      "name": "SQLDatabases",
      "type": "Database",
      "sources": [
        "SQLSERVER_INSTANCE"
      ],
      "destination": "\\\\backup-server\\db_backups",
      "compression": true,
      "encryption": false,
      "schedule": "Daily",
      "retention": 14
    }
  ]
}
```

-   `name`: A unique name for the backup job.
-   `type`: The type of backup. Can be `FileSystem`, `Database`, or `SystemState`.
-   `sources`: An array of paths or resources to back up.
-   `destination`: The primary location to store the backup.
-   `compression`: Set to `true` to compress the backup.
-   `encryption`: Set to `true` to encrypt the backup.
-   `schedule`: A descriptive schedule for the job (e.g., "Daily", "Weekly"). This is for informational purposes.
-   `retention`: The number of days to retain backups for this job.

## Group Mappings (`config/group-mappings.json`)

The `Sync-ADGroupMembership.ps1` script uses this file to map source groups to destination groups.

**Structure:**

```json
{
  "mappings": [
    {
      "SourceGroup": "CN=SourceAdmins,OU=Groups,DC=example,DC=com",
      "DestinationGroup": "CN=DestinationAdmins,OU=Groups,DC=example,DC=com"
    }
  ]
}
```

-   `SourceGroup`: The distinguished name of the source Active Directory group.
-   `DestinationGroup`: The distinguished name of the destination Active Directory group.