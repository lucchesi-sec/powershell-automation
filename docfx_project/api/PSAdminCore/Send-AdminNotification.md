---
uid: api.psadmincore.send-adminnotification
name: Send-AdminNotification
---

# Send-AdminNotification

## Synopsis
Sends administrative notifications via email or other configured channels.

## Description
This function provides a centralized notification service for enterprise automation scripts, enabling real-time alerts for critical events. It is designed to integrate with a corporate SMTP server for sending emails, with configuration managed in a 'config/email.json' file.

For security, it can retrieve SMTP credentials from a secure store via Get-AdminCredential, ensuring that passwords are not hard-coded. If email is not configured, it provides a fallback by writing notifications to a local log file, ensuring no event is lost.

## Syntax
```powershell
Send-AdminNotification [-Subject] <String> [-Message] <String> [[-Priority] <String>] [[-Recipients] <String[]>] [<CommonParameters>]
```

## Parameters

### -Subject
A concise summary of the notification, used as the email subject line. This parameter is mandatory.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| String | true | 1 | none |

### -Message
The detailed content of the notification, which forms the body of the email or log entry. This parameter is mandatory.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| String | true | 2 | none |

### -Priority
The priority level of the notification ('Low', 'Normal', 'High'), which can be used by recipients to filter or prioritize alerts.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| String | false | 3 | Normal |

**Valid values:** Low, Normal, High

### -Recipients
An array of recipient email addresses. If this parameter is not provided, the function will use a default list of recipients defined in the 'config/email.json' configuration file.

| Type | Required | Position | Default value |
|------|----------|----------|---------------|
| String[] | false | 4 | none |

## Examples

### Example 1: Basic notification
```powershell
PS C:\> Send-AdminNotification -Subject "Backup Job Completed" -Message "The nightly backup job finished successfully." -Priority Normal
```

This command sends an email notification with the specified subject and message to the default recipients.

### Example 2: Critical service alert
```powershell
PS C:\> $failedServices = Get-Service | Where-Object { $_.Status -ne 'Running' }
if ($failedServices) {
    $serviceNames = ($failedServices.Name | Out-String).Trim()
    $errorMessage = "The following critical services are not running:`n$serviceNames"
    Send-AdminNotification -Subject "Critical Service Alert" -Message $errorMessage -Priority High -Recipients "it-admins@example.com"
}
```

This command checks for non-running services and sends a high-priority email to the IT administrators if any are found. This is a typical use case for automated monitoring and alerting.

## Notes
- **Author:** Enterprise Automation Team
- **Version:** 1.2.0
- **Prerequisites:** For email notifications to work, a valid 'config/email.json' file must be present and correctly configured with SMTP server details. If authentication is required, credentials should be stored using Get-AdminCredential.

## Related Links
- [Send-MailMessage](https://docs.microsoft.com/powershell/module/microsoft.powershell.utility/send-mailmessage)
- [Get-AdminCredential](Get-AdminCredential.md)