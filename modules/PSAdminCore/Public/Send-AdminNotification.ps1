function Send-AdminNotification {
    <#
    .SYNOPSIS
        Sends email notifications using configured SMTP settings.
    .DESCRIPTION
        Sends email notifications using settings from the email configuration file.
        Supports attachments, custom recipients, and various email priorities.
        Falls back to default settings if configuration is not available.
    .PARAMETER Subject
        The subject line of the email.
    .PARAMETER Body
        The body content of the email. Supports HTML if BodyAsHtml is specified.
    .PARAMETER To
        Override the default recipient list from configuration.
    .PARAMETER Cc
        Carbon copy recipients.
    .PARAMETER Bcc
        Blind carbon copy recipients.
    .PARAMETER AttachmentPath
        Array of file paths to attach to the email.
    .PARAMETER Priority
        Email priority: Normal, High, or Low.
    .PARAMETER BodyAsHtml
        If specified, treats the body as HTML content.
    .PARAMETER Credential
        PSCredential object for SMTP authentication. If not provided, attempts to retrieve from credential store.
    .EXAMPLE
        Send-AdminNotification -Subject "Backup Complete" -Body "Daily backup completed successfully"
    .EXAMPLE
        Send-AdminNotification -Subject "Error Report" -Body $htmlReport -BodyAsHtml -Priority High
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Subject,

        [Parameter(Mandatory = $true)]
        [string]$Body,

        [Parameter(Mandatory = $false)]
        [string[]]$To,

        [Parameter(Mandatory = $false)]
        [string[]]$Cc,

        [Parameter(Mandatory = $false)]
        [string[]]$Bcc,

        [Parameter(Mandatory = $false)]
        [string[]]$AttachmentPath,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Normal', 'High', 'Low')]
        [string]$Priority = 'Normal',

        [Parameter(Mandatory = $false)]
        [switch]$BodyAsHtml,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    try {
        Write-AdminLog -Message "Preparing to send notification: $Subject" -Level Info

        # Get email configuration
        $emailConfig = Get-AdminConfig -ConfigName 'email'

        if (-not $emailConfig -or -not $emailConfig.SmtpServer) {
            throw "Email configuration not found or incomplete. Please configure email settings."
        }

        # Build email parameters
        $mailParams = @{
            SmtpServer = $emailConfig.SmtpServer
            Subject    = $Subject
            Body       = $Body
            Priority   = $Priority
        }

        # Add From address
        if ($emailConfig.From) {
            $mailParams['From'] = $emailConfig.From
        } else {
            $mailParams['From'] = "$env:COMPUTERNAME@$env:USERDNSDOMAIN"
        }

        # Add To recipients
        if ($To) {
            $mailParams['To'] = $To
        } elseif ($emailConfig.To) {
            $mailParams['To'] = $emailConfig.To
        } else {
            throw "No recipients specified and none configured."
        }

        # Add optional recipients
        if ($Cc) {
            $mailParams['Cc'] = $Cc
        } elseif ($emailConfig.Cc) {
            $mailParams['Cc'] = $emailConfig.Cc
        }

        if ($Bcc) {
            $mailParams['Bcc'] = $Bcc
        }

        # Add SMTP port if configured
        if ($emailConfig.SmtpPort) {
            $mailParams['Port'] = $emailConfig.SmtpPort
        }

        # Add SSL if configured
        if ($emailConfig.UseSsl) {
            $mailParams['UseSsl'] = $true
        }

        # Handle HTML body
        if ($BodyAsHtml) {
            $mailParams['BodyAsHtml'] = $true
        }

        # Handle attachments
        if ($AttachmentPath) {
            $validAttachments = @()
            foreach ($path in $AttachmentPath) {
                if (Test-Path $path) {
                    $validAttachments += $path
                } else {
                    Write-AdminLog -Message "Attachment not found: $path" -Level Warning
                }
            }
            if ($validAttachments.Count -gt 0) {
                $mailParams['Attachments'] = $validAttachments
            }
        }

        # Handle credentials
        if ($Credential) {
            $mailParams['Credential'] = $Credential
        } elseif ($emailConfig.RequireAuthentication) {
            # Try to get credentials from credential store
            $storedCred = Get-AdminCredential -Name 'SmtpCredential' -ErrorAction SilentlyContinue
            if ($storedCred) {
                $mailParams['Credential'] = $storedCred
            } else {
                Write-AdminLog -Message "SMTP authentication required but no credentials provided" -Level Warning
            }
        }

        # Send the email
        Send-MailMessage @mailParams -ErrorAction Stop

        Write-AdminLog -Message "Notification sent successfully: $Subject" -Level Success
        
        # Log recipients for audit
        $recipientList = ($mailParams['To'] -join ', ')
        Write-AdminLog -Message "Email sent to: $recipientList" -Level Info
        
        return $true
    }
    catch {
        Write-AdminLog -Message "Failed to send notification: $_" -Level Error
        
        # Check for common SMTP errors and provide helpful messages
        if ($_.Exception.Message -match 'relay|authentication|credentials') {
            Write-AdminLog -Message "This appears to be an authentication issue. Check SMTP credentials and server settings." -Level Warning
        } elseif ($_.Exception.Message -match 'connect|timeout|unreachable') {
            Write-AdminLog -Message "Unable to connect to SMTP server. Check server address and port." -Level Warning
        }
        
        throw
    }
}