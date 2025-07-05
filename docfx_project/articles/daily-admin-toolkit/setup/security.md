# Security Guide

## Overview

The Daily Admin Toolkit handles sensitive operations including user account management, service control, and remote system access. This guide establishes security best practices to protect your environment while maintaining operational efficiency.

## Security Principles

### Defense in Depth

The Daily Admin Toolkit implements multiple security layers:

1. **Authentication** - Verify user identity
2. **Authorization** - Validate permissions for operations
3. **Encryption** - Protect data in transit and at rest
4. **Auditing** - Log all security-relevant activities
5. **Monitoring** - Detect suspicious activities
6. **Isolation** - Limit blast radius of potential compromises

### Principle of Least Privilege

- Grant minimum necessary permissions
- Use dedicated service accounts for automation
- Implement just-in-time (JIT) access where possible
- Regular permission audits and cleanup

### Zero Trust Approach

- Verify every connection and transaction
- Assume breach mentality
- Continuous validation of trust
- Network segmentation and monitoring

## Authentication and Authorization

### Service Account Management

**Dedicated Service Accounts:**
```powershell
# Create dedicated service account for Daily Admin Toolkit
New-ADUser -Name "SVC_DailyAdminToolkit" -UserPrincipalName "SVC_DailyAdminToolkit@contoso.com" -AccountPassword (Read-Host "Password" -AsSecureString) -PasswordNeverExpires $true -CannotChangePassword $true -Enabled $true

# Set service principal names
setspn -A PowerShellRemoting/SVC_DailyAdminToolkit contoso\SVC_DailyAdminToolkit

# Add to required security groups
Add-ADGroupMember -Identity "Remote Management Users" -Members "SVC_DailyAdminToolkit"
Add-ADGroupMember -Identity "Account Operators" -Members "SVC_DailyAdminToolkit"  # Only if unlock/reset needed
```

**Group Managed Service Accounts (gMSA) - Recommended:**
```powershell
# Create gMSA for enhanced security
New-ADServiceAccount -Name "gMSA_DailyAdminToolkit" -DNSHostName "gmsa.contoso.com" -PrincipalsAllowedToRetrieveManagedPassword "AdminWorkstations"

# Install on authorized computers
Install-ADServiceAccount -Identity "gMSA_DailyAdminToolkit"

# Test gMSA
Test-ADServiceAccount -Identity "gMSA_DailyAdminToolkit"
```

### Secure Credential Storage

**Windows Credential Manager Integration:**
```powershell
function Set-SecureCredential {
    param(
        [Parameter(Mandatory)]
        [string]$TargetName,
        
        [Parameter(Mandatory)]
        [PSCredential]$Credential,
        
        [string]$Description = "Daily Admin Toolkit Credential"
    )
    
    try {
        # Store credential securely in Windows Credential Manager
        $username = $Credential.UserName
        $password = $Credential.GetNetworkCredential().Password
        
        # Use cmdkey for reliable storage
        $result = Start-Process -FilePath "cmdkey" -ArgumentList "/generic:$TargetName", "/user:$username", "/pass:$password" -Wait -PassThru -WindowStyle Hidden
        
        if ($result.ExitCode -eq 0) {
            Write-Host "✅ Credential stored securely for $TargetName" -ForegroundColor Green
            
            # Log credential storage (without sensitive data)
            Write-EventLog -LogName Application -Source "DailyAdminToolkit" -EventID 1001 -EntryType Information -Message "Credential stored for target: $TargetName, User: $username"
        } else {
            throw "Failed to store credential (Exit code: $($result.ExitCode))"
        }
    } catch {
        Write-Error "Failed to store credential: $($_.Exception.Message)"
        Write-EventLog -LogName Application -Source "DailyAdminToolkit" -EventID 1002 -EntryType Error -Message "Failed to store credential for target: $TargetName, Error: $($_.Exception.Message)"
    }
}

function Get-SecureCredential {
    param(
        [Parameter(Mandatory)]
        [string]$TargetName
    )
    
    try {
        # Retrieve credential from Windows Credential Manager
        $credResult = & cmdkey /list:$TargetName 2>$null
        
        if ($credResult -match "User: (.+)") {
            $username = $Matches[1]
            
            # For automation scenarios, use stored credentials
            # For interactive scenarios, prompt for password
            $securePassword = Read-Host "Enter password for $username" -AsSecureString
            $credential = New-Object PSCredential($username, $securePassword)
            
            Write-EventLog -LogName Application -Source "DailyAdminToolkit" -EventID 1003 -EntryType Information -Message "Credential retrieved for target: $TargetName, User: $username"
            
            return $credential
        } else {
            throw "Credential not found for target: $TargetName"
        }
    } catch {
        Write-Warning "Failed to retrieve credential for $TargetName`: $($_.Exception.Message)"
        return $null
    }
}

# Usage
$serviceCred = Get-Credential -Message "Enter service account credentials"
Set-SecureCredential -TargetName "DailyAdminToolkit_ServiceAccount" -Credential $serviceCred
```

**Azure Key Vault Integration (Advanced):**
```powershell
function Set-KeyVaultCredential {
    param(
        [Parameter(Mandatory)]
        [string]$VaultName,
        
        [Parameter(Mandatory)]
        [string]$SecretName,
        
        [Parameter(Mandatory)]
        [PSCredential]$Credential
    )
    
    try {
        # Ensure Azure PowerShell module is available
        if (-not (Get-Module -ListAvailable Az.KeyVault)) {
            Write-Warning "Azure PowerShell module not found. Install with: Install-Module Az"
            return
        }
        
        Import-Module Az.KeyVault
        
        # Convert credential to secure format for Key Vault
        $credentialObject = @{
            Username = $Credential.UserName
            Password = $Credential.GetNetworkCredential().Password
        } | ConvertTo-Json
        
        $secureCredential = ConvertTo-SecureString $credentialObject -AsPlainText -Force
        
        # Store in Key Vault
        Set-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName -SecretValue $secureCredential
        
        Write-Host "✅ Credential stored in Azure Key Vault: $VaultName/$SecretName" -ForegroundColor Green
    } catch {
        Write-Error "Failed to store credential in Key Vault: $($_.Exception.Message)"
    }
}
```

### Role-Based Access Control (RBAC)

**Define Security Roles:**
```powershell
# Security roles for Daily Admin Toolkit
$SecurityRoles = @{
    
    # Level 1: Read-Only Observer
    "DailyAdminToolkit_ReadOnly" = @{
        Description = "Read-only access to monitoring functions"
        Permissions = @(
            "Get-ServerHealth",
            "Get-ServiceStatus", 
            "Test-ServerConnectivity",
            "Get-ProcessByName",
            "Get-ADUserLastLogon",
            "Get-ADUserMembership"
        )
        Restrictions = @(
            "NoModificationOperations",
            "ReadOnlyAccess",
            "LogAllActivities"
        )
    }
    
    # Level 2: Standard Administrator
    "DailyAdminToolkit_StandardAdmin" = @{
        Description = "Standard administrative operations"
        Permissions = @(
            "Unlock-ADAccount",
            "Reset-ADUserPassword",
            "Restart-RemoteService",
            "Stop-ProcessRemotely"
        ) + $SecurityRoles["DailyAdminToolkit_ReadOnly"].Permissions
        Restrictions = @(
            "RequireConfirmation",
            "LogAllOperations",
            "BusinessHoursOnly"
        )
    }
    
    # Level 3: Emergency Administrator
    "DailyAdminToolkit_EmergencyAdmin" = @{
        Description = "Emergency operations with elevated privileges"
        Permissions = @(
            "ForceOperations",
            "BypassSafetyChecks",
            "24x7Access"
        ) + $SecurityRoles["DailyAdminToolkit_StandardAdmin"].Permissions
        Restrictions = @(
            "RequireJustification",
            "MandatoryAuditing",
            "ManagerApproval"
        )
    }
}

# Create Active Directory security groups for RBAC
foreach ($role in $SecurityRoles.Keys) {
    try {
        New-ADGroup -Name $role -GroupScope DomainLocal -GroupCategory Security -Description $SecurityRoles[$role].Description -Path "OU=Security Groups,DC=contoso,DC=com"
        Write-Host "✅ Created security group: $role" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to create group $role`: $($_.Exception.Message)"
    }
}
```

**Permission Validation Function:**
```powershell
function Test-DailyAdminToolkitPermissions {
    param(
        [Parameter(Mandatory)]
        [string]$Operation,
        
        [string]$UserName = $env:USERNAME,
        
        [switch]$RequireJustification
    )
    
    $permissionResult = @{
        UserName = $UserName
        Operation = $Operation
        Authorized = $false
        Role = "None"
        Restrictions = @()
        Justification = ""
    }
    
    try {
        # Get user's group memberships
        $userGroups = Get-ADUser -Identity $UserName -Properties MemberOf | 
            Select-Object -ExpandProperty MemberOf | 
            ForEach-Object { (Get-ADGroup -Identity $_).Name }
        
        # Check permissions based on role hierarchy
        foreach ($role in $SecurityRoles.Keys) {
            if ($userGroups -contains $role) {
                $roleConfig = $SecurityRoles[$role]
                
                if ($Operation -in $roleConfig.Permissions) {
                    $permissionResult.Authorized = $true
                    $permissionResult.Role = $role
                    $permissionResult.Restrictions = $roleConfig.Restrictions
                    break
                }
            }
        }
        
        # Check time-based restrictions
        if ($permissionResult.Authorized -and "BusinessHoursOnly" -in $permissionResult.Restrictions) {
            $currentHour = (Get-Date).Hour
            if ($currentHour -lt 8 -or $currentHour -gt 17) {
                if ($permissionResult.Role -ne "DailyAdminToolkit_EmergencyAdmin") {
                    $permissionResult.Authorized = $false
                    $permissionResult.Restrictions += "OutsideBusinessHours"
                }
            }
        }
        
        # Require justification for certain operations
        if ($RequireJustification -and $permissionResult.Authorized) {
            $permissionResult.Justification = Read-Host "Please provide justification for this operation"
            if ([string]::IsNullOrWhiteSpace($permissionResult.Justification)) {
                $permissionResult.Authorized = $false
                $permissionResult.Restrictions += "NoJustificationProvided"
            }
        }
        
        # Log permission check
        $logMessage = "Permission check: User=$UserName, Operation=$Operation, Authorized=$($permissionResult.Authorized), Role=$($permissionResult.Role)"
        Write-EventLog -LogName Application -Source "DailyAdminToolkit" -EventID 2001 -EntryType Information -Message $logMessage
        
    } catch {
        Write-Error "Permission validation failed: $($_.Exception.Message)"
        $permissionResult.Authorized = $false
    }
    
    return [PSCustomObject]$permissionResult
}

# Usage example
$permissionCheck = Test-DailyAdminToolkitPermissions -Operation "Unlock-ADAccount" -RequireJustification
if ($permissionCheck.Authorized) {
    Write-Host "✅ Operation authorized for user $($permissionCheck.UserName)" -ForegroundColor Green
    Write-Host "   Role: $($permissionCheck.Role)" -ForegroundColor Cyan
    if ($permissionCheck.Restrictions) {
        Write-Host "   Restrictions: $($permissionCheck.Restrictions -join ', ')" -ForegroundColor Yellow
    }
} else {
    Write-Host "❌ Operation not authorized" -ForegroundColor Red
    Write-Host "   Restrictions: $($permissionCheck.Restrictions -join ', ')" -ForegroundColor Red
}
```

## Data Protection

### Encryption in Transit

**PowerShell Remoting with HTTPS:**
```powershell
# Configure HTTPS for PowerShell remoting
function Enable-SecurePSRemoting {
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [string]$CertificateThumbprint,
        
        [int]$Port = 5986
    )
    
    # Create HTTPS listener with certificate
    if ($CertificateThumbprint) {
        $listenerCommand = "winrm create winrm/config/Listener?Address=*+Transport=HTTPS @{Hostname=`"$ComputerName`";CertificateThumbprint=`"$CertificateThumbprint`";Port=`"$Port`"}"
    } else {
        # Self-signed certificate for testing (not recommended for production)
        $cert = New-SelfSignedCertificate -DnsName $ComputerName -CertStoreLocation "cert:\LocalMachine\My"
        $listenerCommand = "winrm create winrm/config/Listener?Address=*+Transport=HTTPS @{Hostname=`"$ComputerName`";CertificateThumbprint=`"$($cert.Thumbprint)`";Port=`"$Port`"}"
    }
    
    # Execute configuration
    try {
        Invoke-Expression $listenerCommand
        
        # Configure firewall
        New-NetFirewallRule -DisplayName "PowerShell Remoting HTTPS" -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow
        
        Write-Host "✅ HTTPS PowerShell remoting configured on port $Port" -ForegroundColor Green
    } catch {
        Write-Error "Failed to configure HTTPS remoting: $($_.Exception.Message)"
    }
}

# Use HTTPS sessions
function New-SecurePSSession {
    param(
        [Parameter(Mandatory)]
        [string[]]$ComputerName,
        
        [PSCredential]$Credential,
        
        [int]$Port = 5986,
        
        [switch]$SkipCACheck,
        
        [switch]$SkipCNCheck
    )
    
    $sessionOptions = New-PSSessionOption -SkipCACheck:$SkipCACheck -SkipCNCheck:$SkipCNCheck -SkipRevocationCheck:$SkipCACheck
    
    $sessions = @()
    foreach ($computer in $ComputerName) {
        try {
            $session = New-PSSession -ComputerName $computer -Port $Port -UseSSL -Credential $Credential -SessionOption $sessionOptions
            $sessions += $session
            Write-Host "✅ Secure session established with $computer" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to establish secure session with $computer`: $($_.Exception.Message)"
        }
    }
    
    return $sessions
}
```

### Secure Logging

**Encrypted Log Files:**
```powershell
function Write-SecureLog {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [ValidateSet("Information", "Warning", "Error", "Critical")]
        [string]$Level = "Information",
        
        [string]$LogPath = "$env:USERPROFILE\.dailyadmintoolkit\logs",
        
        [switch]$Encrypt
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$Level] $Message"
    
    # Add context information
    $context = @{
        User = $env:USERNAME
        Computer = $env:COMPUTERNAME
        ProcessId = $PID
        SessionId = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
    }
    
    $contextString = ($context.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ", "
    $fullLogEntry = "$logEntry | Context: $contextString"
    
    try {
        # Ensure log directory exists
        if (-not (Test-Path $LogPath)) {
            New-Item -Path $LogPath -ItemType Directory -Force
        }
        
        $logFile = Join-Path $LogPath "DailyAdminToolkit_$(Get-Date -Format 'yyyyMMdd').log"
        
        if ($Encrypt) {
            # Encrypt log entry
            $encryptedEntry = Protect-CmsMessage -Content $fullLogEntry -To "CN=DailyAdminToolkit"
            Add-Content -Path "$logFile.encrypted" -Value $encryptedEntry
        } else {
            Add-Content -Path $logFile -Value $fullLogEntry
        }
        
        # Also log to Windows Event Log for important events
        if ($Level -in @("Error", "Critical")) {
            $eventId = switch ($Level) {
                "Error" { 3001 }
                "Critical" { 3002 }
            }
            Write-EventLog -LogName Application -Source "DailyAdminToolkit" -EventID $eventId -EntryType Error -Message $Message
        }
        
    } catch {
        # Fallback to Windows Event Log if file logging fails
        Write-EventLog -LogName Application -Source "DailyAdminToolkit" -EventID 3000 -EntryType Warning -Message "Failed to write to log file: $($_.Exception.Message). Original message: $Message"
    }
}

# Create certificate for log encryption (one-time setup)
function Initialize-LogEncryption {
    try {
        $cert = New-SelfSignedCertificate -Subject "CN=DailyAdminToolkit" -KeyUsage KeyEncipherment -Type DocumentEncryptionCert -CertStoreLocation "Cert:\CurrentUser\My"
        Write-Host "✅ Log encryption certificate created: $($cert.Thumbprint)" -ForegroundColor Green
        return $cert
    } catch {
        Write-Error "Failed to create encryption certificate: $($_.Exception.Message)"
    }
}

# Initialize logging with encryption
$encryptionCert = Initialize-LogEncryption
```

## Network Security

### Firewall Configuration

**Secure Firewall Rules:**
```powershell
function Set-DailyAdminToolkitFirewallRules {
    param(
        [string[]]$AllowedSourceNetworks = @("192.168.1.0/24", "10.0.0.0/8"),
        [string[]]$AdminWorkstations = @("ADMIN01", "ADMIN02"),
        [switch]$RestrictToAdminWorkstations
    )
    
    # Remove existing rules
    Get-NetFirewallRule -DisplayName "*DailyAdminToolkit*" | Remove-NetFirewallRule -Confirm:$false
    
    if ($RestrictToAdminWorkstations) {
        # Create rules restricted to specific admin workstations
        foreach ($workstation in $AdminWorkstations) {
            New-NetFirewallRule -DisplayName "DailyAdminToolkit - PowerShell Remoting HTTP ($workstation)" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow -RemoteAddress $workstation
            New-NetFirewallRule -DisplayName "DailyAdminToolkit - PowerShell Remoting HTTPS ($workstation)" -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow -RemoteAddress $workstation
        }
    } else {
        # Create rules for allowed network ranges
        foreach ($network in $AllowedSourceNetworks) {
            New-NetFirewallRule -DisplayName "DailyAdminToolkit - PowerShell Remoting HTTP ($network)" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow -RemoteAddress $network
            New-NetFirewallRule -DisplayName "DailyAdminToolkit - PowerShell Remoting HTTPS ($network)" -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow -RemoteAddress $network
        }
    }
    
    # Block all other PowerShell remoting traffic
    New-NetFirewallRule -DisplayName "DailyAdminToolkit - Block Unauthorized PS Remoting" -Direction Inbound -Protocol TCP -LocalPort 5985,5986 -Action Block -Priority 1000
    
    Write-Host "✅ Firewall rules configured for Daily Admin Toolkit" -ForegroundColor Green
}

# Apply restrictive firewall rules
Set-DailyAdminToolkitFirewallRules -RestrictToAdminWorkstations -AdminWorkstations @("ADMIN01.contoso.com", "ADMIN02.contoso.com")
```

### Network Segmentation

**Dedicated Administrative Network:**
```powershell
# Check if running from authorized administrative network
function Test-AuthorizedNetwork {
    param(
        [string[]]$AuthorizedNetworks = @("10.0.100.0/24", "192.168.100.0/24")  # Admin networks
    )
    
    $currentIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.PrefixOrigin -eq "Dhcp" -or $_.PrefixOrigin -eq "Manual" }).IPAddress
    
    foreach ($ip in $currentIP) {
        foreach ($network in $AuthorizedNetworks) {
            if (Test-NetConnection -ComputerName $ip -InformationLevel Quiet) {
                # Simple network check - in production, use proper CIDR validation
                $networkBase = $network.Split('/')[0]
                $networkPrefix = $network.Split('/')[1]
                
                if ($ip.StartsWith($networkBase.Substring(0, $networkBase.LastIndexOf('.')))) {
                    Write-Host "✅ Operating from authorized network: $network" -ForegroundColor Green
                    return $true
                }
            }
        }
    }
    
    Write-Warning "❌ Not operating from authorized administrative network"
    Write-Host "Current IP addresses: $($currentIP -join ', ')" -ForegroundColor Yellow
    Write-Host "Authorized networks: $($AuthorizedNetworks -join ', ')" -ForegroundColor Yellow
    
    return $false
}

# Enforce network restrictions
if (-not (Test-AuthorizedNetwork)) {
    Write-Error "Daily Admin Toolkit operations are restricted to authorized administrative networks only."
    exit 1
}
```

## Monitoring and Auditing

### Security Event Monitoring

**Security Event Detection:**
```powershell
function Start-SecurityMonitoring {
    param(
        [int]$MonitoringIntervalSeconds = 300,  # 5 minutes
        [string[]]$CriticalEvents = @("FailedLogon", "PrivilegeEscalation", "UnauthorizedAccess"),
        [string]$AlertEmail = "security@contoso.com"
    )
    
    Write-Host "🔒 Starting Daily Admin Toolkit Security Monitoring" -ForegroundColor Cyan
    
    while ($true) {
        try {
            # Monitor failed authentication attempts
            $failedLogons = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddSeconds(-$MonitoringIntervalSeconds)} -ErrorAction SilentlyContinue
            
            if ($failedLogons) {
                foreach ($event in $failedLogons) {
                    $message = "Failed logon detected: $($event.TimeCreated) - $($event.Message)"
                    Write-SecureLog -Message $message -Level "Warning"
                    
                    # Alert on multiple failures
                    if ($failedLogons.Count -gt 5) {
                        Send-SecurityAlert -Type "MultipleFailedLogons" -Count $failedLogons.Count -Email $AlertEmail
                    }
                }
            }
            
            # Monitor privilege escalation
            $privilegeEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4672; StartTime=(Get-Date).AddSeconds(-$MonitoringIntervalSeconds)} -ErrorAction SilentlyContinue
            
            if ($privilegeEvents) {
                foreach ($event in $privilegeEvents) {
                    $message = "Privilege escalation detected: $($event.TimeCreated) - $($event.Message)"
                    Write-SecureLog -Message $message -Level "Information"
                }
            }
            
            # Monitor PowerShell remoting sessions
            $psRemoteEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4103,4104; StartTime=(Get-Date).AddSeconds(-$MonitoringIntervalSeconds)} -ErrorAction SilentlyContinue
            
            if ($psRemoteEvents) {
                foreach ($event in $psRemoteEvents) {
                    # Look for Daily Admin Toolkit specific activities
                    if ($event.Message -like "*DailyAdminToolkit*" -or $event.Message -like "*Unlock-ADAccount*" -or $event.Message -like "*Reset-ADUserPassword*") {
                        $message = "Daily Admin Toolkit activity detected: $($event.TimeCreated) - $($event.Message)"
                        Write-SecureLog -Message $message -Level "Information"
                    }
                }
            }
            
        } catch {
            Write-SecureLog -Message "Security monitoring error: $($_.Exception.Message)" -Level "Error"
        }
        
        Start-Sleep -Seconds $MonitoringIntervalSeconds
    }
}

function Send-SecurityAlert {
    param(
        [Parameter(Mandatory)]
        [string]$Type,
        
        [int]$Count = 1,
        
        [string]$Email,
        
        [hashtable]$AdditionalData = @{}
    )
    
    $alertData = @{
        Type = $Type
        Timestamp = Get-Date
        Computer = $env:COMPUTERNAME
        User = $env:USERNAME
        Count = $Count
        AdditionalData = $AdditionalData
    }
    
    $alertMessage = "SECURITY ALERT: $Type detected on $($alertData.Computer) at $($alertData.Timestamp)"
    
    # Log alert
    Write-SecureLog -Message $alertMessage -Level "Critical"
    Write-EventLog -LogName Application -Source "DailyAdminToolkit" -EventID 9001 -EntryType Error -Message $alertMessage
    
    # Send email alert (implement based on your email system)
    if ($Email) {
        try {
            # Example using Send-MailMessage (configure SMTP settings)
            # Send-MailMessage -To $Email -From "noreply@contoso.com" -Subject "Daily Admin Toolkit Security Alert" -Body $alertMessage -SmtpServer "smtp.contoso.com"
            Write-Host "📧 Security alert would be sent to: $Email" -ForegroundColor Yellow
        } catch {
            Write-SecureLog -Message "Failed to send security alert email: $($_.Exception.Message)" -Level "Error"
        }
    }
}

# Start monitoring in background job
# Start-Job -ScriptBlock { Start-SecurityMonitoring -AlertEmail "security@contoso.com" }
```

### Compliance Reporting

**Generate Security Compliance Reports:**
```powershell
function New-SecurityComplianceReport {
    param(
        [datetime]$StartDate = (Get-Date).AddDays(-30),
        [datetime]$EndDate = (Get-Date),
        [string]$ReportPath = "$env:USERPROFILE\.dailyadmintoolkit\reports"
    )
    
    $reportData = @{
        ReportDate = Get-Date
        Period = @{
            Start = $StartDate
            End = $EndDate
            Days = ($EndDate - $StartDate).Days
        }
        Compliance = @{}
        Activities = @{}
        Recommendations = @()
    }
    
    # Ensure report directory exists
    if (-not (Test-Path $ReportPath)) {
        New-Item -Path $ReportPath -ItemType Directory -Force
    }
    
    try {
        # Analyze authentication events
        $authEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625; StartTime=$StartDate; EndTime=$EndDate} -ErrorAction SilentlyContinue
        
        $reportData.Activities.Authentication = @{
            SuccessfulLogons = ($authEvents | Where-Object { $_.Id -eq 4624 }).Count
            FailedLogons = ($authEvents | Where-Object { $_.Id -eq 4625 }).Count
            UniqueUsers = ($authEvents | ForEach-Object { 
                ([xml]$_.ToXml()).Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' } | Select-Object -ExpandProperty '#text' 
            } | Sort-Object -Unique).Count
        }
        
        # Analyze Daily Admin Toolkit usage
        $logFiles = Get-ChildItem -Path "$env:USERPROFILE\.dailyadmintoolkit\logs" -Filter "*.log" -ErrorAction SilentlyContinue
        $toolkitActivities = @()
        
        foreach ($logFile in $logFiles) {
            $logContent = Get-Content $logFile.FullName | Where-Object { $_ -match "Unlock-ADAccount|Reset-ADUserPassword|Restart-RemoteService" }
            $toolkitActivities += $logContent
        }
        
        $reportData.Activities.DailyAdminToolkit = @{
            TotalOperations = $toolkitActivities.Count
            UnlockOperations = ($toolkitActivities | Where-Object { $_ -like "*Unlock-ADAccount*" }).Count
            PasswordResets = ($toolkitActivities | Where-Object { $_ -like "*Reset-ADUserPassword*" }).Count
            ServiceRestarts = ($toolkitActivities | Where-Object { $_ -like "*Restart-RemoteService*" }).Count
        }
        
        # Compliance checks
        $reportData.Compliance.PasswordPolicy = Test-PasswordPolicy
        $reportData.Compliance.AccountLockout = Test-AccountLockoutPolicy
        $reportData.Compliance.AuditPolicy = Test-AuditPolicy
        $reportData.Compliance.FirewallStatus = Test-FirewallCompliance
        
        # Generate recommendations
        if ($reportData.Activities.Authentication.FailedLogons -gt 100) {
            $reportData.Recommendations += "High number of failed logons detected. Review authentication security."
        }
        
        if ($reportData.Activities.DailyAdminToolkit.UnlockOperations -gt 50) {
            $reportData.Recommendations += "High number of account unlocks. Consider user security training."
        }
        
        if (-not $reportData.Compliance.AuditPolicy.Compliant) {
            $reportData.Recommendations += "Audit policy not fully compliant. Review audit settings."
        }
        
        # Generate report file
        $reportFile = Join-Path $ReportPath "SecurityCompliance_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $reportData | ConvertTo-Json -Depth 3 | Out-File -FilePath $reportFile -Encoding UTF8
        
        # Generate HTML summary
        $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Daily Admin Toolkit Security Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 10px; border-radius: 5px; }
        .section { margin: 20px 0; }
        .compliant { color: green; font-weight: bold; }
        .non-compliant { color: red; font-weight: bold; }
        .warning { color: orange; font-weight: bold; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Daily Admin Toolkit Security Compliance Report</h1>
        <p>Generated: $($reportData.ReportDate)</p>
        <p>Period: $($reportData.Period.Start.ToString('yyyy-MM-dd')) to $($reportData.Period.End.ToString('yyyy-MM-dd')) ($($reportData.Period.Days) days)</p>
    </div>
    
    <div class="section">
        <h2>Authentication Activity</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Successful Logons</td><td>$($reportData.Activities.Authentication.SuccessfulLogons)</td></tr>
            <tr><td>Failed Logons</td><td>$($reportData.Activities.Authentication.FailedLogons)</td></tr>
            <tr><td>Unique Users</td><td>$($reportData.Activities.Authentication.UniqueUsers)</td></tr>
        </table>
    </div>
    
    <div class="section">
        <h2>Daily Admin Toolkit Usage</h2>
        <table>
            <tr><th>Operation</th><th>Count</th></tr>
            <tr><td>Total Operations</td><td>$($reportData.Activities.DailyAdminToolkit.TotalOperations)</td></tr>
            <tr><td>Account Unlocks</td><td>$($reportData.Activities.DailyAdminToolkit.UnlockOperations)</td></tr>
            <tr><td>Password Resets</td><td>$($reportData.Activities.DailyAdminToolkit.PasswordResets)</td></tr>
            <tr><td>Service Restarts</td><td>$($reportData.Activities.DailyAdminToolkit.ServiceRestarts)</td></tr>
        </table>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <ul>
"@
        
        foreach ($recommendation in $reportData.Recommendations) {
            $htmlReport += "<li>$recommendation</li>"
        }
        
        $htmlReport += @"
        </ul>
    </div>
</body>
</html>
"@
        
        $htmlReportFile = Join-Path $ReportPath "SecurityCompliance_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        $htmlReport | Out-File -FilePath $htmlReportFile -Encoding UTF8
        
        Write-Host "✅ Security compliance report generated:" -ForegroundColor Green
        Write-Host "   JSON: $reportFile" -ForegroundColor Cyan
        Write-Host "   HTML: $htmlReportFile" -ForegroundColor Cyan
        
        return $reportData
        
    } catch {
        Write-Error "Failed to generate compliance report: $($_.Exception.Message)"
        return $null
    }
}

# Helper functions for compliance checks
function Test-PasswordPolicy {
    try {
        $policy = Get-ADDefaultDomainPasswordPolicy
        return @{
            Compliant = ($policy.MinPasswordLength -ge 8 -and $policy.MaxPasswordAge.Days -le 90)
            MinLength = $policy.MinPasswordLength
            MaxAge = $policy.MaxPasswordAge.Days
            ComplexityEnabled = $policy.ComplexityEnabled
        }
    } catch {
        return @{ Compliant = $false; Error = $_.Exception.Message }
    }
}

function Test-AccountLockoutPolicy {
    try {
        $policy = Get-ADDefaultDomainPasswordPolicy
        return @{
            Compliant = ($policy.LockoutThreshold -gt 0 -and $policy.LockoutThreshold -le 5)
            LockoutThreshold = $policy.LockoutThreshold
            LockoutDuration = $policy.LockoutDuration.Minutes
        }
    } catch {
        return @{ Compliant = $false; Error = $_.Exception.Message }
    }
}

function Test-AuditPolicy {
    try {
        $auditSettings = auditpol /get /category:* /r | ConvertFrom-Csv
        $requiredAudits = @("Logon/Logoff", "Account Management", "Privilege Use")
        
        $compliant = $true
        foreach ($audit in $requiredAudits) {
            if (-not ($auditSettings | Where-Object { $_."Subcategory" -like "*$audit*" -and $_."Inclusion Setting" -eq "Success and Failure" })) {
                $compliant = $false
                break
            }
        }
        
        return @{
            Compliant = $compliant
            AuditSettings = $auditSettings
        }
    } catch {
        return @{ Compliant = $false; Error = $_.Exception.Message }
    }
}

function Test-FirewallCompliance {
    try {
        $firewallProfiles = Get-NetFirewallProfile
        $allEnabled = $firewallProfiles | Where-Object { $_.Enabled -eq $false }
        
        return @{
            Compliant = ($allEnabled.Count -eq 0)
            DisabledProfiles = $allEnabled.Name -join ", "
        }
    } catch {
        return @{ Compliant = $false; Error = $_.Exception.Message }
    }
}

# Generate monthly compliance report
$complianceReport = New-SecurityComplianceReport -StartDate (Get-Date).AddDays(-30)
```

## Security Hardening Checklist

### Final Security Checklist

```powershell
Write-Host "🔒 Daily Admin Toolkit Security Hardening Checklist" -ForegroundColor Cyan

$securityChecklist = @(
    @{ Item = "Dedicated service accounts configured"; Status = "☐" }
    @{ Item = "Group Managed Service Accounts (gMSA) implemented"; Status = "☐" }
    @{ Item = "Role-based access control (RBAC) defined"; Status = "☐" }
    @{ Item = "Secure credential storage configured"; Status = "☐" }
    @{ Item = "HTTPS PowerShell remoting enabled"; Status = "☐" }
    @{ Item = "Network segmentation implemented"; Status = "☐" }
    @{ Item = "Firewall rules restricted to admin networks"; Status = "☐" }
    @{ Item = "Audit logging enabled and configured"; Status = "☐" }
    @{ Item = "Security monitoring implemented"; Status = "☐" }
    @{ Item = "Compliance reporting automated"; Status = "☐" }
    @{ Item = "Encryption configured for sensitive data"; Status = "☐" }
    @{ Item = "Regular security assessments scheduled"; Status = "☐" }
    @{ Item = "Incident response procedures documented"; Status = "☐" }
    @{ Item = "User security training completed"; Status = "☐" }
    @{ Item = "Regular permission audits scheduled"; Status = "☐" }
)

foreach ($item in $securityChecklist) {
    Write-Host "$($item.Status) $($item.Item)" -ForegroundColor Yellow
}

Write-Host "`n🛡️ Security hardening provides defense against:" -ForegroundColor Green
Write-Host "   • Unauthorized access attempts" -ForegroundColor White
Write-Host "   • Privilege escalation attacks" -ForegroundColor White
Write-Host "   • Credential theft and misuse" -ForegroundColor White
Write-Host "   • Network-based attacks" -ForegroundColor White
Write-Host "   • Data exfiltration" -ForegroundColor White
Write-Host "   • Compliance violations" -ForegroundColor White

Write-Host "`n✅ Complete this checklist to ensure maximum security for your Daily Admin Toolkit deployment." -ForegroundColor Cyan
```

---

> **Security is a Journey**: Regularly review and update your security configuration as threats evolve and your environment changes. Consider engaging security professionals for periodic assessments of your Daily Admin Toolkit deployment.