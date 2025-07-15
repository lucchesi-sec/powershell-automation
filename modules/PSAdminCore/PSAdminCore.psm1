<#
.SYNOPSIS
    PSAdminCore - Shared functions for PowerShell administration automation
.DESCRIPTION
    This module provides common functions used across all PowerShell administration scripts.
    It includes logging, credential management, privilege checking, and reporting utilities.
.NOTES
    Author: System Administrator
    Version: 1.0.0
    Requires: PowerShell 5.1 or higher
#>

# Function to write standardized administrative logs
function Write-AdminLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info",
        
        [Parameter(Mandatory = $false)]
        [string]$LogPath = "$env:TEMP\PSAdmin.log"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to log file
    Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
    
    # Write to console with color coding
    switch ($Level) {
        "Info"    { Write-Host $logEntry -ForegroundColor Cyan }
        "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
        "Error"   { Write-Host $logEntry -ForegroundColor Red }
        "Success" { Write-Host $logEntry -ForegroundColor Green }
    }
}

# Function to test administrative privileges
function Test-AdminPrivileges {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        Write-AdminLog -Message "Failed to check admin privileges: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

# Function to get secure credentials
function Get-AdminCredential {
    [CmdletBinding()]
    [OutputType([PSCredential])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Purpose,
        
        [Parameter(Mandatory = $false)]
        [string]$Username
    )
    
    try {
        if ($Username) {
            $credential = Get-Credential -UserName $Username -Message "Enter credentials for: $Purpose"
        } else {
            $credential = Get-Credential -Message "Enter credentials for: $Purpose"
        }
        
        if ($credential) {
            Write-AdminLog -Message "Credentials obtained for: $Purpose" -Level "Success"
            return $credential
        } else {
            Write-AdminLog -Message "No credentials provided for: $Purpose" -Level "Warning"
            return $null
        }
    }
    catch {
        Write-AdminLog -Message "Failed to get credentials for $Purpose`: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

# Function to send administrative notifications
function Send-AdminNotification {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Subject,
        
        [Parameter(Mandatory = $true)]
        [string]$Body,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Recipients = @("admin@company.com"),
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Low", "Normal", "High")]
        [string]$Priority = "Normal"
    )
    
    try {
        # Check if email configuration exists
        $configPath = "$PSScriptRoot\..\..\config\email.json"
        if (Test-Path $configPath) {
            $emailConfig = Get-Content $configPath | ConvertFrom-Json
            
            $mailParams = @{
                To = $Recipients
                From = $emailConfig.From
                Subject = "[$($env:COMPUTERNAME)] $Subject"
                Body = $Body
                SmtpServer = $emailConfig.SmtpServer
                Port = $emailConfig.Port
                UseSsl = $emailConfig.UseSsl
            }
            
            if ($emailConfig.Credential) {
                $mailParams.Credential = Get-AdminCredential -Purpose "Email Authentication"
            }
            
            Send-MailMessage @mailParams
            Write-AdminLog -Message "Notification sent: $Subject" -Level "Success"
        } else {
            Write-AdminLog -Message "Email configuration not found. Notification logged only: $Subject" -Level "Warning"
        }
    }
    catch {
        Write-AdminLog -Message "Failed to send notification: $($_.Exception.Message)" -Level "Error"
    }
}

# Function to create standardized reports
function New-AdminReport {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReportTitle,
        
        [Parameter(Mandatory = $true)]
        [object]$Data,
        
        [Parameter(Mandatory = $false)]
        [string]$Description = "",
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Metadata = @{}
    )
    
    $report = [PSCustomObject]@{
        ReportTitle = $ReportTitle
        GeneratedBy = $env:USERNAME
        ComputerName = $env:COMPUTERNAME
        GeneratedDate = Get-Date
        Description = $Description
        Data = $Data
        Metadata = $Metadata
        Summary = @{
            TotalItems = if ($Data -is [array]) { $Data.Count } else { 1 }
            DataType = $Data.GetType().Name
        }
    }
    
    Write-AdminLog -Message "Report generated: $ReportTitle" -Level "Success"
    return $report
}

# Function to test network connectivity
function Test-AdminConnectivity {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ComputerName,
        
        [Parameter(Mandatory = $false)]
        [int]$Port = 443,
        
        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 5
    )
    
    $results = @()
    
    foreach ($computer in $ComputerName) {
        try {
            $result = Test-NetConnection -ComputerName $computer -Port $Port -WarningAction SilentlyContinue
            
            $results += [PSCustomObject]@{
                ComputerName = $computer
                Port = $Port
                Connected = $result.TcpTestSucceeded
                ResponseTime = if ($result.PingSucceeded) { $result.PingReplyDetails.RoundtripTime } else { $null }
                TestDate = Get-Date
            }
        }
        catch {
            $results += [PSCustomObject]@{
                ComputerName = $computer
                Port = $Port
                Connected = $false
                ResponseTime = $null
                Error = $_.Exception.Message
                TestDate = Get-Date
            }
        }
    }
    
    return $results
}

# Function to validate input parameters
function Test-AdminParameter {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Value,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("Email", "IPAddress", "Path", "ComputerName", "NotEmpty")]
        [string]$Type
    )
    
    switch ($Type) {
        "Email" {
            return $Value -match "^[^@\s]+@[^@\s]+\.[^@\s]+$"
        }
        "IPAddress" {
            return [System.Net.IPAddress]::TryParse($Value, [ref]$null)
        }
        "Path" {
            return Test-Path $Value -IsValid
        }
        "ComputerName" {
            return $Value -match "^[a-zA-Z0-9\-\.]+$"
        }
        "NotEmpty" {
            return -not [string]::IsNullOrWhiteSpace($Value)
        }
        default {
            return $false
        }
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Write-AdminLog',
    'Test-AdminPrivileges', 
    'Get-AdminCredential',
    'Send-AdminNotification',
    'New-AdminReport',
    'Test-AdminConnectivity',
    'Test-AdminParameter'
)