<#
.SYNOPSIS
    Monitors critical Windows services and automatically restarts them if they stop.

.DESCRIPTION
    This script continuously monitors a configurable list of critical services
    and automatically restarts them if they are found to be stopped. It includes:
    - Service status monitoring
    - Automatic restart with retry logic
    - Dependency chain management
    - Email notifications (optional)
    - Comprehensive logging
    - Health check reporting

.PARAMETER ConfigPath
    Path to JSON configuration file containing service definitions

.PARAMETER CheckInterval
    Interval in seconds between service checks (default: 300 seconds)

.PARAMETER MaxRetries
    Maximum number of restart attempts per service (default: 3)

.PARAMETER EmailNotifications
    Enable email notifications for service failures

.PARAMETER ReportOnly
    Run in report-only mode without performing any restart actions

.EXAMPLE
    .\Monitor-CriticalServices.ps1
    Runs with default settings and built-in service list

.EXAMPLE
    .\Monitor-CriticalServices.ps1 -ConfigPath ".\service-config.json" -CheckInterval 180
    Uses custom configuration and checks every 3 minutes

.NOTES
    Author: PowerShell Automation Project
    Requires: Administrator privileges to restart services
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath,
    
    [Parameter(Mandatory = $false)]
    [ValidateRange(30, 3600)]
    [int]$CheckInterval = 300,
    
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 10)]
    [int]$MaxRetries = 3,
    
    [Parameter(Mandatory = $false)]
    [switch]$EmailNotifications,
    
    [Parameter(Mandatory = $false)]
    [switch]$ReportOnly
)

# Import required modules

if (Test-Path $modulePath) {
    Import-Module $modulePath -Force
} else {
    # Fall back to installed module
    Import-Module PSAdminCore -Force -ErrorAction Stop
}

# Initialize variables
$ErrorActionPreference = "Continue"
$LogFile = "$env:TEMP\ServiceMonitor_$(Get-Date -Format 'yyyyMMdd').log"
$ServiceStatus = @{}
$RestartAttempts = @{}

# Default critical services configuration
$DefaultServices = @{
    "Critical" = @(
        @{ Name = "Spooler"; DisplayName = "Print Spooler"; Dependencies = @() }
        @{ Name = "Themes"; DisplayName = "Themes"; Dependencies = @() }
        @{ Name = "AudioSrv"; DisplayName = "Windows Audio"; Dependencies = @("AudioEndpointBuilder") }
        @{ Name = "BITS"; DisplayName = "Background Intelligent Transfer Service"; Dependencies = @() }
        @{ Name = "EventLog"; DisplayName = "Windows Event Log"; Dependencies = @() }
    )
    "Infrastructure" = @(
        @{ Name = "Dhcp"; DisplayName = "DHCP Client"; Dependencies = @() }
        @{ Name = "Dnscache"; DisplayName = "DNS Client"; Dependencies = @() }
        @{ Name = "LanmanWorkstation"; DisplayName = "Workstation"; Dependencies = @("NSI") }
        @{ Name = "LanmanServer"; DisplayName = "Server"; Dependencies = @() }
        @{ Name = "RpcSs"; DisplayName = "Remote Procedure Call (RPC)"; Dependencies = @() }
    )
    "Application" = @(
        @{ Name = "W3SVC"; DisplayName = "World Wide Web Publishing Service"; Dependencies = @("HTTP") }
        @{ Name = "MSSQLSERVER"; DisplayName = "SQL Server"; Dependencies = @() }
        @{ Name = "SQLSERVERAGENT"; DisplayName = "SQL Server Agent"; Dependencies = @("MSSQLSERVER") }
    )
}

function Write-ServiceLog {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$Service = ""
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $serviceInfo = if ($Service) { " [$Service]" } else { "" }
    $logMessage = "[$timestamp] [$Level]$serviceInfo $Message"
    
    Write-Host $logMessage
    Add-Content -Path $LogFile -Value $logMessage
}

function Load-ServiceConfiguration {
    if ($ConfigPath -and (Test-Path $ConfigPath)) {
        try {
            Write-ServiceLog "Loading configuration from: $ConfigPath"
            $config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
            return $config
        }
        catch {
            Write-ServiceLog "Error loading configuration file: $($_.Exception.Message)" -Level "ERROR"
            Write-ServiceLog "Using default configuration"
            return $DefaultServices
        }
    }
    else {
        Write-ServiceLog "Using default service configuration"
        return $DefaultServices
    }
}

function Test-ServiceDependencies {
    param([array]$Dependencies)

    foreach ($dependency in $Dependencies) {
        $depService = Get-Service -Name $dependency -ErrorAction SilentlyContinue
        if (-not $depService) {
            Write-ServiceLog "Dependency service '$dependency' not found" -Level "WARNING"
            return $false
        }
        
        if ($depService.Status -ne "Running") {
            Write-ServiceLog "Dependency service '$dependency' is not running" -Level "WARNING"
            
            if (-not $ReportOnly) {
                try {
                    Write-ServiceLog "Starting dependency service: $dependency"
                    Start-Service -Name $dependency -ErrorAction Stop
                    Start-Sleep -Seconds 5
                    
                    $depService = Get-Service -Name $dependency
                    if ($depService.Status -eq "Running") {
                        Write-ServiceLog "Successfully started dependency: $dependency"
                    }
                    else {
                        Write-ServiceLog "Failed to start dependency: $dependency" -Level "ERROR"
                        return $false
                    }
                }
                catch {
                    Write-ServiceLog "Error starting dependency '$dependency': $($_.Exception.Message)" -Level "ERROR"
                    return $false
                }
            }
        }
    }
    
    return $true
}

function Restart-ServiceWithRetry {
    param(
        [string]$ServiceName,
        [string]$DisplayName,
        [array]$Dependencies
    )

    if (-not $RestartAttempts.ContainsKey($ServiceName)) {
        $RestartAttempts[$ServiceName] = 0
    }
    
    if ($RestartAttempts[$ServiceName] -ge $MaxRetries) {
        Write-ServiceLog "Maximum restart attempts ($MaxRetries) reached for service: $DisplayName" -Level "ERROR" -Service $ServiceName
        Send-ServiceAlert -ServiceName $ServiceName -DisplayName $DisplayName -Status "FAILED" -Message "Maximum restart attempts exceeded"
        return $false
    }
    
    $RestartAttempts[$ServiceName]++
    Write-ServiceLog "Restart attempt $($RestartAttempts[$ServiceName]) of $MaxRetries for service: $DisplayName" -Service $ServiceName
    
    # Check and start dependencies first
    if ($Dependencies.Count -gt 0) {
        Write-ServiceLog "Checking dependencies for service: $DisplayName" -Service $ServiceName
        if (-not (Test-ServiceDependencies -Dependencies $Dependencies)) {
            Write-ServiceLog "Dependency check failed for service: $DisplayName" -Level "ERROR" -Service $ServiceName
            return $false
        }
    }
    
    if ($ReportOnly) {
        Write-ServiceLog "REPORT ONLY: Would restart service: $DisplayName" -Service $ServiceName
        return $true
    }
    
    try {
        # Stop service if it's in a bad state
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq "StopPending") {
            Write-ServiceLog "Service is stopping, waiting..." -Service $ServiceName
            $service.WaitForStatus("Stopped", (New-TimeSpan -Seconds 30))
        }
        
        # Start the service
        Write-ServiceLog "Starting service: $DisplayName" -Service $ServiceName
        Start-Service -Name $ServiceName -ErrorAction Stop
        
        # Wait and verify
        Start-Sleep -Seconds 10
        $service = Get-Service -Name $ServiceName
        
        if ($service.Status -eq "Running") {
            Write-ServiceLog "Successfully restarted service: $DisplayName" -Service $ServiceName
            $RestartAttempts[$ServiceName] = 0  # Reset counter on success
            Send-ServiceAlert -ServiceName $ServiceName -DisplayName $DisplayName -Status "RECOVERED" -Message "Service successfully restarted"
            return $true
        }
        else {
            Write-ServiceLog "Service restart failed - Status: $($service.Status)" -Level "ERROR" -Service $ServiceName
            return $false
        }
    }
    catch {
        Write-ServiceLog "Error restarting service: $($_.Exception.Message)" -Level "ERROR" -Service $ServiceName
        return $false
    }
}

function Send-ServiceAlert {
    param(
        [string]$ServiceName,
        [string]$DisplayName,
        [string]$Status,
        [string]$Message
    )

    if (-not $EmailNotifications) {
        return
    }
    
    # Check if email configuration exists
    $emailConfigPath = ".\config\email.json"
    if (-not (Test-Path $emailConfigPath)) {
        Write-ServiceLog "Email configuration not found, skipping notification" -Level "WARNING"
        return
    }
    
    try {
        $emailConfig = Get-Content -Path $emailConfigPath -Raw | ConvertFrom-Json
        
        $subject = "Service Monitor Alert - $Status - $DisplayName"
        $body = @"
Service Monitor Alert

Service: $DisplayName ($ServiceName)
Status: $Status
Message: $Message
Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer: $env:COMPUTERNAME

This is an automated notification from the Service Monitor script.
"@
        
        $emailParams = @{
            To = $emailConfig.To
            From = $emailConfig.From
            Subject = $subject
            Body = $body
            SmtpServer = $emailConfig.SmtpServer
        }
        
        if ($emailConfig.Credential) {
            $emailParams.Credential = $emailConfig.Credential
        }
        
        Send-MailMessage @emailParams
        Write-ServiceLog "Email notification sent for service: $DisplayName" -Service $ServiceName
    }
    catch {
        Write-ServiceLog "Error sending email notification: $($_.Exception.Message)" -Level "ERROR" -Service $ServiceName
    }
}

function Monitor-Services {
    param([hashtable]$ServiceConfig)

    $allServices = @()
    foreach ($category in $ServiceConfig.Keys) {
        $allServices += $ServiceConfig[$category]
    }
    
    Write-ServiceLog "Monitoring $($allServices.Count) services..."
    
    foreach ($serviceInfo in $allServices) {
        $serviceName = $serviceInfo.Name
        $displayName = $serviceInfo.DisplayName
        $dependencies = $serviceInfo.Dependencies
        
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            
            if (-not $service) {
                Write-ServiceLog "Service not found: $displayName ($serviceName)" -Level "WARNING" -Service $serviceName
                continue
            }
            
            $currentStatus = $service.Status
            
            # Track status changes
            if ($ServiceStatus.ContainsKey($serviceName)) {
                $previousStatus = $ServiceStatus[$serviceName]
                if ($currentStatus -ne $previousStatus) {
                    Write-ServiceLog "Status changed from '$previousStatus' to '$currentStatus'" -Service $serviceName
                }
            }
            
            $ServiceStatus[$serviceName] = $currentStatus
            
            # Handle stopped services
            if ($currentStatus -eq "Stopped") {
                Write-ServiceLog "Service is stopped: $displayName" -Level "WARNING" -Service $serviceName
                Send-ServiceAlert -ServiceName $serviceName -DisplayName $displayName -Status "STOPPED" -Message "Service has stopped unexpectedly"
                
                if (Restart-ServiceWithRetry -ServiceName $serviceName -DisplayName $displayName -Dependencies $dependencies) {
                    Write-ServiceLog "Service restart successful: $displayName" -Service $serviceName
                }
                else {
                    Write-ServiceLog "Service restart failed: $displayName" -Level "ERROR" -Service $serviceName
                }
            }
            elseif ($currentStatus -eq "Running") {
                # Reset restart attempts for running services
                if ($RestartAttempts.ContainsKey($serviceName) -and $RestartAttempts[$serviceName] -gt 0) {
                    Write-ServiceLog "Service is healthy, resetting restart counter" -Service $serviceName
                    $RestartAttempts[$serviceName] = 0
                }
            }
            else {
                Write-ServiceLog "Service in transitional state: $currentStatus" -Level "WARNING" -Service $serviceName
            }
        }
        catch {
            Write-ServiceLog "Error monitoring service '$serviceName': $($_.Exception.Message)" -Level "ERROR" -Service $serviceName
        }
    }
}

function Generate-HealthReport {
    param([hashtable]$ServiceConfig)

    $report = @{
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Computer = $env:COMPUTERNAME
        ServicesByCategory = @{}
        Summary = @{
            TotalServices = 0
            RunningServices = 0
            StoppedServices = 0
            ServicesWithIssues = 0
        }
    }
    
    foreach ($category in $ServiceConfig.Keys) {
        $report.ServicesByCategory[$category] = @()
        
        foreach ($serviceInfo in $ServiceConfig[$category]) {
            $serviceName = $serviceInfo.Name
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            
            $serviceReport = @{
                Name = $serviceName
                DisplayName = $serviceInfo.DisplayName
                Status = if ($service) { $service.Status.ToString() } else { "Not Found" }
                StartType = if ($service) { $service.StartType.ToString() } else { "Unknown" }
                RestartAttempts = if ($RestartAttempts.ContainsKey($serviceName)) { $RestartAttempts[$serviceName] } else { 0 }
                Dependencies = $serviceInfo.Dependencies
            }
            
            $report.ServicesByCategory[$category] += $serviceReport
            $report.Summary.TotalServices++
            
            if ($service) {
                if ($service.Status -eq "Running") {
                    $report.Summary.RunningServices++
                }
                elseif ($service.Status -eq "Stopped") {
                    $report.Summary.StoppedServices++
                }
                
                if ($RestartAttempts.ContainsKey($serviceName) -and $RestartAttempts[$serviceName] -gt 0) {
                    $report.Summary.ServicesWithIssues++
                }
            }
        }
    }
    
    return $report
}

# Main execution
Write-ServiceLog "=== Service Monitor Started ==="
Write-ServiceLog "Check Interval: $CheckInterval seconds"
Write-ServiceLog "Max Retries: $MaxRetries"
Write-ServiceLog "Report Only Mode: $ReportOnly"
Write-ServiceLog "Email Notifications: $EmailNotifications"

# Load service configuration
$serviceConfig = Load-ServiceConfiguration

# Create sample configuration file if it doesn't exist
if (-not $ConfigPath) {
    $sampleConfigPath = ".\config\service-monitor-config.json"
    if (-not (Test-Path $sampleConfigPath)) {
        try {
            if (-not (Test-Path ".\config")) {
                New-Item -ItemType Directory -Path ".\config" -Force | Out-Null
            }
            
            $DefaultServices | ConvertTo-Json -Depth 3 | Set-Content -Path $sampleConfigPath
            Write-ServiceLog "Sample configuration created: $sampleConfigPath"
        }
        catch {
            Write-ServiceLog "Could not create sample configuration: $($_.Exception.Message)" -Level "WARNING"
        }
    }
}

try {
    if ($ReportOnly) {
        Write-ServiceLog "Running in report-only mode - no services will be restarted"
        Monitor-Services -ServiceConfig $serviceConfig
        
        $healthReport = Generate-HealthReport -ServiceConfig $serviceConfig
        $reportJson = $healthReport | ConvertTo-Json -Depth 4
        $reportPath = "$env:TEMP\ServiceHealthReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $reportJson | Set-Content -Path $reportPath
        
        Write-ServiceLog "Health report generated: $reportPath"
        Write-Host "`n=== Service Health Summary ===" -ForegroundColor Green
        Write-Host "Total Services: $($healthReport.Summary.TotalServices)"
        Write-Host "Running: $($healthReport.Summary.RunningServices)" -ForegroundColor Green
        Write-Host "Stopped: $($healthReport.Summary.StoppedServices)" -ForegroundColor Red
        Write-Host "With Issues: $($healthReport.Summary.ServicesWithIssues)" -ForegroundColor Yellow
    }
    else {
        Write-ServiceLog "Starting continuous monitoring (Ctrl+C to stop)"
        
        while ($true) {
            Monitor-Services -ServiceConfig $serviceConfig
            
            Write-ServiceLog "Sleeping for $CheckInterval seconds..."
            Start-Sleep -Seconds $CheckInterval
        }
    }
}
catch {
    Write-ServiceLog "Script terminated: $($_.Exception.Message)" -Level "ERROR"
}
finally {
    Write-ServiceLog "=== Service Monitor Stopped ==="
    
    # Generate final health report
    $finalReport = Generate-HealthReport -ServiceConfig $serviceConfig
    Write-Output $finalReport
}

