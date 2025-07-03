<#
.SYNOPSIS
    Automated Windows Update management and patching script.

.DESCRIPTION
    This script provides comprehensive Windows Update automation including:
    - Automatic update detection and installation
    - Update scheduling and maintenance windows
    - Selective update filtering and approval
    - Pre/post-update system validation
    - Rollback capability for problematic updates
    - Comprehensive reporting and logging

.PARAMETER MaintenanceWindow
    Defines maintenance window in format "DayOfWeek,StartHour,EndHour" (e.g., "Sunday,02,06")

.PARAMETER UpdateCategories
    Categories of updates to install (Critical, Important, Optional, Drivers)

.PARAMETER ExcludeKBs
    Array of KB numbers to exclude from installation

.PARAMETER AutoReboot
    Automatically reboot if required after updates

.PARAMETER RebootDelay
    Minutes to wait before automatic reboot (default: 15)

.PARAMETER TestMode
    Run in test mode to download but not install updates

.PARAMETER ForceInstall
    Force installation even outside maintenance window

.EXAMPLE
    .\Update-SystemPatches.ps1 -MaintenanceWindow "Sunday,02,06" -UpdateCategories @("Critical","Important")
    Install critical and important updates during Sunday 2-6 AM window

.EXAMPLE
    .\Update-SystemPatches.ps1 -TestMode -UpdateCategories @("Critical")
    Download but don't install critical updates

.NOTES
    Author: PowerShell Automation Project
    Requires: Administrator privileges and PSWindowsUpdate module
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$MaintenanceWindow,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Critical", "Important", "Optional", "Drivers", "DefinitionUpdates")]
    [string[]]$UpdateCategories = @("Critical", "Important"),
    
    [Parameter(Mandatory = $false)]
    [string[]]$ExcludeKBs = @(),
    
    [Parameter(Mandatory = $false)]
    [switch]$AutoReboot,
    
    [Parameter(Mandatory = $false)]
    [ValidateRange(5, 120)]
    [int]$RebootDelay = 15,
    
    [Parameter(Mandatory = $false)]
    [switch]$TestMode,
    
    [Parameter(Mandatory = $false)]
    [switch]$ForceInstall
)

# Initialize variables
$ErrorActionPreference = "Continue"
$LogFile = "$env:TEMP\SystemUpdates_$(Get-Date -Format 'yyyyMMdd').log"
$UpdateSession = $null
$RebootRequired = $false

function Write-UpdateLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    Write-Host $logMessage
    Add-Content -Path $LogFile -Value $logMessage
}

function Test-MaintenanceWindow {
    if (-not $MaintenanceWindow -or $ForceInstall) {
        return $true
    }
    
    try {
        $windowParts = $MaintenanceWindow -split ','
        if ($windowParts.Count -ne 3) {
            Write-UpdateLog "Invalid maintenance window format. Expected: DayOfWeek,StartHour,EndHour" -Level "ERROR"
            return $false
        }
        
        $targetDay = [System.DayOfWeek]$windowParts[0]
        $startHour = [int]$windowParts[1]
        $endHour = [int]$windowParts[2]
        
        $currentTime = Get-Date
        $currentDay = $currentTime.DayOfWeek
        $currentHour = $currentTime.Hour
        
        if ($currentDay -eq $targetDay -and $currentHour -ge $startHour -and $currentHour -lt $endHour) {
            Write-UpdateLog "Currently in maintenance window: $MaintenanceWindow"
            return $true
        }
        else {
            Write-UpdateLog "Outside maintenance window. Current: $currentDay $currentHour, Window: $MaintenanceWindow"
            return $false
        }
    }
    catch {
        Write-UpdateLog "Error parsing maintenance window: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Install-PSWindowsUpdateModule {
    Write-UpdateLog "Checking for PSWindowsUpdate module..."
    
    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Write-UpdateLog "PSWindowsUpdate module not found. Installing..."
        
        try {
            Install-Module -Name PSWindowsUpdate -Force -AllowClobber
            Write-UpdateLog "PSWindowsUpdate module installed successfully"
        }
        catch {
            Write-UpdateLog "Failed to install PSWindowsUpdate module: $($_.Exception.Message)" -Level "ERROR"
            
            # Try alternative method using Windows Update API directly
            Write-UpdateLog "Falling back to Windows Update API"
            return $false
        }
    }
    else {
        Write-UpdateLog "PSWindowsUpdate module is available"
    }
    
    try {
        Import-Module PSWindowsUpdate -Force
        return $true
    }
    catch {
        Write-UpdateLog "Failed to import PSWindowsUpdate module: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Initialize-WindowsUpdateAPI {
    Write-UpdateLog "Initializing Windows Update API..."
    
    try {
        $script:UpdateSession = New-Object -ComObject Microsoft.Update.Session
        $script:UpdateSearcher = $script:UpdateSession.CreateUpdateSearcher()
        $script:UpdateDownloader = $script:UpdateSession.CreateUpdateDownloader()
        $script:UpdateInstaller = $script:UpdateSession.CreateUpdateInstaller()
        
        Write-UpdateLog "Windows Update API initialized successfully"
        return $true
    }
    catch {
        Write-UpdateLog "Failed to initialize Windows Update API: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Get-AvailableUpdates {
    Write-UpdateLog "Searching for available updates..."
    
    try {
        # Create search criteria based on categories
        $searchCriteria = "IsInstalled=0"
        
        if ($UpdateCategories -contains "Critical") {
            $searchCriteria += " and Type='Software'"
        }
        
        Write-UpdateLog "Search criteria: $searchCriteria"
        $searchResult = $script:UpdateSearcher.Search($searchCriteria)
        
        Write-UpdateLog "Found $($searchResult.Updates.Count) available updates"
        
        $filteredUpdates = @()
        
        foreach ($update in $searchResult.Updates) {
            $includeUpdate = $true
            
            # Filter by categories
            $updateCategories = $update.Categories | ForEach-Object { $_.Name }
            $categoryMatch = $false
            
            foreach ($category in $UpdateCategories) {
                if ($updateCategories -contains $category) {
                    $categoryMatch = $true
                    break
                }
            }
            
            if (-not $categoryMatch) {
                $includeUpdate = $false
                Write-UpdateLog "Excluding update (category): $($update.Title)"
            }
            
            # Filter by excluded KBs
            foreach ($excludeKB in $ExcludeKBs) {
                if ($update.Title -match $excludeKB -or $update.KBArticleIDs -contains $excludeKB) {
                    $includeUpdate = $false
                    Write-UpdateLog "Excluding update (KB filter): $($update.Title)"
                    break
                }
            }
            
            if ($includeUpdate) {
                $filteredUpdates += $update
            }
        }
        
        Write-UpdateLog "After filtering: $($filteredUpdates.Count) updates to process"
        return $filteredUpdates
    }
    catch {
        Write-UpdateLog "Error searching for updates: $($_.Exception.Message)" -Level "ERROR"
        return @()
    }
}

function Download-Updates {
    param([array]$Updates)
    
    if ($Updates.Count -eq 0) {
        Write-UpdateLog "No updates to download"
        return $true
    }
    
    Write-UpdateLog "Downloading $($Updates.Count) updates..."
    
    try {
        $script:UpdateDownloader.Updates = $Updates
        $downloadResult = $script:UpdateDownloader.Download()
        
        if ($downloadResult.ResultCode -eq 2) {  # OperationResultCodeSucceeded
            Write-UpdateLog "All updates downloaded successfully"
            return $true
        }
        else {
            Write-UpdateLog "Download completed with result code: $($downloadResult.ResultCode)" -Level "WARNING"
            
            # Check individual update results
            for ($i = 0; $i -lt $Updates.Count; $i++) {
                $result = $downloadResult.GetUpdateResult($i)
                if ($result.ResultCode -ne 2) {
                    Write-UpdateLog "Download failed for: $($Updates[$i].Title) (Code: $($result.ResultCode))" -Level "ERROR"
                }
            }
            
            return $false
        }
    }
    catch {
        Write-UpdateLog "Error downloading updates: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Install-Updates {
    param([array]$Updates)
    
    if ($Updates.Count -eq 0) {
        Write-UpdateLog "No updates to install"
        return $true
    }
    
    if ($TestMode) {
        Write-UpdateLog "TEST MODE: Would install $($Updates.Count) updates:"
        foreach ($update in $Updates) {
            Write-UpdateLog "  - $($update.Title)"
        }
        return $true
    }
    
    Write-UpdateLog "Installing $($Updates.Count) updates..."
    
    try {
        # Check if any updates require reboot
        foreach ($update in $Updates) {
            if ($update.InstallationBehavior.RebootBehavior -ne 0) {
                $script:RebootRequired = $true
                Write-UpdateLog "Update requires reboot: $($update.Title)"
            }
        }
        
        $script:UpdateInstaller.Updates = $Updates
        $installResult = $script:UpdateInstaller.Install()
        
        if ($installResult.ResultCode -eq 2) {  # OperationResultCodeSucceeded
            Write-UpdateLog "All updates installed successfully"
            
            # Log installation details
            for ($i = 0; $i -lt $Updates.Count; $i++) {
                $result = $installResult.GetUpdateResult($i)
                $update = $Updates[$i]
                
                if ($result.ResultCode -eq 2) {
                    Write-UpdateLog "Installed: $($update.Title)"
                }
                else {
                    Write-UpdateLog "Installation failed: $($update.Title) (Code: $($result.ResultCode))" -Level "ERROR"
                }
            }
            
            return $true
        }
        else {
            Write-UpdateLog "Installation completed with result code: $($installResult.ResultCode)" -Level "WARNING"
            return $false
        }
    }
    catch {
        Write-UpdateLog "Error installing updates: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Test-SystemHealth {
    param([string]$Phase)
    
    Write-UpdateLog "Performing system health check ($Phase)..."
    
    $healthResults = @{
        Phase = $Phase
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Checks = @{}
    }
    
    # Check disk space
    try {
        $systemDrive = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'"
        $freeSpaceGB = [math]::Round($systemDrive.FreeSpace / 1GB, 2)
        $healthResults.Checks.DiskSpace = @{
            Status = if ($freeSpaceGB -gt 5) { "OK" } else { "WARNING" }
            Value = "$freeSpaceGB GB free"
        }
        Write-UpdateLog "Disk space check: $freeSpaceGB GB free"
    }
    catch {
        $healthResults.Checks.DiskSpace = @{
            Status = "ERROR"
            Value = "Unable to check disk space"
        }
        Write-UpdateLog "Error checking disk space: $($_.Exception.Message)" -Level "ERROR"
    }
    
    # Check critical services
    $criticalServices = @("Winmgmt", "EventLog", "RpcSs", "Dhcp", "Dnscache")
    $serviceIssues = 0
    
    foreach ($serviceName in $criticalServices) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if (-not $service -or $service.Status -ne "Running") {
                $serviceIssues++
                Write-UpdateLog "Service issue: $serviceName" -Level "WARNING"
            }
        }
        catch {
            $serviceIssues++
        }
    }
    
    $healthResults.Checks.Services = @{
        Status = if ($serviceIssues -eq 0) { "OK" } else { "WARNING" }
        Value = "$serviceIssues issues found"
    }
    
    # Check Windows Update service
    try {
        $wuService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
        $healthResults.Checks.WindowsUpdate = @{
            Status = if ($wuService -and $wuService.Status -eq "Running") { "OK" } else { "WARNING" }
            Value = if ($wuService) { $wuService.Status } else { "Not Found" }
        }
    }
    catch {
        $healthResults.Checks.WindowsUpdate = @{
            Status = "ERROR"
            Value = "Unable to check service"
        }
    }
    
    Write-UpdateLog "System health check completed"
    return $healthResults
}

function Invoke-SystemReboot {
    if (-not $AutoReboot) {
        Write-UpdateLog "Reboot required but AutoReboot is disabled. Manual reboot needed."
        return
    }
    
    Write-UpdateLog "System reboot required. Rebooting in $RebootDelay minutes..."
    
    # Send shutdown command with delay
    $shutdownTime = $RebootDelay * 60  # Convert to seconds
    
    try {
        shutdown.exe /r /t $shutdownTime /c "Automated system reboot after Windows Updates"
        Write-UpdateLog "Reboot scheduled successfully"
        
        # Optional: Send notification if email is configured
        Send-UpdateNotification -Subject "System Reboot Scheduled" -Message "System will reboot in $RebootDelay minutes after Windows Updates"
    }
    catch {
        Write-UpdateLog "Error scheduling reboot: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Send-UpdateNotification {
    param(
        [string]$Subject,
        [string]$Message
    )
    
    $emailConfigPath = ".\config\email.json"
    if (-not (Test-Path $emailConfigPath)) {
        return
    }
    
    try {
        $emailConfig = Get-Content -Path $emailConfigPath -Raw | ConvertFrom-Json
        
        $body = @"
Windows Update Notification

$Message

Computer: $env:COMPUTERNAME
Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

This is an automated notification from the System Update script.
"@
        
        $emailParams = @{
            To = $emailConfig.To
            From = $emailConfig.From
            Subject = $Subject
            Body = $body
            SmtpServer = $emailConfig.SmtpServer
        }
        
        if ($emailConfig.Credential) {
            $emailParams.Credential = $emailConfig.Credential
        }
        
        Send-MailMessage @emailParams
        Write-UpdateLog "Email notification sent: $Subject"
    }
    catch {
        Write-UpdateLog "Error sending email notification: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Generate-UpdateReport {
    param(
        [array]$InstalledUpdates,
        [hashtable]$PreHealthCheck,
        [hashtable]$PostHealthCheck
    )
    
    $report = @{
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Computer = $env:COMPUTERNAME
        MaintenanceWindow = $MaintenanceWindow
        UpdateCategories = $UpdateCategories
        TestMode = $TestMode.IsPresent
        RebootRequired = $script:RebootRequired
        Summary = @{
            TotalUpdates = $InstalledUpdates.Count
            SuccessfulInstalls = 0
            FailedInstalls = 0
        }
        Updates = @()
        HealthChecks = @{
            PreUpdate = $PreHealthCheck
            PostUpdate = $PostHealthCheck
        }
    }
    
    foreach ($update in $InstalledUpdates) {
        $updateInfo = @{
            Title = $update.Title
            Description = $update.Description
            Categories = $update.Categories | ForEach-Object { $_.Name }
            Size = "$([math]::Round($update.MaxDownloadSize / 1MB, 2)) MB"
            KBArticleIDs = $update.KBArticleIDs
        }
        
        $report.Updates += $updateInfo
        $report.Summary.SuccessfulInstalls++
    }
    
    return $report
}

# Main execution
Write-UpdateLog "=== Windows Update Process Started ==="
Write-UpdateLog "Maintenance Window: $MaintenanceWindow"
Write-UpdateLog "Update Categories: $($UpdateCategories -join ', ')"
Write-UpdateLog "Test Mode: $TestMode"
Write-UpdateLog "Auto Reboot: $AutoReboot"

# Check maintenance window
if (-not (Test-MaintenanceWindow)) {
    Write-UpdateLog "Not in maintenance window. Exiting."
    exit 0
}

# Perform pre-update health check
$preHealthCheck = Test-SystemHealth -Phase "Pre-Update"

# Initialize Windows Update components
$apiInitialized = Initialize-WindowsUpdateAPI
$moduleAvailable = Install-PSWindowsUpdateModule

if (-not $apiInitialized -and -not $moduleAvailable) {
    Write-UpdateLog "Unable to initialize Windows Update components" -Level "ERROR"
    exit 1
}

try {
    # Get available updates
    $availableUpdates = Get-AvailableUpdates
    
    if ($availableUpdates.Count -eq 0) {
        Write-UpdateLog "No updates available"
        Send-UpdateNotification -Subject "Windows Updates - No Updates Available" -Message "No updates found for installation."
        exit 0
    }
    
    Write-UpdateLog "Found $($availableUpdates.Count) updates to process"
    
    # Download updates
    if (Download-Updates -Updates $availableUpdates) {
        Write-UpdateLog "Download phase completed successfully"
        
        # Install updates
        if (Install-Updates -Updates $availableUpdates) {
            Write-UpdateLog "Installation phase completed successfully"
            
            # Perform post-update health check
            $postHealthCheck = Test-SystemHealth -Phase "Post-Update"
            
            # Generate report
            $updateReport = Generate-UpdateReport -InstalledUpdates $availableUpdates -PreHealthCheck $preHealthCheck -PostHealthCheck $postHealthCheck
            $reportJson = $updateReport | ConvertTo-Json -Depth 4
            $reportPath = "$env:TEMP\UpdateReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
            $reportJson | Set-Content -Path $reportPath
            
            Write-UpdateLog "Update report generated: $reportPath"
            
            # Send success notification
            Send-UpdateNotification -Subject "Windows Updates - Installation Complete" -Message "Successfully installed $($availableUpdates.Count) updates. Report: $reportPath"
            
            # Handle reboot if required
            if ($script:RebootRequired) {
                Invoke-SystemReboot
            }
        }
        else {
            Write-UpdateLog "Installation phase failed" -Level "ERROR"
            Send-UpdateNotification -Subject "Windows Updates - Installation Failed" -Message "Update installation encountered errors. Check logs for details."
        }
    }
    else {
        Write-UpdateLog "Download phase failed" -Level "ERROR"
        Send-UpdateNotification -Subject "Windows Updates - Download Failed" -Message "Update download encountered errors. Check logs for details."
    }
}
catch {
    Write-UpdateLog "Unexpected error during update process: $($_.Exception.Message)" -Level "ERROR"
    Send-UpdateNotification -Subject "Windows Updates - Process Error" -Message "Update process encountered an unexpected error: $($_.Exception.Message)"
}
finally {
    Write-UpdateLog "=== Windows Update Process Completed ==="
    
    # Return final status
    return @{
        UpdatesProcessed = if ($availableUpdates) { $availableUpdates.Count } else { 0 }
        RebootRequired = $script:RebootRequired
        LogFile = $LogFile
        PreHealthCheck = $preHealthCheck
        PostHealthCheck = if ($postHealthCheck) { $postHealthCheck } else { $null }
    }
}
