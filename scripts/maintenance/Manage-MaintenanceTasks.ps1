<#
.SYNOPSIS
    Manages and schedules automated maintenance tasks for Windows systems.

.DESCRIPTION
    This script creates, manages, and monitors scheduled tasks for system maintenance
    operations including:
    - Creating scheduled tasks for maintenance scripts
    - Managing task schedules and configurations  
    - Monitoring task execution and results
    - Generating maintenance task reports
    - Email notifications for task failures

.PARAMETER Action
    Action to perform: Create, Remove, List, Report, Monitor

.PARAMETER TaskName
    Name of the specific task to manage

.PARAMETER ScriptPath
    Path to the PowerShell script to schedule

.PARAMETER Schedule
    Schedule configuration in JSON format or predefined schedule name

.PARAMETER EmailNotifications
    Enable email notifications for task failures

.PARAMETER Force
    Force creation/removal without confirmation

.EXAMPLE
    .\Manage-MaintenanceTasks.ps1 -Action Create -TaskName "DiskCleanup" -ScriptPath "Clear-DiskSpace.ps1" -Schedule "Daily"
    Creates a daily scheduled task for disk cleanup

.EXAMPLE
    .\Manage-MaintenanceTasks.ps1 -Action Report
    Generates a report of all maintenance tasks

.NOTES
    Author: PowerShell Automation Project
    Requires: Administrator privileges to manage scheduled tasks
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Create", "Remove", "List", "Report", "Monitor", "Setup")]
    [string]$Action,
    
    [Parameter(Mandatory = $false)]
    [string]$TaskName,
    
    [Parameter(Mandatory = $false)]
    [string]$ScriptPath,
    
    [Parameter(Mandatory = $false)]
    [string]$Schedule,
    
    [Parameter(Mandatory = $false)]
    [switch]$EmailNotifications,
    
    [Parameter(Mandatory = $false)]
    [switch]$Force
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
$LogFile = "$env:TEMP\MaintenanceTasks_$(Get-Date -Format 'yyyyMMdd').log"
$TaskFolder = "\MaintenanceAutomation"

# Predefined schedule templates
$ScheduleTemplates = @{
    "Daily" = @{
        Frequency = "Daily"
        StartTime = "02:00"
        Description = "Runs daily at 2:00 AM"
    }
    "Weekly" = @{
        Frequency = "Weekly"
        DaysOfWeek = "Sunday"
        StartTime = "01:00"
        Description = "Runs weekly on Sunday at 1:00 AM"
    }
    "Monthly" = @{
        Frequency = "Monthly"
        DayOfMonth = 1
        StartTime = "00:30"
        Description = "Runs monthly on the 1st day at 12:30 AM"
    }
    "Startup" = @{
        Frequency = "AtStartup"
        Delay = "PT5M"
        Description = "Runs 5 minutes after system startup"
    }
}

# Default maintenance task configurations
$DefaultTasks = @{
    "DiskCleanup" = @{
        ScriptPath = "scripts\maintenance\Clear-DiskSpace.ps1"
        Parameters = "-LogRetentionDays 30"
        Schedule = "Weekly"
        Description = "Automated disk space cleanup"
        Priority = "High"
    }
    "ServiceMonitor" = @{
        ScriptPath = "scripts\maintenance\Monitor-CriticalServices.ps1" 
        Parameters = "-ReportOnly -EmailNotifications"
        Schedule = "Daily"
        Description = "Critical service health monitoring"
        Priority = "High"
    }
    "SystemUpdates" = @{
        ScriptPath = "scripts\maintenance\Update-SystemPatches.ps1"
        Parameters = "-MaintenanceWindow 'Sunday,02,06' -UpdateCategories @('Critical','Important') -AutoReboot"
        Schedule = "Weekly"
        Description = "Automated Windows Update installation"
        Priority = "Normal"
    }
}

function Write-TaskLog {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$Task = ""
    )


}
}
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $taskInfo = if ($Task) { " [$Task]" } else { "" }
    $logMessage = "[$timestamp] [$Level]$taskInfo $Message"
    
    Write-Host $logMessage
    Add-Content -Path $LogFile -Value $logMessage
}

function Test-AdminPrivileges {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Initialize-TaskScheduler {
    Write-TaskLog "Initializing Task Scheduler components..."
    
    if (-not (Test-AdminPrivileges)) {
        Write-TaskLog "Administrator privileges required for task management" -Level "ERROR"
        return $false
    }
    
    try {
        $script:TaskScheduler = New-Object -ComObject Schedule.Service
        $script:TaskScheduler.Connect()
        
        # Create maintenance task folder if it doesn't exist
        try {
            $rootFolder = $script:TaskScheduler.GetFolder("\")
            $maintenanceFolder = $rootFolder.GetFolder($TaskFolder)
        }
        catch {
            Write-TaskLog "Creating maintenance task folder: $TaskFolder"
            $rootFolder.CreateFolder($TaskFolder)
        }
        
        Write-TaskLog "Task Scheduler initialized successfully"
        return $true
    }
    catch {
        Write-TaskLog "Failed to initialize Task Scheduler: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function New-MaintenanceTask {
    param(
        [string]$Name,
        [string]$ScriptPath,
        [string]$Parameters,
        [hashtable]$ScheduleConfig,
        [string]$Description,
        [string]$Priority = "Normal"
    )

}
    Write-TaskLog "Creating maintenance task: $Name" -Task $Name
    
    try {
        # Create task definition
        $taskDefinition = $script:TaskScheduler.NewTask(0)
        $taskDefinition.RegistrationInfo.Description = $Description
        $taskDefinition.RegistrationInfo.Author = "PowerShell Automation"
        
        # Set principal (run as SYSTEM with highest privileges)
        $principal = $taskDefinition.Principal
        $principal.UserId = "SYSTEM"
        $principal.LogonType = 5  # S4U logon type
        $principal.RunLevel = 1   # Highest privileges
        
        # Set settings
        $settings = $taskDefinition.Settings
        $settings.Enabled = $true
        $settings.Hidden = $false
        $settings.ExecutionTimeLimit = "PT4H"  # 4 hour timeout
        $settings.Priority = switch ($Priority) {
            "High" { 4 }
            "Normal" { 6 }
            "Low" { 8 }
            default { 6 }
        }
        $settings.DisallowStartIfOnBatteries = $false
        $settings.StopIfGoingOnBatteries = $false
        $settings.WakeToRun = $false
        $settings.StartWhenAvailable = $true
        $settings.RestartOnFailure.Enabled = $true
        $settings.RestartOnFailure.Count = 3
        $settings.RestartOnFailure.Interval = "PT15M"
        
        # Create trigger based on schedule
        $trigger = $taskDefinition.Triggers.Create($null)
        
        switch ($ScheduleConfig.Frequency) {
            "Daily" {
                $trigger.Type = 2  # Daily trigger
                $trigger.DaysInterval = 1
                $trigger.StartBoundary = (Get-Date $ScheduleConfig.StartTime).ToString("yyyy-MM-ddTHH:mm:ss")
            }
            "Weekly" {
                $trigger.Type = 3  # Weekly trigger
                $trigger.WeeksInterval = 1
                $trigger.DaysOfWeek = switch ($ScheduleConfig.DaysOfWeek) {
                    "Sunday" { 1 }
                    "Monday" { 2 }
                    "Tuesday" { 4 }
                    "Wednesday" { 8 }
                    "Thursday" { 16 }
                    "Friday" { 32 }
                    "Saturday" { 64 }
                    default { 1 }
                }
                $trigger.StartBoundary = (Get-Date $ScheduleConfig.StartTime).ToString("yyyy-MM-ddTHH:mm:ss")
            }
            "Monthly" {
                $trigger.Type = 4  # Monthly trigger
                $trigger.MonthsOfYear = 4095  # All months
                $trigger.DaysOfMonth = [math]::Pow(2, $ScheduleConfig.DayOfMonth - 1)
                $trigger.StartBoundary = (Get-Date $ScheduleConfig.StartTime).ToString("yyyy-MM-ddTHH:mm:ss")
            }
            "AtStartup" {
                $trigger.Type = 8  # Boot trigger
                if ($ScheduleConfig.Delay) {
                    $trigger.Delay = $ScheduleConfig.Delay
                }
            }
        }
        
        # Create action
        $action = $taskDefinition.Actions.Create(0)  # Exec action
        $action.Path = "PowerShell.exe"
        $action.Arguments = "-ExecutionPolicy Bypass -File `"$ScriptPath`" $Parameters"
        $action.WorkingDirectory = Split-Path $ScriptPath -Parent
        
        # Register the task
        $taskFolder = $script:TaskScheduler.GetFolder($TaskFolder)
        $registeredTask = $taskFolder.RegisterTaskDefinition(
            $Name,
            $taskDefinition,
            6,  # TASK_CREATE_OR_UPDATE
            $null,
            $null,
            5   # TASK_LOGON_SERVICE_ACCOUNT
        )
        
        Write-TaskLog "Task created successfully: $Name" -Task $Name
        return $true
    }
    catch {
        Write-TaskLog "Error creating task: $($_.Exception.Message)" -Level "ERROR" -Task $Name
        return $false
    }
}

function Remove-MaintenanceTask {
    param([string]$Name)

}
    Write-TaskLog "Removing maintenance task: $Name" -Task $Name
    
    try {
        $taskFolder = $script:TaskScheduler.GetFolder($TaskFolder)
        $taskFolder.DeleteTask($Name, 0)
        
        Write-TaskLog "Task removed successfully: $Name" -Task $Name
        return $true
    }
    catch {
        Write-TaskLog "Error removing task: $($_.Exception.Message)" -Level "ERROR" -Task $Name
        return $false
    }
}

function Get-MaintenanceTasks {
    Write-TaskLog "Retrieving maintenance tasks..."
    
    try {
        $taskFolder = $script:TaskScheduler.GetFolder($TaskFolder)
        $tasks = $taskFolder.GetTasks(0)
        
        $taskList = @()
        foreach ($task in $tasks) {
            $taskInfo = @{
                Name = $task.Name
                Path = $task.Path
                State = switch ($task.State) {
                    0 { "Unknown" }
                    1 { "Disabled" }
                    2 { "Queued" }
                    3 { "Ready" }
                    4 { "Running" }
                    default { "Unknown" }
                }
                LastRunTime = if ($task.LastRunTime) { $task.LastRunTime.ToString() } else { "Never" }
                LastTaskResult = $task.LastTaskResult
                NextRunTime = if ($task.NextRunTime) { $task.NextRunTime.ToString() } else { "Not Scheduled" }
                NumberOfMissedRuns = $task.NumberOfMissedRuns
                Enabled = $task.Enabled
            }
            $taskList += $taskInfo
        }
        
        Write-TaskLog "Retrieved $($taskList.Count) maintenance tasks"
        return $taskList
    }
    catch {
        Write-TaskLog "Error retrieving tasks: $($_.Exception.Message)" -Level "ERROR"
        return @()
    }
}

function Monitor-TaskExecution {
    Write-TaskLog "Starting task execution monitoring..."
    
    $tasks = Get-MaintenanceTasks
    $issues = @()
    
    foreach ($task in $tasks) {
        Write-TaskLog "Checking task: $($task.Name)" -Task $task.Name
        
        # Check for failed executions
        if ($task.LastTaskResult -ne 0 -and $task.LastTaskResult -ne 267014) {  # 267014 = Task hasn't run
            $issues += [PSCustomObject]@{
                TaskName = $task.Name
                Issue = "Failed Execution"
                Details = "Last result code: $($task.LastTaskResult)"
                LastRunTime = $task.LastRunTime
            }
            Write-TaskLog "Task execution failed with code: $($task.LastTaskResult)" -Level "WARNING" -Task $task.Name
        }
        
        # Check for missed runs
        if ($task.NumberOfMissedRuns -gt 0) {
            $issues += [PSCustomObject]@{
                TaskName = $task.Name
                Issue = "Missed Runs"
                Details = "Number of missed runs: $($task.NumberOfMissedRuns)"
                LastRunTime = $task.LastRunTime
            }
            Write-TaskLog "Task has $($task.NumberOfMissedRuns) missed runs" -Level "WARNING" -Task $task.Name
        }
        
        # Check if task is disabled
        if (-not $task.Enabled) {
            $issues += [PSCustomObject]@{
                TaskName = $task.Name
                Issue = "Task Disabled"
                Details = "Task is currently disabled"
                LastRunTime = $task.LastRunTime
            }
            Write-TaskLog "Task is disabled" -Level "WARNING" -Task $task.Name
        }
    }
    
    if ($issues.Count -gt 0) {
        Write-TaskLog "Found $($issues.Count) task issues" -Level "WARNING"
        Send-TaskAlert -Issues $issues
    }
    else {
        Write-TaskLog "All tasks are healthy"
    }
    
    return $issues
}

function Send-TaskAlert {
    param([array]$Issues)

}
    if (-not $EmailNotifications) {
        return
    }
    
    $emailConfigPath = ".\config\email.json"
    if (-not (Test-Path $emailConfigPath)) {
        Write-TaskLog "Email configuration not found, skipping notification" -Level "WARNING"
        return
    }
    
    try {
        $emailConfig = Get-Content -Path $emailConfigPath -Raw | ConvertFrom-Json
        
        $subject = "Maintenance Task Alert - $($Issues.Count) Issues Found"
        $body = @"
Maintenance Task Monitoring Alert

$($Issues.Count) issues found with scheduled maintenance tasks:

"@
        
        foreach ($issue in $Issues) {
            $body += @"
Task: $($issue.TaskName)
Issue: $($issue.Issue)
Details: $($issue.Details)
Last Run: $($issue.LastRunTime)

"@
        }
        
        $body += @"
Computer: $env:COMPUTERNAME
Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

This is an automated notification from the Maintenance Task Manager.
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
        Write-TaskLog "Email alert sent for $($Issues.Count) task issues"
    }
    catch {
        Write-TaskLog "Error sending email alert: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Generate-TaskReport {
    $tasks = Get-MaintenanceTasks
    
    $report = @{
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Computer = $env:COMPUTERNAME
        TaskFolder = $TaskFolder
        Summary = @{
            TotalTasks = $tasks.Count
            EnabledTasks = ($tasks | Where-Object { $_.Enabled }).Count
            DisabledTasks = ($tasks | Where-Object { -not $_.Enabled }).Count
            RunningTasks = ($tasks | Where-Object { $_.State -eq "Running" }).Count
            FailedTasks = ($tasks | Where-Object { $_.LastTaskResult -ne 0 -and $_.LastTaskResult -ne 267014 }).Count
        }
        Tasks = $tasks
    }
    
    return $report
}

function Setup-DefaultTasks {
    Write-TaskLog "Setting up default maintenance tasks..."
    
    $successCount = 0
    
    foreach ($taskName in $DefaultTasks.Keys) {
        $taskConfig = $DefaultTasks[$taskName]
        
        # Check if script exists
        if (-not (Test-Path $taskConfig.ScriptPath)) {
            Write-TaskLog "Script not found: $($taskConfig.ScriptPath)" -Level "WARNING" -Task $taskName
            continue
        }
        
        # Get schedule configuration
        $scheduleConfig = $ScheduleTemplates[$taskConfig.Schedule]
        if (-not $scheduleConfig) {
            Write-TaskLog "Unknown schedule template: $($taskConfig.Schedule)" -Level "ERROR" -Task $taskName
            continue
        }
        
        # Create the task
        if (New-MaintenanceTask -Name $taskName -ScriptPath $taskConfig.ScriptPath -Parameters $taskConfig.Parameters -ScheduleConfig $scheduleConfig -Description $taskConfig.Description -Priority $taskConfig.Priority) {
            $successCount++
        }
    }
    
    Write-TaskLog "Successfully created $successCount of $($DefaultTasks.Count) default tasks"
    return $successCount
}

# Main execution
Write-TaskLog "=== Maintenance Task Manager Started ==="
Write-TaskLog "Action: $Action"
Write-TaskLog "Task Name: $TaskName"
Write-TaskLog "Email Notifications: $EmailNotifications"

# Initialize Task Scheduler
if (-not (Initialize-TaskScheduler)) {
    Write-TaskLog "Failed to initialize Task Scheduler" -Level "ERROR"
    exit 1
}

try {
    switch ($Action) {
        "Create" {
            if (-not $TaskName -or -not $ScriptPath) {
                Write-TaskLog "TaskName and ScriptPath are required for Create action" -Level "ERROR"
                exit 1
            }
            
            if (-not (Test-Path $ScriptPath)) {
                Write-TaskLog "Script file not found: $ScriptPath" -Level "ERROR"
                exit 1
            }
            
            # Use predefined schedule or parse custom schedule
            $scheduleConfig = if ($ScheduleTemplates.ContainsKey($Schedule)) {
                $ScheduleTemplates[$Schedule]
            } else {
                try {
                    $Schedule | ConvertFrom-Json
                } catch {
                    Write-TaskLog "Invalid schedule format" -Level "ERROR"
                    exit 1
                }
            }
            
            if (New-MaintenanceTask -Name $TaskName -ScriptPath $ScriptPath -Parameters "" -ScheduleConfig $scheduleConfig -Description "Custom maintenance task: $TaskName") {
                Write-TaskLog "Task created successfully: $TaskName"
            }
        }
        
        "Remove" {
            if (-not $TaskName) {
                Write-TaskLog "TaskName is required for Remove action" -Level "ERROR"
                exit 1
            }
            
            if ($Force -or (Read-Host "Remove task '$TaskName'? (y/N)") -eq 'y') {
                if (Remove-MaintenanceTask -Name $TaskName) {
                    Write-TaskLog "Task removed successfully: $TaskName"
                }
            }
        }
        
        "List" {
            $tasks = Get-MaintenanceTasks
            Write-Host "`n=== Maintenance Tasks ===" -ForegroundColor Green
            $tasks | Format-Table -AutoSize
        }
        
        "Report" {
            $report = Generate-TaskReport
            $reportJson = $report | ConvertTo-Json -Depth 3
            $reportPath = "$env:TEMP\MaintenanceTaskReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
            $reportJson | Set-Content -Path $reportPath
            
            Write-TaskLog "Report generated: $reportPath"
            Write-Host "`n=== Task Summary ===" -ForegroundColor Green
            Write-Host "Total Tasks: $($report.Summary.TotalTasks)"
            Write-Host "Enabled: $($report.Summary.EnabledTasks)" -ForegroundColor Green
            Write-Host "Disabled: $($report.Summary.DisabledTasks)" -ForegroundColor Yellow
            Write-Host "Running: $($report.Summary.RunningTasks)" -ForegroundColor Cyan
            Write-Host "Failed: $($report.Summary.FailedTasks)" -ForegroundColor Red
        }
        
        "Monitor" {
            $issues = Monitor-TaskExecution
            Write-Host "`n=== Monitoring Results ===" -ForegroundColor Green
            if ($issues.Count -eq 0) {
                Write-Host "All tasks are healthy" -ForegroundColor Green
            } else {
                Write-Host "Found $($issues.Count) issues:" -ForegroundColor Yellow
                $issues | Format-Table -AutoSize
            }
        }
        
        "Setup" {
            if ($Force -or (Read-Host "Create default maintenance tasks? (y/N)") -eq 'y') {
                $created = Setup-DefaultTasks
                Write-Host "Created $created default maintenance tasks" -ForegroundColor Green
            }
        }
    }
}
catch {
    Write-TaskLog "Unexpected error: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}
finally {
    Write-TaskLog "=== Maintenance Task Manager Completed ==="
}


