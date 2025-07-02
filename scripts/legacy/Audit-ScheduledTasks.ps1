<#
.SYNOPSIS
    Audits and lists scheduled tasks on the system.
.DESCRIPTION
    This script retrieves all scheduled tasks and displays key information
    such as the task path, name, state, actions, triggers, principal (run-as user),
    and last/next run times.
.EXAMPLE
    .\Audit-ScheduledTasks.ps1
    Lists all scheduled tasks with summary information.
.EXAMPLE
    .\Audit-ScheduledTasks.ps1 -Path "\Microsoft\Windows\Defrag\"
    Lists scheduled tasks only within the specified path.
.EXAMPLE
    .\Audit-ScheduledTasks.ps1 -ShowDisabled
    Includes disabled tasks in the output.
.NOTES
    Author: Your Name
    Date: $(Get-Date)
    Requires permissions to query scheduled tasks. Some tasks might require
    administrator privileges to view all details.
#>
param (
    [string]$Path = "*",  # Default to all paths
    [switch]$ShowDisabled
)

Write-Host "Auditing Scheduled Tasks (Path: '$Path')..." -ForegroundColor Yellow
if ($ShowDisabled) {
    Write-Host "Including disabled tasks in the audit." -ForegroundColor Yellow
}

try {
    $tasks = Get-ScheduledTask -TaskPath $Path -ErrorAction Stop
    
    if (-not $ShowDisabled) {
        $tasks = $tasks | Where-Object {$_.State -ne 'Disabled'}
    }

    if ($tasks) {
        Write-Host "`n--- Scheduled Task Details ---" -ForegroundColor Cyan
        
        $output = foreach ($task in $tasks) {
            # Consolidate actions into a readable string
            $actionStrings = @()
            if ($task.Actions) {
                foreach ($action in $task.Actions) {
                    if ($action -is [Microsoft.Management.Infrastructure.CimInstance]) { # For PSv5+ Get-ScheduledTask
                        if ($action.PSobject.Properties.Exists('Execute')) {
                            $actionStrings += "Exec: $($action.Execute)"
                            if ($action.PSobject.Properties.Exists('Arguments')) {$actionStrings[-1] += " $($action.Arguments)"}
                            if ($action.PSobject.Properties.Exists('WorkingDirectory')) {$actionStrings[-1] += " (WD: $($action.WorkingDirectory))"}
                        } elseif ($action.PSobject.Properties.Exists('ClassId')) { # ComHandlerAction
                             $actionStrings += "COM: $($action.ClassId)"
                        } # Add more action types if needed (Email, ShowMessage - deprecated)
                    } else { # Older PS versions might return different object types
                        $actionStrings += $action.ToString() 
                    }
                }
            }
            $actionsSummary = $actionStrings -join "; "

            # Consolidate triggers
            $triggerStrings = @()
            if ($task.Triggers) {
                foreach($trigger in $task.Triggers){
                    $triggerType = $trigger.PSobject.TypeNames[0] -replace "MSFT_ST(.*)Trigger","`$1"
                    $triggerStrings += $triggerType
                }
            }
            $triggersSummary = $triggerStrings -join ", "


            [PSCustomObject]@{
                TaskPath        = $task.TaskPath
                TaskName        = $task.TaskName
                State           = $task.State
                Principal       = $task.Principal.UserId
                RunLevel        = $task.Principal.RunLevel # HighestAvailable or Limited
                Actions         = $actionsSummary
                Triggers        = $triggersSummary
                Author          = $task.Author
                LastRunTime     = if ($task.LastRunTime -eq ([datetime]'1/1/0001 12:00:00 AM')) { "Never" } else { $task.LastRunTime }
                NextRunTime     = if ($task.NextRunTime -eq ([datetime]'1/1/0001 12:00:00 AM')) { "N/A" } else { $task.NextRunTime }
            }
        }
        
        $output | Format-Table -AutoSize -Wrap
        
    } else {
        Write-Host "`nNo scheduled tasks found matching the criteria." -ForegroundColor Green
    }
}
catch {
    Write-Error "An error occurred while auditing scheduled tasks: $($_.Exception.Message)"
}

Write-Host "`nScheduled task audit complete." -ForegroundColor Yellow
