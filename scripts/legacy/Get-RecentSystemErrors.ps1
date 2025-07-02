<#
.SYNOPSIS
    Retrieves recent Error and Warning events from the System event log.
.DESCRIPTION
    This script queries the System event log for events with a level of Error or Warning
    that have occurred within a specified number of hours.
.PARAMETER Hours
    The number of hours in the past to search for events. Defaults to 24 hours.
.EXAMPLE
    .\Get-RecentSystemErrors.ps1
    Gets errors and warnings from the System log in the last 24 hours.
.EXAMPLE
    .\Get-RecentSystemErrors.ps1 -Hours 72
    Gets errors and warnings from the System log in the last 72 hours.
.NOTES
    Author: Your Name
    Date: $(Get-Date)
    Requires permissions to read the System event log.
#>
param (
    [int]$Hours = 24
)

Write-Host "Querying System event log for Errors and Warnings in the last $Hours hour(s)..." -ForegroundColor Yellow

$startTime = (Get-Date).AddHours(-$Hours)

try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'System'
        Level     = 2, 3 # 2 for Error, 3 for Warning
        StartTime = $startTime
    } -ErrorAction Stop

    if ($events) {
        Write-Host "`n--- Recent System Errors and Warnings (Last $Hours Hours) ---" -ForegroundColor Cyan
        $events | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message | Format-Table -AutoSize -Wrap
    } else {
        Write-Host "`nNo Error or Warning events found in the System log for the last $Hours hour(s)." -ForegroundColor Green
    }
}
catch {
    Write-Error "An error occurred while querying the System event log: $($_.Exception.Message)"
}

Write-Host "`nSystem event log query complete." -ForegroundColor Yellow
