<#
.SYNOPSIS
    Searches for specific Event IDs in a specified Windows event log.
.DESCRIPTION
    This script queries a chosen event log (e.g., Security, System, Application)
    for one or more specified Event IDs that have occurred within a given timeframe.
.PARAMETER EventID
    An integer or an array of integers representing the Event ID(s) to search for. Mandatory.
.PARAMETER LogName
    The name of the event log to query. Defaults to 'Security'.
    Common values: 'Security', 'System', 'Application'.
.PARAMETER Hours
    The number of hours in the past to search for events. Defaults to 24 hours.
.EXAMPLE
    .\Search-SpecificEventID.ps1 -EventID 4624
    Searches the Security log for successful logon events (ID 4624) in the last 24 hours.
.EXAMPLE
    .\Search-SpecificEventID.ps1 -EventID 4625, 4634 -LogName Security -Hours 48
    Searches the Security log for failed logons (4625) and logoffs (4634) in the last 48 hours.
.EXAMPLE
    .\Search-SpecificEventID.ps1 -EventID 1000, 1001 -LogName Application -Hours 72
    Searches the Application log for events 1000 and 1001 in the last 72 hours.
.NOTES
    Author: Your Name
    Date: $(Get-Date)
    Requires appropriate permissions to read the specified event log.
#>
param (
    [Parameter(Mandatory=$true)]
    [int[]]$EventID,

    [string]$LogName = 'Security',

    [int]$Hours = 24
)

Write-Host "Searching for Event ID(s): $($EventID -join ', ') in '$LogName' log for the last $Hours hour(s)..." -ForegroundColor Yellow

$startTime = (Get-Date).AddHours(-$Hours)

try {
    $filterHashtable = @{
        LogName   = $LogName
        Id        = $EventID # Get-WinEvent can take an array for Id
        StartTime = $startTime
    }

    $events = Get-WinEvent -FilterHashtable $filterHashtable -ErrorAction Stop

    if ($events) {
        Write-Host "`n--- Found Events (Log: $LogName, ID(s): $($EventID -join ', '), Last $Hours Hours) ---" -ForegroundColor Cyan
        # Select common useful properties. Message can be long.
        $events | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, TaskDisplayName, Message | Format-Table -AutoSize -Wrap
        
        # For more detailed properties, especially for Security events, you might need to parse the Message or use EventData
        # Example for extracting specific properties from XML for a known event ID (more advanced):
        # if ($LogName -eq 'Security' -and $EventID -contains 4624) {
        #     Write-Host "`n--- Parsed Logon Details (Event ID 4624) ---" -ForegroundColor Magenta
        #     $events | ForEach-Object {
        #         $xml = [xml]$_.ToXml()
        #         [PSCustomObject]@{
        #             Time = $_.TimeCreated
        #             TargetUser = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'
        #             TargetDomain = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetDomainName'} | Select-Object -ExpandProperty '#text'
        #             LogonType = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'LogonType'} | Select-Object -ExpandProperty '#text'
        #             SourceIP = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'} | Select-Object -ExpandProperty '#text'
        #         }
        #     } | Format-Table -AutoSize
        # }

    } else {
        Write-Host "`nNo events matching Event ID(s) $($EventID -join ', ') found in '$LogName' log for the last $Hours hour(s)." -ForegroundColor Green
    }
}
catch {
    Write-Error "An error occurred while querying event log '$LogName': $($_.Exception.Message)"
}

Write-Host "`nEvent log search complete." -ForegroundColor Yellow
