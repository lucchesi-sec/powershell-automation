<#
.SYNOPSIS
    Collects various pieces of volatile system data and returns it as a single PowerShell object.
.DESCRIPTION
    This script gathers live system information that can change quickly, including currently
    logged-on users, ARP cache entries, DNS client cache, and running processes. It outputs
    this data as a structured PSCustomObject, allowing it to be piped to other cmdlets.
.EXAMPLE
    .\Collect-VolatileData.ps1
    Outputs a rich object containing all collected volatile data.
.EXAMPLE
    .\Collect-VolatileData.ps1 | Select-Object -ExpandProperty ARPCache
    Displays only the ARP cache (network neighbor) information.
.EXAMPLE
    .\Collect-VolatileData.ps1 | ConvertTo-Json -Depth 3
    Converts the collected volatile data into a JSON string.
.NOTES
    Author: Gemini
    Date: 25/06/2025
    Requires Administrator privileges for full access to all data sources.
    Refactored to output a single PSCustomObject for better pipeline integration.
#>
param ()

Write-Host "Collecting volatile system data..." -ForegroundColor Yellow

try {
    # --- Logged-on Users ---
    Write-Verbose "Collecting Logged-On Users..."
    $loggedOnUsers = Get-CimInstance -ClassName Win32_LogonSession -ErrorAction SilentlyContinue |
        Where-Object {$_.LogonType -in (2,10)} | # Interactive, RemoteInteractive
        ForEach-Object {
            $logonSession = $_;
            Get-CimAssociatedInstance -InputObject $logonSession -ResultClassName Win32_LoggedOnUser -ErrorAction SilentlyContinue |
            ForEach-Object {
                $account = Get-CimInstance -CimInstance $_.Antecedent -ErrorAction SilentlyContinue;
                [PSCustomObject]@{
                    UserName  = "$($account.Domain)\$($account.Name)";
                    LogonId   = $logonSession.LogonId;
                    LogonType = switch ($logonSession.LogonType) {
                        2 {"Interactive"}; 3 {"Network"}; 4 {"Batch"}; 5 {"Service"}; 7 {"Unlock"};
                        8 {"NetworkCleartext"}; 9 {"NewCredentials"}; 10 {"RemoteInteractive"};
                        11 {"CachedInteractive"}; default {"Unknown ($($logonSession.LogonType))"}
                    };
                    LogonTime = $logonSession.StartTime # This is CIM DateTime
                }
            }
        } | Select-Object UserName, LogonType, LogonTime, LogonId | Sort-Object UserName

    # --- ARP Cache ---
    Write-Verbose "Collecting ARP Cache (Network Neighbors)..."
    $arpCache = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias

    # --- DNS Client Cache ---
    Write-Verbose "Collecting DNS Client Cache..."
    $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Success'} | Select-Object Entry, Type, Data, Status, Section | Sort-Object Entry

    # --- Running Processes ---
    Write-Verbose "Collecting Running Processes..."
    $runningProcesses = Get-Process -IncludeUserName -ErrorAction SilentlyContinue | Select-Object Name, Id, Path, UserName

    # --- Assemble the final output object ---
    $volatileDataReport = [PSCustomObject]@{
        ReportDate       = Get-Date;
        LoggedOnUsers    = $loggedOnUsers;
        ARPCache         = $arpCache;
        DNSCache         = $dnsCache;
        RunningProcesses = $runningProcesses;
    }

    # Output the single, rich object to the pipeline
    Write-Output $volatileDataReport

    Write-Host "`nVolatile data collection complete." -ForegroundColor Green
    Write-Host "The script has returned a PowerShell object. Pipe it to other cmdlets to format or export." -ForegroundColor Gray
}
catch {
    Write-Error "An error occurred while collecting volatile data: $($_.Exception.Message)"
}
