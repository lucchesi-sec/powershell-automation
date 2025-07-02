<#
.SYNOPSIS
    Takes a snapshot of current network TCP connections and UDP listeners.
.DESCRIPTION
    This script retrieves all current TCP connections and UDP listening endpoints,
    along with their associated process IDs. It can display this information
    to the console and optionally save it to a CSV file.
.PARAMETER OutputCsvPath
    Optional. The full path to a CSV file where the network connection snapshot will be saved.
    If not provided, output is to the console only.
.EXAMPLE
    .\Get-NetworkConnectionsSnapshot.ps1
    Displays current TCP connections and UDP listeners to the console.
.EXAMPLE
    .\Get-NetworkConnectionsSnapshot.ps1 -OutputCsvPath "C:\temp\NetworkSnapshot.csv"
    Displays the information and also saves it to C:\temp\NetworkSnapshot.csv.
.NOTES
    Author: Your Name
    Date: $(Get-Date)
    Requires permissions to query network state; running as Administrator is recommended for full details.
#>
param (
    [string]$OutputCsvPath
)

Write-Host "Gathering network connections snapshot..." -ForegroundColor Yellow

$connections = @()

# Get TCP Connections
try {
    Write-Host "Querying TCP connections..."
    $tcpConnections = Get-NetTCPConnection -ErrorAction Stop
    if ($tcpConnections) {
        foreach ($tcp in $tcpConnections) {
            $processName = (Get-Process -Id $tcp.OwningProcess -ErrorAction SilentlyContinue).Name
            $connections += [PSCustomObject]@{
                Type          = "TCP"
                LocalAddress  = $tcp.LocalAddress
                LocalPort     = $tcp.LocalPort
                RemoteAddress = $tcp.RemoteAddress
                RemotePort    = $tcp.RemotePort
                State         = $tcp.State
                ProcessId     = $tcp.OwningProcess
                ProcessName   = if ($processName) { $processName } else { "N/A" }
            }
        }
    }
}
catch {
    Write-Warning "Could not retrieve TCP connections: $($_.Exception.Message)"
}

# Get UDP Listeners (Endpoints)
try {
    Write-Host "Querying UDP listeners..."
    $udpListeners = Get-NetUDPEndpoint -ErrorAction Stop
    if ($udpListeners) {
        foreach ($udp in $udpListeners) {
            # UDP doesn't have a "RemoteAddress" or "State" in the same way TCP connections do for listeners
            # OwningProcess is not directly available on Get-NetUDPEndpoint, requires more work (e.g., netstat -ano parsing or API calls)
            # For simplicity, we'll note this limitation here.
            # A more advanced script might try to correlate PID from netstat output.
            $connections += [PSCustomObject]@{
                Type          = "UDP Listener"
                LocalAddress  = $udp.LocalAddress
                LocalPort     = $udp.LocalPort
                RemoteAddress = "N/A"
                RemotePort    = "N/A"
                State         = "Listening" # Implied for UDP endpoints
                ProcessId     = "N/A (Use netstat -ano for PID)" # Get-NetUDPEndpoint doesn't provide PID directly
                ProcessName   = "N/A"
            }
        }
    }
}
catch {
    Write-Warning "Could not retrieve UDP listeners: $($_.Exception.Message)"
}


if ($connections.Count -gt 0) {
    Write-Host "`n--- Network Connections Snapshot ---" -ForegroundColor Cyan
    $connections | Format-Table -AutoSize -Wrap
    
    if ($PSBoundParameters.ContainsKey('OutputCsvPath')) {
        try {
            Write-Host "`nSaving snapshot to CSV: $OutputCsvPath" -ForegroundColor Yellow
            $connections | Export-Csv -Path $OutputCsvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Write-Host "Successfully saved to $OutputCsvPath" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to save CSV to '$OutputCsvPath': $($_.Exception.Message)"
        }
    }
} else {
    Write-Host "`nNo active network connections or listeners found (or an error occurred)." -ForegroundColor Yellow
}

Write-Host "`nNetwork connections snapshot complete." -ForegroundColor Yellow
