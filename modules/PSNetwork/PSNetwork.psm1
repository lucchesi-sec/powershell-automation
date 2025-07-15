function Get-NetworkConnectionsSnapshot {
    [CmdletBinding()]
    param ()

    $connections = @()

    # Get TCP Connections
    try {
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

    return $connections
}
