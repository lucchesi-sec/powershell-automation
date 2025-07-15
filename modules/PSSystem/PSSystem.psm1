function Get-SystemInfo {
    [CmdletBinding()]
    param ()

    try {
        # --- Collect all data points ---
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime
        $csInfo = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Manufacturer, Model, TotalPhysicalMemory, NumberOfLogicalProcessors
        $cpuInfo = Get-CimInstance -ClassName Win32_Processor | Select-Object Name, Manufacturer, MaxClockSpeed, NumberOfCores
        $diskInfo = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3} | Select-Object DeviceID, VolumeName, FileSystem, @{N="SizeGB";E={[math]::Round($_.Size / 1GB, 2)}}, @{N="FreeSpaceGB";E={[math]::Round($_.FreeSpace / 1GB, 2)}}
        $netAdapterInfo = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled} | Select-Object Description, IPAddress, IPSubnet, DefaultIPGateway, MACAddress, DNSServerSearchOrder
        $topProcesses = Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 | Select-Object Name, Id, @{N="CPU_Seconds";E={$_.CPU}}, @{N="Memory_MB";E={[math]::Round($_.WorkingSet64 / 1MB, 2)}}
        $runningServices = Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, DisplayName, Status

        # --- Assemble the final output object ---
        $systemReport = [PSCustomObject]@{
            ReportDate      = Get-Date
            OperatingSystem = $osInfo
            ComputerSystem  = $csInfo
            Processor       = $cpuInfo
            Disks           = $diskInfo
            Network         = $netAdapterInfo
            TopProcessesCPU = $topProcesses
            RunningServices = $runningServices
        }

        # Output the single, rich object to the pipeline
        return $systemReport
    }
    catch {
        Write-Error "An error occurred while gathering system information: $($_.Exception.Message)"
    }
}
