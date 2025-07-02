<#
.SYNOPSIS
    Gathers comprehensive system information and returns it as a single PowerShell object.
.DESCRIPTION
    This script collects various details about the local system, including OS version,
    hardware, network configuration, and top processes, and outputs them as a structured
    PSCustomObject. This allows the output to be easily piped to other cmdlets like
    ConvertTo-Json, Export-Csv, or Format-List.
.EXAMPLE
    .\Get-SystemInfo.ps1
    Outputs a rich object containing all system information, which PowerShell will display
    using default formatting.
.EXAMPLE
    .\Get-SystemInfo.ps1 | Format-List
    Displays all collected system information in a detailed list format.
.EXAMPLE
    .\Get-SystemInfo.ps1 | ConvertTo-Json -Depth 3
    Converts the collected system information into a JSON string.
.EXAMPLE
    (.\Get-SystemInfo.ps1).Disks | Where-Object { $_.FreeSpaceGB -lt 10 }
    Retrieves just the disk information and filters for disks with less than 10 GB of free space.
.NOTES
    Author: Gemini
    Date: 25/06/2025
    Refactored to output a single PSCustomObject for better pipeline integration and usability.
#>
param ()

Write-Host "Gathering comprehensive system information..." -ForegroundColor Yellow

try {
    # --- Collect all data points ---
    Write-Verbose "Collecting Operating System Information..."
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime

    Write-Verbose "Collecting Computer System Information..."
    $csInfo = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Manufacturer, Model, TotalPhysicalMemory, NumberOfLogicalProcessors

    Write-Verbose "Collecting Processor Information..."
    $cpuInfo = Get-CimInstance -ClassName Win32_Processor | Select-Object Name, Manufacturer, MaxClockSpeed, NumberOfCores

    Write-Verbose "Collecting Disk Information..."
    $diskInfo = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3} | Select-Object DeviceID, VolumeName, FileSystem, @{N="SizeGB";E={[math]::Round($_.Size / 1GB, 2)}}, @{N="FreeSpaceGB";E={[math]::Round($_.FreeSpace / 1GB, 2)}}

    Write-Verbose "Collecting Network Adapter Configuration..."
    $netAdapterInfo = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled} | Select-Object Description, IPAddress, IPSubnet, DefaultIPGateway, MACAddress, DNSServerSearchOrder

    Write-Verbose "Collecting Top 10 Processes by CPU..."
    $topProcesses = Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 | Select-Object Name, Id, @{N="CPU_Seconds";E={$_.CPU}}, @{N="Memory_MB";E={[math]::Round($_.WorkingSet64 / 1MB, 2)}}

    Write-Verbose "Collecting Running Services..."
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
    Write-Output $systemReport

    Write-Host "`nSystem information gathering complete." -ForegroundColor Green
    Write-Host "The script has returned a PowerShell object. Pipe it to Format-List, ConvertTo-Json, etc. to view." -ForegroundColor Gray

}
catch {
    Write-Error "An error occurred while gathering system information: $($_.Exception.Message)"
}
