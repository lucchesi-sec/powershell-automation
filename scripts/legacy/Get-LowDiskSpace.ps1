<#
.SYNOPSIS
    Checks for local fixed disks with low free space.
.DESCRIPTION
    This script queries all local fixed disks (hard drives, SSDs) and
    reports any that have free space below a specified percentage threshold.
.PARAMETER ThresholdPercent
    The percentage of free space below which a disk will be reported as low.
    Defaults to 15 percent.
.EXAMPLE
    .\Get-LowDiskSpace.ps1
    Checks for disks with less than 15% free space.
.EXAMPLE
    .\Get-LowDiskSpace.ps1 -ThresholdPercent 10
    Checks for disks with less than 10% free space.
.NOTES
    Author: Your Name
    Date: $(Get-Date)
    Requires permissions to query WMI/CIM for disk information.
#>
param (
    [ValidateRange(1,99)] # Ensure threshold is between 1 and 99
    [int]$ThresholdPercent = 15
)

Write-Host "Checking for disks with less than $ThresholdPercent% free space..." -ForegroundColor Yellow

try {
    # Get fixed logical disks (DriveType 3)
    $disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop

    if (-not $disks) {
        Write-Warning "No fixed disks found on this system."
        exit 0
    }

    $lowSpaceDisks = @()

    foreach ($disk in $disks) {
        if ($disk.Size -gt 0) { # Avoid division by zero for unformatted/problematic drives
            $percentFree = ($disk.FreeSpace / $disk.Size) * 100
            
            if ($percentFree -lt $ThresholdPercent) {
                $lowSpaceDisks += [PSCustomObject]@{
                    DeviceID      = $disk.DeviceID
                    VolumeName    = if ($disk.VolumeName) { $disk.VolumeName } else { "N/A" }
                    SizeGB        = [math]::Round($disk.Size / 1GB, 2)
                    FreeSpaceGB   = [math]::Round($disk.FreeSpace / 1GB, 2)
                    PercentFree   = [math]::Round($percentFree, 2)
                    FileSystem    = $disk.FileSystem
                }
            }
        }
    }

    if ($lowSpaceDisks.Count -gt 0) {
        Write-Host "`n--- Disks with Low Free Space (Less than $ThresholdPercent% free) ---" -ForegroundColor Red
        $lowSpaceDisks | Format-Table -AutoSize
    } else {
        Write-Host "`nNo disks found with less than $ThresholdPercent% free space." -ForegroundColor Green
    }
}
catch {
    Write-Error "An error occurred while checking disk space: $($_.Exception.Message)"
}

Write-Host "`nDisk space check complete." -ForegroundColor Yellow
