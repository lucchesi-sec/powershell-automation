function Get-LowDiskSpace {
    [CmdletBinding()]
    param (
        [ValidateRange(1,99)] # Ensure threshold is between 1 and 99
        [int]$ThresholdPercent = 15
    )

    try {
        # Get fixed logical disks (DriveType 3)
        $disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop

        if (-not $disks) {
            Write-Warning "No fixed disks found on this system."
            return
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

        return $lowSpaceDisks
    }
    catch {
        Write-Error "An error occurred while checking disk space: $($_.Exception.Message)"
    }
}

function Get-ServiceStatus {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string[]]$ServiceNames
    )

    $serviceStatus = @()

    foreach ($serviceName in $ServiceNames) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction Stop
            
            $serviceStatus += [PSCustomObject]@{
                Name = $service.Name
                DisplayName = $service.DisplayName
                Status = $service.Status
            }
        }
        catch [Microsoft.PowerShell.Commands.ServiceCommandException] {
            # Handles cases where the service does not exist
            Write-Warning "Service '$serviceName' not found or an error occurred: $($_.Exception.Message)"
        }
        catch {
            # Handles other potential errors
            Write-Error "An unexpected error occurred while checking service '$serviceName': $($_.Exception.Message)"
        }
    }

    return $serviceStatus
}
