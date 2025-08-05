<#
.SYNOPSIS
    Automated disk space cleanup script for Windows systems.

.DESCRIPTION
    This script performs comprehensive disk cleanup operations including:
    - Temporary files cleanup
    - Log file rotation and cleanup
    - Recycle bin emptying
    - Windows update cleanup
    - IIS log cleanup (if applicable)
    - Event log archival

.PARAMETER DriveLetter
    Target drive letter to clean (default: C)

.PARAMETER LogRetentionDays
    Number of days to retain log files (default: 30)

.PARAMETER WhatIf
    Show what would be cleaned without actually performing cleanup

.EXAMPLE
    .\Clear-DiskSpace.ps1
    Performs cleanup on C: drive with default settings

.EXAMPLE
    .\Clear-DiskSpace.ps1 -DriveLetter D -LogRetentionDays 14
    Cleans D: drive and retains logs for 14 days

.NOTES
    Author: PowerShell Automation Project
    Requires: Administrator privileges for full functionality
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[A-Za-z]$')]
    [string]$DriveLetter = "C",
    
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 365)]
    [int]$LogRetentionDays = 30,
    
    [Parameter(Mandatory = $false)]
    [switch]$WhatIf
)

# Import required modules

if (Test-Path $modulePath) {
    Import-Module $modulePath -Force
} else {
    # Fall back to installed module
    Import-Module PSAdminCore -Force -ErrorAction Stop
}

# Initialize variables
$ErrorActionPreference = "Continue"
$VerbosePreference = "Continue"
$TotalSpaceFreed = 0
$CleanupResults = @()

function Write-CleanupLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage
    
    # Log to file if not in WhatIf mode
    if (-not $WhatIf) {
        $logFile = "$env:TEMP\DiskCleanup_$(Get-Date -Format 'yyyyMMdd').log"
        Add-Content -Path $logFile -Value $logMessage
    }
}

function Get-DirectorySize {
    param([string]$Path)
    
    if (Test-Path $Path) {
        try {
            $size = (Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue | 
                    Measure-Object -Property Length -Sum).Sum
            return [math]::Round($size / 1MB, 2)
        }
        catch {
            return 0
        }
    }
    return 0
}

function Clear-TemporaryFiles {
    Write-CleanupLog "Starting temporary files cleanup..."
    
    $tempPaths = @(
        "$env:TEMP",
        "$env:WINDIR\Temp",
        "$env:LOCALAPPDATA\Temp"
    )
    
    foreach ($tempPath in $tempPaths) {
        if (Test-Path $tempPath) {
            $sizeBefore = Get-DirectorySize -Path $tempPath
            Write-CleanupLog "Cleaning: $tempPath (Current size: $sizeBefore MB)"
            
            if ($PSCmdlet.ShouldProcess($tempPath, "Clear temporary files")) {
                try {
                    Get-ChildItem -Path $tempPath -Recurse -Force -ErrorAction SilentlyContinue |
                        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-1) } |
                        Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                    
                    $sizeAfter = Get-DirectorySize -Path $tempPath
                    $freedSpace = $sizeBefore - $sizeAfter
                    $TotalSpaceFreed += $freedSpace
                    
                    $CleanupResults += [PSCustomObject]@{
                        Location = $tempPath
                        SpaceFreed = "$freedSpace MB"
                        Status = "Success"
                    }
                    
                    Write-CleanupLog "Freed $freedSpace MB from $tempPath"
                }
                catch {
                    Write-CleanupLog "Error cleaning $tempPath`: $($_.Exception.Message)" -Level "ERROR"
                    $CleanupResults += [PSCustomObject]@{
                        Location = $tempPath
                        SpaceFreed = "0 MB"
                        Status = "Error: $($_.Exception.Message)"
                    }
                }
            }
        }
    }
}

function Clear-RecycleBin {
    Write-CleanupLog "Emptying Recycle Bin..."
    
    if ($PSCmdlet.ShouldProcess("Recycle Bin", "Empty")) {
        try {
            $recycleBin = (New-Object -ComObject Shell.Application).Namespace(10)
            $recycledItems = $recycleBin.Items()
            $recycleSize = ($recycledItems | ForEach-Object { $_.Size } | Measure-Object -Sum).Sum
            $recycleSize = [math]::Round($recycleSize / 1MB, 2)
            
            # Empty recycle bin
            Clear-RecycleBin -Force -ErrorAction SilentlyContinue
            
            $TotalSpaceFreed += $recycleSize
            $CleanupResults += [PSCustomObject]@{
                Location = "Recycle Bin"
                SpaceFreed = "$recycleSize MB"
                Status = "Success"
            }
            
            Write-CleanupLog "Freed $recycleSize MB from Recycle Bin"
        }
        catch {
            Write-CleanupLog "Error emptying Recycle Bin: $($_.Exception.Message)" -Level "ERROR"
            $CleanupResults += [PSCustomObject]@{
                Location = "Recycle Bin"
                SpaceFreed = "0 MB"
                Status = "Error: $($_.Exception.Message)"
            }
        }
    }
}

function Clear-WindowsUpdateFiles {
    Write-CleanupLog "Cleaning Windows Update files..."
    
    $updatePaths = @(
        "$env:WINDIR\SoftwareDistribution\Download",
        "$env:WINDIR\System32\catroot2"
    )
    
    foreach ($updatePath in $updatePaths) {
        if (Test-Path $updatePath) {
            $sizeBefore = Get-DirectorySize -Path $updatePath
            Write-CleanupLog "Cleaning: $updatePath (Current size: $sizeBefore MB)"
            
            if ($PSCmdlet.ShouldProcess($updatePath, "Clear Windows Update files")) {
                try {
                    # Stop Windows Update service temporarily
                    Stop-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue
                    
                    Get-ChildItem -Path $updatePath -Recurse -Force -ErrorAction SilentlyContinue |
                        Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                    
                    # Restart Windows Update service
                    Start-Service -Name "wuauserv" -ErrorAction SilentlyContinue
                    
                    $sizeAfter = Get-DirectorySize -Path $updatePath
                    $freedSpace = $sizeBefore - $sizeAfter
                    $TotalSpaceFreed += $freedSpace
                    
                    $CleanupResults += [PSCustomObject]@{
                        Location = $updatePath
                        SpaceFreed = "$freedSpace MB"
                        Status = "Success"
                    }
                    
                    Write-CleanupLog "Freed $freedSpace MB from $updatePath"
                }
                catch {
                    Write-CleanupLog "Error cleaning $updatePath`: $($_.Exception.Message)" -Level "ERROR"
                    $CleanupResults += [PSCustomObject]@{
                        Location = $updatePath
                        SpaceFreed = "0 MB"
                        Status = "Error: $($_.Exception.Message)"
                    }
                }
            }
        }
    }
}

function Clear-LogFiles {
    Write-CleanupLog "Cleaning old log files..."
    
    $logPaths = @(
        "$env:WINDIR\Logs",
        "$env:WINDIR\System32\LogFiles",
        "$env:ProgramData\Microsoft\Windows\WER\ReportQueue"
    )
    
    # Add IIS logs if IIS is installed
    if (Get-Service -Name "W3SVC" -ErrorAction SilentlyContinue) {
        $logPaths += "$env:SystemDrive\inetpub\logs\LogFiles"
    }
    
    $cutoffDate = (Get-Date).AddDays(-$LogRetentionDays)
    
    foreach ($logPath in $logPaths) {
        if (Test-Path $logPath) {
            $sizeBefore = Get-DirectorySize -Path $logPath
            Write-CleanupLog "Cleaning logs older than $LogRetentionDays days in: $logPath"
            
            if ($PSCmdlet.ShouldProcess($logPath, "Clear old log files")) {
                try {
                    Get-ChildItem -Path $logPath -Recurse -File -ErrorAction SilentlyContinue |
                        Where-Object { $_.LastWriteTime -lt $cutoffDate -and $_.Extension -match '\.(log|txt)$' } |
                        Remove-Item -Force -ErrorAction SilentlyContinue
                    
                    $sizeAfter = Get-DirectorySize -Path $logPath
                    $freedSpace = $sizeBefore - $sizeAfter
                    $TotalSpaceFreed += $freedSpace
                    
                    $CleanupResults += [PSCustomObject]@{
                        Location = $logPath
                        SpaceFreed = "$freedSpace MB"
                        Status = "Success"
                    }
                    
                    Write-CleanupLog "Freed $freedSpace MB from $logPath"
                }
                catch {
                    Write-CleanupLog "Error cleaning $logPath`: $($_.Exception.Message)" -Level "ERROR"
                    $CleanupResults += [PSCustomObject]@{
                        Location = $logPath
                        SpaceFreed = "0 MB"
                        Status = "Error: $($_.Exception.Message)"
                    }
                }
            }
        }
    }
}

function Archive-EventLogs {
    Write-CleanupLog "Archiving large event logs..."
    
    if ($PSCmdlet.ShouldProcess("Event Logs", "Archive large logs")) {
        try {
            $eventLogs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
                Where-Object { $_.RecordCount -gt 10000 -and $_.LogName -notmatch 'Security|System|Application' }
            
            foreach ($log in $eventLogs) {
                try {
                    $archivePath = "$env:TEMP\EventLogArchive_$($log.LogName -replace '[\\/:*?"<>|]', '_')_$(Get-Date -Format 'yyyyMMdd').evtx"
                    wevtutil.exe epl $log.LogName $archivePath
                    wevtutil.exe cl $log.LogName
                    
                    Write-CleanupLog "Archived and cleared event log: $($log.LogName)"
                }
                catch {
                    Write-CleanupLog "Error archiving $($log.LogName): $($_.Exception.Message)" -Level "ERROR"
                }
            }
        }
        catch {
            Write-CleanupLog "Error during event log archival: $($_.Exception.Message)" -Level "ERROR"
        }
    }
}

# Main execution
Write-CleanupLog "=== Starting Disk Cleanup Process ==="
Write-CleanupLog "Target Drive: $DriveLetter"
Write-CleanupLog "Log Retention: $LogRetentionDays days"
Write-CleanupLog "WhatIf Mode: $WhatIf"

# Get initial disk space
$initialSpace = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='${DriveLetter}:'"
$initialFreeSpace = [math]::Round($initialSpace.FreeSpace / 1GB, 2)

Write-CleanupLog "Initial free space on ${DriveLetter}: $initialFreeSpace GB"

# Perform cleanup operations
Clear-TemporaryFiles
Clear-RecycleBin
Clear-WindowsUpdateFiles
Clear-LogFiles
Archive-EventLogs

# Get final disk space
$finalSpace = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='${DriveLetter}:'"
$finalFreeSpace = [math]::Round($finalSpace.FreeSpace / 1GB, 2)
$totalFreed = [math]::Round($TotalSpaceFreed / 1024, 2)

Write-CleanupLog "=== Cleanup Complete ==="
Write-CleanupLog "Final free space on ${DriveLetter}: $finalFreeSpace GB"
Write-CleanupLog "Total space freed: $totalFreed GB"

# Display results table
Write-Host "`n=== Cleanup Results ===" -ForegroundColor Green
$CleanupResults | Format-Table -AutoSize

# Return summary object
return [PSCustomObject]@{
    DriveLetter = $DriveLetter
    InitialFreeSpace = "$initialFreeSpace GB"
    FinalFreeSpace = "$finalFreeSpace GB"
    TotalSpaceFreed = "$totalFreed GB"
    CleanupResults = $CleanupResults
}


