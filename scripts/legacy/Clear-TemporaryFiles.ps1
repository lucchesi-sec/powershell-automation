<#
.SYNOPSIS
    Clears temporary files from common locations.
.DESCRIPTION
    This script identifies and optionally deletes files from common temporary
    locations such as the user's TEMP folder and the system's TEMP folder.
    It can also target the Windows Update cache.
    By default, it runs in a "report-only" mode. Deletion requires explicit parameters.
.PARAMETER CleanUserTemp
    Switch to target the current user's TEMP folder ($env:TEMP).
.PARAMETER CleanSystemTemp
    Switch to target the system's TEMP folder ($env:windir\Temp).
.PARAMETER CleanWindowsUpdateCache
    Switch to target the Windows Update download cache (C:\Windows\SoftwareDistribution\Download).
    USE WITH CAUTION: Clearing this might impact pending updates or update history.
.PARAMETER OlderThanDays
    Specifies that only files older than this many days should be targeted. Defaults to 7 days.
    Set to 0 to target all files regardless of age.
.PARAMETER Delete
    Switch to actually delete the identified files.
    If not specified, the script will only report what would be deleted.
.PARAMETER Force
    Switch to suppress confirmation prompts when deleting. Use with -Delete.
.EXAMPLE
    .\Clear-TemporaryFiles.ps1 -CleanUserTemp -CleanSystemTemp
    Reports on files older than 7 days in user and system temp folders that would be deleted.
.EXAMPLE
    .\Clear-TemporaryFiles.ps1 -CleanUserTemp -OlderThanDays 30 -Delete -Force
    Deletes files older than 30 days from the user's TEMP folder without confirmation.
.EXAMPLE
    .\Clear-TemporaryFiles.ps1 -CleanWindowsUpdateCache -Delete -OlderThanDays 0 -Force
    Deletes ALL files from the Windows Update download cache without confirmation. (Use extreme caution!)
.NOTES
    Author: Your Name
    Date: $(Get-Date)
    WARNING: This script can delete files. Always test with report-only mode first.
    Ensure you understand the implications before using the -Delete parameter, especially with -CleanWindowsUpdateCache.
    Running with Administrator privileges is recommended for system-wide locations.
#>
param (
    [switch]$CleanUserTemp,
    [switch]$CleanSystemTemp,
    [switch]$CleanWindowsUpdateCache,

    [int]$OlderThanDays = 7,

    [switch]$Delete,
    [switch]$Force
)

Write-Host "Temporary File Cleanup Utility" -ForegroundColor Yellow
Write-Host "--------------------------------"
if (-not $Delete) {
    Write-Host "Running in REPORT-ONLY mode. No files will be deleted." -ForegroundColor Cyan
    Write-Host "Use the -Delete switch to enable file deletion." -ForegroundColor Cyan
}
if ($Delete -and -not $Force) {
    Write-Host "Deletion enabled. You MAY be prompted for confirmation for items." -ForegroundColor Magenta
    Write-Host "Use -Force (with -Delete) to suppress individual confirmations." -ForegroundColor Magenta
}
if ($Delete -and $Force) {
    Write-Host "Deletion enabled. Confirmation prompts will be SUPPRESSED." -ForegroundColor Red
}
Write-Host "Targeting files older than $OlderThanDays day(s)."
Write-Host "--------------------------------`n"


function Process-Path {
    param (
        [string]$PathToClean,
        [string]$Description
    )

    Write-Host "Processing: $Description (`"$PathToClean`")" -ForegroundColor White
    if (-not (Test-Path $PathToClean)) {
        Write-Warning "Path not found: $PathToClean"
        return
    }

    $cutoffDate = (Get-Date).AddDays(-$OlderThanDays)
    $itemsToDelete = @()
    $totalSize = 0

    # Get items (files and folders)
    # We get all items first, then filter. Deleting folders will also delete their contents.
    try {
        $items = Get-ChildItem -Path $PathToClean -Recurse -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning "Could not access path '$PathToClean' or list its contents fully: $($_.Exception.Message)"
        return
    }


    foreach ($item in $items) {
        # For OlderThanDays = 0, we target everything. Otherwise, check LastWriteTime.
        if (($OlderThanDays -eq 0) -or ($item.LastWriteTime -lt $cutoffDate)) {
            $itemsToDelete += $item
            try {
                # Calculate size. For folders, sum up file sizes.
                if ($item.PSIsContainer) {
                    $folderSize = (Get-ChildItem -Path $item.FullName -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                    $totalSize += $folderSize
                } else {
                    $totalSize += $item.Length
                }
            } catch { Write-Warning "Could not get size for $($item.FullName)"}
        }
    }
    
    $totalSizeMB = [math]::Round($totalSize / 1MB, 2)

    if ($itemsToDelete.Count -eq 0) {
        Write-Host "  No items found older than $OlderThanDays day(s) in $Description." -ForegroundColor Green
        return
    }

    Write-Host "  Found $($itemsToDelete.Count) items (files/folders) older than $OlderThanDays day(s), totaling approx. $($totalSizeMB) MB."
    
    if ($Delete) {
        Write-Host "  Attempting to delete..." -ForegroundColor Magenta
        $deletedCount = 0
        $errorCount = 0
        foreach ($item in $itemsToDelete) {
            try {
                if ($Force) {
                    Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction Stop
                    # Write-Verbose "Deleted: $($item.FullName)" # Enable if needed
                } else {
                    # -Confirm without -Force will prompt if $ConfirmPreference is not 'None'
                    Remove-Item -Path $item.FullName -Recurse -Confirm:$false -ErrorAction Stop 
                }
                $deletedCount++
            }
            catch {
                Write-Warning "    Failed to delete '$($item.FullName)': $($_.Exception.Message)"
                $errorCount++
            }
        }
        Write-Host "    Successfully deleted $deletedCount item(s)." -ForegroundColor Green
        if ($errorCount -gt 0) {
            Write-Host "    Failed to delete $errorCount item(s) (likely in use or access denied)." -ForegroundColor Red
        }
    } else {
        Write-Host "  (Report-Only) Items that would be targeted for deletion:"
        # $itemsToDelete | Select-Object -First 5 FullName, LastWriteTime, @{N="SizeKB";E={[math]::Round($_.Length/1KB,0)}} | Format-Table # Show a sample
        # For full report, can be very long:
        # $itemsToDelete | Select-Object FullName, LastWriteTime, @{N="SizeKB";E={[math]::Round($_.Length/1KB,0)}} | Format-List
        Write-Host "  Run with -Delete to remove these items."
    }
    Write-Host "" # Newline
}


if (-not ($CleanUserTemp -or $CleanSystemTemp -or $CleanWindowsUpdateCache)) {
    Write-Warning "No locations specified for cleanup. Use -CleanUserTemp, -CleanSystemTemp, or -CleanWindowsUpdateCache."
    exit 1
}

if ($CleanUserTemp) {
    Process-Path -PathToClean $env:TEMP -Description "User Temporary Files"
}

if ($CleanSystemTemp) {
    Process-Path -PathToClean "$env:windir\Temp" -Description "System Temporary Files"
}

if ($CleanWindowsUpdateCache) {
    Write-Warning "Processing Windows Update Cache (C:\Windows\SoftwareDistribution\Download). This can affect update history or pending updates. PROCEED WITH EXTREME CAUTION."
    Process-Path -PathToClean "C:\Windows\SoftwareDistribution\Download" -Description "Windows Update Download Cache"
}

Write-Host "Temporary file cleanup process complete." -ForegroundColor Yellow
