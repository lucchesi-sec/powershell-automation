<#
.SYNOPSIS
    Checks when the Windows system was last successfully updated.
.DESCRIPTION
    This script attempts to determine the last successful installation time
    of Windows Updates by checking relevant system information.
.EXAMPLE
    .\Check-LastPatchTime.ps1
    Displays the last successful Windows Update installation time.
.NOTES
    Author: Your Name
    Date: $(Get-Date)
    The accuracy can depend on Windows Update logging.
    Requires permissions to query WMI or registry for update information.
#>
param ()

Write-Host "Checking for the last Windows Update installation time..." -ForegroundColor Yellow

$lastPatchTime = $null
$methodUsed = "N/A"

# Method 1: Using Win32_QuickFixEngineering (shows installed hotfixes)
try {
    $hotfixes = Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction SilentlyContinue | Sort-Object -Property InstalledOn -Descending
    if ($hotfixes) {
        # Convert the string date from WMI to a DateTime object
        # WMI date format is yyyymmddHHMMSS.ffffff±UUU
        # We only need the yyyymmdd part for InstalledOn for QFE
        $latestHotfixDateStr = $hotfixes[0].InstalledOn
        if ($latestHotfixDateStr -match "(\d{4})(\d{2})(\d{2})") {
             $lastPatchTime = Get-Date "$($matches[1])-$($matches[2])-$($matches[3])"
        } else {
            # Fallback if InstalledOn is not in expected string format (less common for QFE)
            # Or if InstalledOn is already a CIM_DATETIME object (depends on PS version/CIM behavior)
            if ($hotfixes[0].InstalledOn -is [datetime]) {
                $lastPatchTime = $hotfixes[0].InstalledOn
            } elseif ($hotfixes[0].PSObject.Properties['InstalledOn'].Value -is [string] -and [datetime]::TryParse($hotfixes[0].PSObject.Properties['InstalledOn'].Value, [ref]$null)) {
                # Try direct parse if it's a parsable string
                $lastPatchTime = [datetime]$hotfixes[0].PSObject.Properties['InstalledOn'].Value
            }
        }
        $methodUsed = "Latest Hotfix (Win32_QuickFixEngineering)"
    }
}
catch {
    Write-Warning "Could not query Win32_QuickFixEngineering: $($_.Exception.Message)"
}

# Method 2: Checking Windows Update registry key (often more accurate for "last successful install cycle")
# This key might not exist on all systems or could be cleared.
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install"
$registryValueName = "LastSuccessTime"

if (Test-Path $registryPath) {
    try {
        $regLastSuccessTime = (Get-ItemProperty -Path $registryPath -Name $registryValueName -ErrorAction SilentlyContinue).$registryValueName
        if ($regLastSuccessTime -is [datetime]) {
            # If $lastPatchTime is already set from WMI, compare and take the latest
            if (-not $lastPatchTime -or $regLastSuccessTime -gt $lastPatchTime) {
                $lastPatchTime = $regLastSuccessTime
                $methodUsed = "Windows Update Registry (LastSuccessTime)"
            }
        }
    }
    catch {
        Write-Warning "Could not read Windows Update registry key '$registryValueName': $($_.Exception.Message)"
    }
}

if ($lastPatchTime) {
    Write-Host "`n--- Last Successful Update Time ---" -ForegroundColor Cyan
    Write-Host "Date: $($lastPatchTime.ToString('yyyy-MM-dd HH:mm:ss'))"
    Write-Host "Method: $methodUsed"
} else {
    Write-Host "`nCould not determine the last update time through available methods." -ForegroundColor Red
}

Write-Host "`nLast patch time check complete." -ForegroundColor Yellow
