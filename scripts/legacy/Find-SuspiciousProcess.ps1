<#
.SYNOPSIS
    Identifies potentially suspicious processes based on common indicators.
.DESCRIPTION
    This script retrieves all running processes and flags those that match
    certain criteria, such as running from temporary user directories or
    lacking company name and file description information.
.EXAMPLE
    .\Find-SuspiciousProcess.ps1
    Scans all running processes for suspicious indicators.
.EXAMPLE
    .\Find-SuspiciousProcess.ps1 -IncludeUnsigned
    Scans processes and includes a check for unsigned executables (can be slow).
.NOTES
    Author: Your Name
    Date: $(Get-Date)
    This script provides indicators and does not definitively confirm a process is malicious.
    Further investigation is always required.
    The -IncludeUnsigned switch can significantly slow down the script.
#>
param (
    [switch]$IncludeUnsigned
)

Write-Host "Scanning for potentially suspicious processes..." -ForegroundColor Yellow

$suspiciousProcesses = @()
$allProcesses = Get-Process -ErrorAction SilentlyContinue

# Define suspicious path patterns (customize as needed)
$tempPathPatterns = @(
    [regex]::Escape($env:TEMP) + ".*",
    [regex]::Escape($env:LOCALAPPDATA) + "\\Temp\\.*",
    [regex]::Escape($env:USERPROFILE) + "\\Downloads\\.*" # Executables running directly from Downloads
    # Add more patterns if needed, e.g., AppData\Roaming for specific scenarios
)

foreach ($process in $allProcesses) {
    $suspicionReasons = [System.Collections.Generic.List[string]]::new()
    $processInfo = $null # Initialize to avoid issues if Get-CimInstance fails

    try {
        # Attempt to get more detailed process info, including path
        # Using try-catch as Path property might not always be accessible
        $processInfo = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($process.Id)" | Select-Object ProcessId, Name, ExecutablePath, CommandLine, Description, CompanyName
    }
    catch {
        # Fallback to Get-Process if Get-CimInstance fails for path
        # Note: $process.Path is less reliable and might be empty for some processes
        if ($process.Path) {
             $processInfo = [PSCustomObject]@{
                ProcessId = $process.Id
                Name = $process.Name
                ExecutablePath = $process.Path
                CommandLine = $process.CommandLine # May not be available via Get-Process alone
                Description = $process.Description
                CompanyName = $process.Company
            }
        } else {
             $processInfo = [PSCustomObject]@{
                ProcessId = $process.Id
                Name = $process.Name
                ExecutablePath = "N/A (Access Denied or No Path)"
                CommandLine = $process.CommandLine
                Description = $process.Description
                CompanyName = $process.Company
            }
        }
    }
    
    if (-not $processInfo.ExecutablePath -or $processInfo.ExecutablePath -eq "N/A (Access Denied or No Path)") {
        # If path is still not found, it's harder to assess. Could be a system process or access issue.
        # For this script, we'll skip path checks if path is unavailable.
    } else {
        foreach ($pattern in $tempPathPatterns) {
            if ($processInfo.ExecutablePath -match $pattern) {
                $suspicionReasons.Add("Running from potentially temporary/user path: $($processInfo.ExecutablePath)")
                break # Found a path match, no need to check other path patterns
            }
        }
    }

    if (-not $processInfo.CompanyName -and -not $processInfo.Description) {
        $suspicionReasons.Add("Lacks Company Name and File Description")
    }

    if ($IncludeUnsigned.IsPresent -and $processInfo.ExecutablePath -ne "N/A (Access Denied or No Path)") {
        try {
            $signature = Get-AuthenticodeSignature -FilePath $processInfo.ExecutablePath -ErrorAction SilentlyContinue
            if ($signature.Status -ne "Valid") {
                $suspicionReasons.Add("Executable is not signed or signature is invalid (Status: $($signature.Status))")
            }
        }
        catch {
            # Write-Warning "Could not check signature for $($processInfo.ExecutablePath): $($_.Exception.Message)"
            $suspicionReasons.Add("Could not verify Authenticode signature (e.g. access denied, file locked)")
        }
    }

    if ($suspicionReasons.Count -gt 0) {
        $suspiciousProcesses += [PSCustomObject]@{
            ProcessId   = $process.Id
            Name        = $process.Name
            Path        = if ($processInfo.ExecutablePath) { $processInfo.ExecutablePath } else { "N/A" }
            CPU         = $process.CPU
            MemoryMB    = [math]::Round($process.WorkingSet64 / 1MB, 2)
            Reasons     = $suspicionReasons -join "; "
        }
    }
}

if ($suspiciousProcesses.Count -gt 0) {
    Write-Host "`n--- Potentially Suspicious Processes Found ---" -ForegroundColor Red
    $suspiciousProcesses | Format-Table -AutoSize -Wrap
} else {
    Write-Host "`nNo processes matching defined suspicious criteria found." -ForegroundColor Green
}

Write-Host "`nProcess scan complete." -ForegroundColor Yellow
