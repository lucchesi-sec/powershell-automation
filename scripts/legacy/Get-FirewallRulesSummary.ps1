<#
.SYNOPSIS
    Provides a high-level summary of Windows Firewall rules and highlights potentially risky configurations.
.DESCRIPTION
    This script analyzes all Windows Firewall rules and provides a summary based on their status (Enabled/Disabled),
    direction (Inbound/Outbound), and action (Allow/Block). It also identifies and lists potentially
    risky rules, such as overly broad 'Allow' rules for inbound traffic.
.EXAMPLE
    .\Get-FirewallRulesSummary.ps1
    Displays the firewall rule summary and a list of potentially risky rules.
.EXAMPLE
    .\Get-FirewallRulesSummary.ps1 -RiskyOnly
    Displays only the list of potentially risky firewall rules.
.NOTES
    Author: Gemini
    Date: 25/06/2025
    Requires Administrator privileges for full rule visibility.
    This script is for informational purposes; "risky" rules may be necessary for legitimate software to function.
#>
param (
    [switch]$RiskyOnly
)

Write-Host "Analyzing Windows Firewall rules for summary and risks..." -ForegroundColor Yellow

try {
    $allRules = Get-NetFirewallRule -ErrorAction Stop
}
catch {
    Write-Error "Failed to retrieve firewall rules. Ensure you are running with Administrator privileges. Error: $($_.Exception.Message)"
    exit 1
}

if (-not $RiskyOnly) {
    Write-Host "`n--- Firewall Rules Summary ---" -ForegroundColor Cyan

    # Overall Count
    Write-Host "Total Rules Found: $($allRules.Count)"

    # Summary by Profile
    Write-Host "`n[Summary by Profile]" -ForegroundColor White
    $allRules | Group-Object -Property Profile | Select-Object Name, Count | Format-Table -AutoSize

    # Summary by Enabled/Disabled Status
    Write-Host "`n[Summary by Status]" -ForegroundColor White
    $allRules | Group-Object -Property Enabled | Select-Object @{N="Status";E={if($_.Name -eq 'True'){"Enabled"}else{"Disabled"}}}, Count | Format-Table -AutoSize

    # Detailed Summary Table
    Write-Host "`n[Detailed Breakdown by Direction and Action]" -ForegroundColor White
    $allRules | Group-Object -Property Direction, Action, Enabled |
        Select-Object @{N="Direction";E={$_.Values[0]}}, @{N="Action";E={$_.Values[1]}}, @{N="Enabled";E={$_.Values[2]}}, Count |
        Sort-Object Direction, Action |
        Format-Table -AutoSize
}

# --- Risky Rule Analysis ---
Write-Host "`n--- Potentially Risky Firewall Rules ---" -ForegroundColor Yellow
Write-Host "Identifying rules that are broad, permissive, and might warrant review." -ForegroundColor Gray

$riskyRules = @()

foreach ($rule in $allRules) {
    $riskReasons = [System.Collections.Generic.List[string]]::new()

    # Criteria for "risky":
    # 1. Inbound 'Allow' rule that is enabled.
    # 2. Applies to Public or Private profile.
    # 3. Has a broad port or address scope.

    if ($rule.Direction -eq 'Inbound' -and $rule.Action -eq 'Allow' -and $rule.Enabled -eq 'True') {
        # Check for broad profiles
        if ($rule.Profile -match 'Public' -or $rule.Profile -match 'Private') {
            $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
            $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue

            if ($portFilter.Protocol -eq 'Any') {
                $riskReasons.Add("Allows ANY protocol.")
            }
            if ($portFilter.LocalPort -eq 'Any') {
                $riskReasons.Add("Applies to ANY local port.")
            }
            if ($addressFilter.RemoteAddress -eq 'Any') {
                $riskReasons.Add("Allows connections from ANY remote address.")
            }
        }
        # 4. Rule is for a program that allows edge traversal (can bypass NATs)
        $appFilter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
        if ($appFilter.EdgeTraversalPolicy -eq 'Allow') {
             $riskReasons.Add("Edge traversal is allowed.")
        }
    }

    # 5. Disabled rules that allow traffic could be a risk if enabled accidentally
    if ($rule.Action -eq 'Allow' -and $rule.Enabled -eq 'False') {
        $riskReasons.Add("Disabled 'Allow' rule. Could be a risk if enabled.")
    }


    if ($riskReasons.Count -gt 0) {
        $riskyRules += [PSCustomObject]@{
            Name        = $rule.DisplayName
            Direction   = $rule.Direction
            Action      = $rule.Action
            Enabled     = $rule.Enabled
            Profile     = $rule.Profile
            Reason      = $riskReasons -join " "
        }
    }
}

if ($riskyRules.Count -gt 0) {
    Write-Host "`nFound $($riskyRules.Count) potentially risky rules:" -ForegroundColor Red
    $riskyRules | Format-Table -AutoSize -Wrap
} else {
    Write-Host "`nNo rules matching the defined 'risky' criteria were found." -ForegroundColor Green
}

Write-Host "`nFirewall rule analysis complete." -ForegroundColor Yellow