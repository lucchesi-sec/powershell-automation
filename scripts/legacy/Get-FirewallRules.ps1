<#
.SYNOPSIS
    Retrieves Windows Firewall rules with optional filtering.
.DESCRIPTION
    This script lists local Windows Defender Firewall rules and allows
    filtering by rule state (Enabled), traffic Direction (Inbound/Outbound),
    and Action (Allow/Block).  Results can be exported to CSV.
.PARAMETER EnabledOnly
    Switch.  When specified, only rules that are enabled will be returned.
.PARAMETER Direction
    Filters on the rule direction.  Accepts 'Inbound' or 'Outbound'.
.PARAMETER Action
    Filters on the rule action.  Accepts 'Allow' or 'Block'.
.PARAMETER OutputCsvPath
    Optional path to export the resulting rules to a CSV file.
.EXAMPLE
    .\Get-FirewallRules.ps1 -EnabledOnly -Direction Inbound
    Lists all enabled inbound firewall rules.
.EXAMPLE
    .\Get-FirewallRules.ps1 -Action Block -OutputCsvPath "C:\temp\BlockedRules.csv"
    Lists all firewall rules with an action of Block and saves them to a CSV file.
.NOTES
    Author: Your Name
    Date: $(Get-Date)
    Requires PowerShell 5.1+ and administrative privileges for full rule visibility.
#>
param (
    [switch]$EnabledOnly,
    [ValidateSet('Inbound', 'Outbound')]
    [string]$Direction,
    [ValidateSet('Allow', 'Block')]
    [string]$Action,
    [string]$OutputCsvPath
)

Write-Host "Retrieving Windows Firewall rules..." -ForegroundColor Yellow

try {
    $rules = Get-NetFirewallRule -ErrorAction Stop
}
catch {
    Write-Error "Failed to retrieve firewall rules: $($_.Exception.Message)"
    exit 1
}

# Apply filters
if ($EnabledOnly.IsPresent) {
    $rules = $rules | Where-Object { $_.Enabled -eq 'True' }
}
if ($PSBoundParameters.ContainsKey('Direction')) {
    $rules = $rules | Where-Object { $_.Direction -eq $Direction }
}
if ($PSBoundParameters.ContainsKey('Action')) {
    $rules = $rules | Where-Object { $_.Action -eq $Action }
}

if (-not $rules) {
    Write-Host "No firewall rules matched the specified criteria." -ForegroundColor Green
    exit 0
}

# Select additional properties via Get-NetFirewallPortFilter / Get-NetFirewallAddressFilter etc. where useful
$displayRules = foreach ($rule in $rules) {
    $portFilter     = Get-NetFirewallPortFilter     -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
    $addressFilter  = Get-NetFirewallAddressFilter  -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        Name        = $rule.DisplayName
        Direction   = $rule.Direction
        Action      = $rule.Action
        Enabled     = $rule.Enabled
        Protocol    = if ($portFilter.Protocol) { $portFilter.Protocol } else { 'Any' }
        LocalPort   = if ($portFilter.LocalPort) { $portFilter.LocalPort } else { 'Any' }
        RemotePort  = if ($portFilter.RemotePort) { $portFilter.RemotePort } else { 'Any' }
        LocalAddr   = if ($addressFilter.LocalAddress)  { $addressFilter.LocalAddress }  else { 'Any' }
        RemoteAddr  = if ($addressFilter.RemoteAddress) { $addressFilter.RemoteAddress } else { 'Any' }
        Profile     = $rule.Profile
    }
}

Write-Host "`n--- Firewall Rules ---" -ForegroundColor Cyan
$displayRules | Format-Table -AutoSize -Wrap

if ($PSBoundParameters.ContainsKey('OutputCsvPath')) {
    try {
        Write-Host "`nExporting rules to CSV: $OutputCsvPath" -ForegroundColor Yellow

        # Ensure the destination directory exists to avoid Export-Csv failure
        $csvDir = Split-Path -Path $OutputCsvPath -Parent
        if ($csvDir -and -not (Test-Path $csvDir)) {
            try {
                New-Item -ItemType Directory -Path $csvDir -Force | Out-Null
            }
            catch {
                throw "Unable to create directory '$csvDir' for CSV export: $($_.Exception.Message)"
            }
        }

        $displayRules | Export-Csv -Path $OutputCsvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host "Successfully saved to $OutputCsvPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to save CSV to '$OutputCsvPath': $($_.Exception.Message)"
    }
}

Write-Host "`nFirewall rule enumeration complete." -ForegroundColor Yellow
