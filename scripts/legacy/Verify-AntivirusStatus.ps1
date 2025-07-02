<#
.SYNOPSIS
    Verifies the status of the installed Antivirus software.
.DESCRIPTION
    This script checks the status of Windows Defender Antivirus. If Windows Defender
    is not the active AV, it attempts to query WMI for third-party antivirus product information.
    It reports whether AV is enabled, real-time protection is active, and signature status.
.EXAMPLE
    .\Verify-AntivirusStatus.ps1
    Displays the status of the installed Antivirus.
.NOTES
    Author: Your Name
    Date: $(Get-Date)
    Requires Administrator privileges for full WMI access to SecurityCenter2 and Get-MpComputerStatus.
    Information for third-party AV products can vary.
#>
param ()

Write-Host "Verifying Antivirus Status..." -ForegroundColor Yellow

function Get-DefenderStatus {
    Write-Host "`n--- Windows Defender Status ---" -ForegroundColor Cyan
    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        if ($status) {
            [PSCustomObject]@{
                ProductName                 = "Windows Defender"
                AntispywareEnabled          = $status.AntispywareEnabled
                AntivirusEnabled            = $status.AntivirusEnabled
                RealTimeProtectionEnabled   = $status.RealTimeProtectionEnabled
                BehaviorMonitorEnabled      = $status.BehaviorMonitorEnabled
                IoavProtectionEnabled       = $status.IoavProtectionEnabled # On-access protection
                NISEnabled                  = $status.NISEnabled          # Network Inspection System
                SignatureVersion            = $status.AntivirusSignatureVersion
                SpywareSignatureVersion     = $status.AntispywareSignatureVersion
                LastSignatureUpdate         = $status.AntivirusSignatureLastUpdated
                LastFullScan                = $status.FullScanEndTime
                LastQuickScan               = $status.QuickScanEndTime
            } | Format-List
        } else {
            Write-Host "Could not retrieve Windows Defender status. It might be disabled or not installed." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Warning "Error retrieving Windows Defender status: $($_.Exception.Message). It might be disabled or superseded by a third-party AV."
    }
}

function Get-ThirdPartyAVStatus {
    Write-Host "`n--- Third-Party Antivirus Status (via WMI SecurityCenter2) ---" -ForegroundColor Cyan
    try {
        # Namespace for modern Windows versions (Vista and later)
        $avProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop
        
        if ($avProducts) {
            foreach ($av in $avProducts) {
                $productStateHex = "0x$($av.ProductState.ToString('X'))" # Display as hex for easier interpretation
                $productStateDecimal = $av.ProductState

                # Decode productState (common interpretations, may vary by AV vendor)
                # See: https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ms721358(v=vs.85)
                # And: https://stackoverflow.com/questions/29009830/what-are-the-possible-values-for-productstate-from-antivirusproduct-wmi-class
                # Bit 1 (0x0010) = Enabled
                # Bit 13 (0x2000) = Product up-to-date (signatures)
                # Example: 266240 (0x041000) -> Enabled, Not up-to-date
                # Example: 397312 (0x061000) -> Enabled, Up-to-date (often means real-time protection is on)
                # Example: 393216 (0x060000) -> Not enabled, Up-to-date (unlikely state)

                $isEnabled = ($productStateDecimal -band 0x0010) -ne 0 # Check if the 'enabled' bit is set
                $isUpToDate = ($productStateDecimal -band 0x2000) -ne 0 # Check if the 'up-to-date' bit is set (often implies RTP)

                [PSCustomObject]@{
                    DisplayName          = $av.DisplayName
                    ProductState_Hex     = $productStateHex
                    ProductState_Decimal = $productStateDecimal
                    IsEnabledGuess       = $isEnabled # Based on common interpretation
                    IsUpToDateGuess      = $isUpToDate # Based on common interpretation
                    PathToSignedProductExe = $av.PathToSignedProductExe
                    PathToSignedReportingExe = $av.PathToSignedReportingExe
                    Timestamp            = $av.Timestamp # When this WMI info was last updated
                } | Format-List
            }
        } else {
            Write-Host "No third-party Antivirus products found in WMI SecurityCenter2." -ForegroundColor Green
        }
    }
    catch {
        Write-Warning "Error querying WMI for third-party AV: $($_.Exception.Message). Ensure you have admin rights."
    }
}

# Check Defender first
Get-DefenderStatus

# Then check for third-party AV, as Defender might be disabled if another AV is active
Get-ThirdPartyAVStatus

Write-Host "`nAntivirus status check complete." -ForegroundColor Yellow
