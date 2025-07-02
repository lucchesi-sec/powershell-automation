<#
.SYNOPSIS
    Monitors the status of specified Windows services.
.DESCRIPTION
    This script takes an array of service names as input and checks
    whether each service is running or stopped. It outputs the status for each service.
.PARAMETER ServiceNames
    An array of strings, where each string is the name of a Windows service
    to monitor (e.g., "WinRM", "Spooler").
.EXAMPLE
    .\Monitor-CriticalServices.ps1 -ServiceNames "WinRM", "Spooler", "BITS"
    Checks the status of the WinRM, Spooler, and BITS services.
.EXAMPLE
    $myServices = "Schedule", "Themes"
    .\Monitor-CriticalServices.ps1 -ServiceNames $myServices
    Checks the status of the services stored in the $myServices variable.
.NOTES
    Author: Your Name
    Date: $(Get-Date)
    Ensure the service names provided are correct.
#>
param (
    [Parameter(Mandatory=$true)]
    [string[]]$ServiceNames
)

Write-Host "Monitoring Critical Services..." -ForegroundColor Yellow
Write-Host "---------------------------------"

foreach ($serviceName in $ServiceNames) {
    try {
        $service = Get-Service -Name $serviceName -ErrorAction Stop
        
        if ($service.Status -eq "Running") {
            Write-Host "$($service.DisplayName) ($($service.Name)): Running" -ForegroundColor Green
        } else {
            Write-Host "$($service.DisplayName) ($($service.Name)): $($service.Status)" -ForegroundColor Red
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

Write-Host "---------------------------------"
Write-Host "Service monitoring complete." -ForegroundColor Yellow
