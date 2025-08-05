function Test-AdminPrivileges {
    <#
    .SYNOPSIS
        Tests if the current session has administrative privileges.
    .DESCRIPTION
        Checks whether the current PowerShell session is running with administrative/elevated
        privileges. Works on both Windows and PowerShell Core across different platforms.
    .PARAMETER Quiet
        If specified, suppresses warning messages when not running as administrator.
    .EXAMPLE
        if (Test-AdminPrivileges) {
            # Perform administrative tasks
        }
    .EXAMPLE
        Test-AdminPrivileges -Quiet
        Returns $true or $false without displaying warnings.
    .OUTPUTS
        System.Boolean
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )

    try {
        # Check if running on Windows
        if ($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows) {
            # Windows platform check
            $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
            $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
            
            if (-not $isAdmin -and -not $Quiet) {
                Write-Warning "This session is not running with administrative privileges. Some operations may fail."
                Write-Warning "To run as administrator, right-click PowerShell and select 'Run as Administrator'."
            }
            
            return $isAdmin
        }
        elseif ($IsLinux -or $IsMacOS) {
            # Unix-based platform check (Linux/macOS)
            $userId = id -u
            $isRoot = $userId -eq 0
            
            if (-not $isRoot -and -not $Quiet) {
                Write-Warning "This session is not running as root. Some operations may fail."
                Write-Warning "To run as root, use 'sudo pwsh' or switch to root user."
            }
            
            return $isRoot
        }
        else {
            # Unknown platform, assume no admin privileges
            if (-not $Quiet) {
                Write-Warning "Unable to determine administrative privileges on this platform."
            }
            return $false
        }
    }
    catch {
        Write-Error "Failed to check administrative privileges: $_"
        return $false
    }
}