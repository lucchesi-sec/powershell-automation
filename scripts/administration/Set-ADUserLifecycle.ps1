<#
.SYNOPSIS
    Manages the complete Active Directory user lifecycle including onboarding, modification, and offboarding.
.DESCRIPTION
    This script provides comprehensive user lifecycle management for Active Directory environments.
    It supports user onboarding, profile updates, role changes, and secure offboarding procedures.
    Includes backup and restoration capabilities for user attributes and group memberships.
.PARAMETER Username
    The username (SamAccountName) of the user to manage.
.PARAMETER Action
    The lifecycle action to perform: Onboard, Update, ChangeRole, Disable, Enable, or Offboard.
.PARAMETER NewRole
    For ChangeRole action: new role/title for the user.
.PARAMETER NewDepartment
    For role changes: new department assignment.
.PARAMETER NewManager
    For role changes: new manager assignment.
.PARAMETER BackupPath
    Directory to store user backup information during offboarding.
.PARAMETER RetentionDays
    Number of days to retain disabled user accounts before final removal.
.PARAMETER NotifyManagers
    If specified, sends notifications to managers about lifecycle changes.
.EXAMPLE
    .\Set-ADUserLifecycle.ps1 -Username "jdoe" -Action "Disable" -BackupPath "C:\UserBackups"
.EXAMPLE
    .\Set-ADUserLifecycle.ps1 -Username "jsmith" -Action "ChangeRole" -NewRole "Senior Developer" -NewDepartment "Engineering"
.NOTES
    Author: System Administrator
    Requires: ActiveDirectory module, PSAdminCore module
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Username,
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Onboard", "Update", "ChangeRole", "Disable", "Enable", "Offboard")]
    [string]$Action,
    
    [Parameter(Mandatory = $false)]
    [string]$NewRole,
    
    [Parameter(Mandatory = $false)]
    [string]$NewDepartment,
    
    [Parameter(Mandatory = $false)]
    [string]$NewManager,
    
    [Parameter(Mandatory = $false)]
    [string]$BackupPath = "$env:TEMP\UserBackups",
    
    [Parameter(Mandatory = $false)]
    [int]$RetentionDays = 90,
    
    [Parameter(Mandatory = $false)]
    [switch]$NotifyManagers
)

# Import required modules

if (Test-Path $modulePath) {
    Import-Module $modulePath -Force
} else {
    # Fall back to installed module
    Import-Module PSAdminCore -Force -ErrorAction Stop
}

} else {
    # Fall back to installed module
    Import-Module PSAdminCore -Force -ErrorAction Stop
}

# Check administrative privileges
if (-not (Test-AdminPrivileges)) {
    Write-AdminLog -Message "This script requires administrative privileges" -Level "Error"
    exit 1
}

Write-AdminLog -Message "Starting user lifecycle management for: $Username (Action: $Action)" -Level "Info"

try {
    # Get user object
    $user = Get-ADUser -Identity $Username -Properties * -ErrorAction Stop
    Write-AdminLog -Message "Found user: $($user.DisplayName)" -Level "Info"
    
    # Create backup directory if needed
    if (-not (Test-Path $BackupPath)) {
        New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
    }
    
    $result = [PSCustomObject]@{
        Username = $Username
        Action = $Action
        Status = "Unknown"
        PreviousState = @{}
        NewState = @{}
        BackupFile = $null
        Timestamp = Get-Date
        Changes = @()
    }
    
    switch ($Action) {
        "Onboard" {
            Write-AdminLog -Message "Processing onboarding for: $Username" -Level "Info"
            
            # Enable account if disabled
            if (-not $user.Enabled) {
                Enable-ADAccount -Identity $Username
                $result.Changes += "Account enabled"
                Write-AdminLog -Message "Enabled account for: $Username" -Level "Success"
            }
            
            # Set password change required
            Set-ADUser -Identity $Username -ChangePasswordAtLogon $true
            $result.Changes += "Password change required at next logon"
            
            # Add to default groups based on department
            $departmentGroups = @{
                "IT" = @("Domain Users", "IT-Department", "VPN-Users")
                "HR" = @("Domain Users", "HR-Department", "Confidential-Access")
                "Finance" = @("Domain Users", "Finance-Department", "Financial-Systems")
                "Sales" = @("Domain Users", "Sales-Department", "CRM-Users")
                "Marketing" = @("Domain Users", "Marketing-Department", "Marketing-Tools")
            }
            
            if ($departmentGroups.ContainsKey($user.Department)) {
                foreach ($group in $departmentGroups[$user.Department]) {
                    try {
                        Add-ADGroupMember -Identity $group -Members $Username -ErrorAction SilentlyContinue
                        $result.Changes += "Added to group: $group"
                        Write-AdminLog -Message "Added $Username to group: $group" -Level "Success"
                    } catch {
                        Write-AdminLog -Message "Could not add to group $group`: $($_.Exception.Message)" -Level "Warning"
                    }
                }
            }
            
            $result.Status = "Onboarded"
        }
        
        "Update" {
            Write-AdminLog -Message "Processing profile update for: $Username" -Level "Info"
            
            $result.PreviousState = @{
                Title = $user.Title
                Department = $user.Department
                Manager = $user.Manager
                Description = $user.Description
            }
            
            # Update fields if provided
            $updateParams = @{}
            if ($NewRole) { $updateParams.Title = $NewRole }
            if ($NewDepartment) { $updateParams.Department = $NewDepartment }
            if ($NewManager) { 
                $managerObj = Get-ADUser -Filter "SamAccountName -eq '$NewManager'" -ErrorAction SilentlyContinue
                if ($managerObj) {
                    $updateParams.Manager = $managerObj.DistinguishedName
                }
            }
            
            if ($updateParams.Count -gt 0) {
                Set-ADUser -Identity $Username @updateParams
                $result.NewState = $updateParams
                $result.Changes += "Profile updated: $($updateParams.Keys -join ', ')"
                Write-AdminLog -Message "Updated profile for: $Username" -Level "Success"
            }
            
            $result.Status = "Updated"
        }
        
        "ChangeRole" {
            Write-AdminLog -Message "Processing role change for: $Username" -Level "Info"
            
            # Backup current group memberships
            $currentGroups = Get-ADPrincipalGroupMembership -Identity $Username | Select-Object -ExpandProperty Name
            $backupFile = "$BackupPath\$Username-groups-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
            $currentGroups | ConvertTo-Json | Out-File -FilePath $backupFile
            $result.BackupFile = $backupFile
            
            # Remove from role-specific groups
            $roleGroups = $currentGroups | Where-Object { $_ -like "*-Role-*" -or $_ -like "*-Department*" -or $_ -like "*-Team*" }
            foreach ($group in $roleGroups) {
                try {
                    Remove-ADGroupMember -Identity $group -Members $Username -Confirm:$false
                    $result.Changes += "Removed from group: $group"
                    Write-AdminLog -Message "Removed $Username from group: $group" -Level "Info"
                } catch {
                    Write-AdminLog -Message "Could not remove from group $group`: $($_.Exception.Message)" -Level "Warning"
                }
            }
            
            # Update role information
            $updateParams = @{}
            if ($NewRole) { $updateParams.Title = $NewRole }
            if ($NewDepartment) { $updateParams.Department = $NewDepartment }
            if ($NewManager) { 
                $managerObj = Get-ADUser -Filter "SamAccountName -eq '$NewManager'" -ErrorAction SilentlyContinue
                if ($managerObj) {
                    $updateParams.Manager = $managerObj.DistinguishedName
                }
            }
            
            Set-ADUser -Identity $Username @updateParams
            $result.Changes += "Role changed to: $NewRole"
            
            $result.Status = "Role Changed"
        }
        
        "Disable" {
            Write-AdminLog -Message "Processing account disable for: $Username" -Level "Info"
            
            # Backup user information
            $backupFile = "$BackupPath\$Username-backup-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
            $backupData = @{
                User = $user | Select-Object *
                Groups = Get-ADPrincipalGroupMembership -Identity $Username | Select-Object -ExpandProperty Name
                DirectReports = Get-ADUser -Filter "Manager -eq '$($user.DistinguishedName)'" | Select-Object SamAccountName, DisplayName
                DisabledDate = Get-Date
                RetentionUntil = (Get-Date).AddDays($RetentionDays)
            }
            $backupData | ConvertTo-Json -Depth 3 | Out-File -FilePath $backupFile
            $result.BackupFile = $backupFile
            
            # Disable account
            Disable-ADAccount -Identity $Username
            
            # Set description with disable date
            $disableDescription = "DISABLED $(Get-Date -Format 'yyyy-MM-dd') - $($user.Description)"
            Set-ADUser -Identity $Username -Description $disableDescription
            
            # Move to disabled OU if it exists
            $disabledOU = "OU=Disabled Users,$(Get-ADDomain | Select-Object -ExpandProperty DistinguishedName)"
            if (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$disabledOU'" -ErrorAction SilentlyContinue) {
                Move-ADObject -Identity $user.DistinguishedName -TargetPath $disabledOU
                $result.Changes += "Moved to Disabled Users OU"
            }
            
            $result.Status = "Disabled"
            $result.Changes += "Account disabled", "Information backed up"
            Write-AdminLog -Message "Disabled account: $Username" -Level "Success"
        }
        
        "Enable" {
            Write-AdminLog -Message "Processing account enable for: $Username" -Level "Info"
            
            # Enable account
            Enable-ADAccount -Identity $Username
            
            # Remove disabled description
            $newDescription = $user.Description -replace "DISABLED \d{4}-\d{2}-\d{2} - ", ""
            Set-ADUser -Identity $Username -Description $newDescription
            
            # Require password change
            Set-ADUser -Identity $Username -ChangePasswordAtLogon $true
            
            $result.Status = "Enabled"
            $result.Changes += "Account enabled", "Password change required"
            Write-AdminLog -Message "Enabled account: $Username" -Level "Success"
        }
        
        "Offboard" {
            Write-AdminLog -Message "Processing complete offboarding for: $Username" -Level "Info"
            
            # Create comprehensive backup
            $backupFile = "$BackupPath\$Username-offboard-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
            $backupData = @{
                User = $user | Select-Object *
                Groups = Get-ADPrincipalGroupMembership -Identity $Username | Select-Object *
                DirectReports = Get-ADUser -Filter "Manager -eq '$($user.DistinguishedName)'" | Select-Object *
                OffboardDate = Get-Date
                OffboardedBy = $env:USERNAME
            }
            $backupData | ConvertTo-Json -Depth 3 | Out-File -FilePath $backupFile
            $result.BackupFile = $backupFile
            
            # Remove from all groups except Domain Users
            $groups = Get-ADPrincipalGroupMembership -Identity $Username | Where-Object { $_.Name -ne "Domain Users" }
            foreach ($group in $groups) {
                try {
                    Remove-ADGroupMember -Identity $group.Name -Members $Username -Confirm:$false
                    $result.Changes += "Removed from group: $($group.Name)"
                } catch {
                    Write-AdminLog -Message "Could not remove from group $($group.Name): $($_.Exception.Message)" -Level "Warning"
                }
            }
            
            # Disable account
            Disable-ADAccount -Identity $Username
            
            # Clear manager relationships for direct reports
            $directReports = Get-ADUser -Filter "Manager -eq '$($user.DistinguishedName)'"
            foreach ($report in $directReports) {
                Set-ADUser -Identity $report.SamAccountName -Manager $null
                $result.Changes += "Cleared manager for: $($report.SamAccountName)"
            }
            
            # Set final description
            Set-ADUser -Identity $Username -Description "OFFBOARDED $(Get-Date -Format 'yyyy-MM-dd') by $env:USERNAME"
            
            $result.Status = "Offboarded"
            $result.Changes += "Account fully offboarded", "All group memberships removed", "Direct reports updated"
            Write-AdminLog -Message "Completed offboarding for: $Username" -Level "Success"
        }
    }
    
    # Send notifications if requested
    if ($NotifyManagers -and $user.Manager) {
        $manager = Get-ADUser -Identity $user.Manager -Properties EmailAddress -ErrorAction SilentlyContinue
        if ($manager -and $manager.EmailAddress) {
            $subject = "User Lifecycle Change: $($user.DisplayName)"
            $body = @"
User lifecycle change notification:

User: $($user.DisplayName) ($Username)
Action: $Action
Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Changes: $($result.Changes -join '; ')

This is an automated notification from the user lifecycle management system.
"@
            Send-AdminNotification -Subject $subject -Body $body -Recipients @($manager.EmailAddress)
        }
    }
    
    # Generate final report
    $report = New-AdminReport -ReportTitle "User Lifecycle Management" -Data $result -Description "User lifecycle management operation results" -Metadata @{
        Action = $Action
        Username = $Username
        ExecutedBy = $env:USERNAME
        RetentionDays = $RetentionDays
    }
    
    Write-Output $report
    Write-AdminLog -Message "User lifecycle management completed for: $Username" -Level "Success"
    
} catch {
    Write-AdminLog -Message "User lifecycle management failed: $($_.Exception.Message)" -Level "Error"
    throw
}
