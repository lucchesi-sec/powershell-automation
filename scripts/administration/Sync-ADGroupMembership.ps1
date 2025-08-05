<#
.SYNOPSIS
    Synchronizes Active Directory group memberships based on user attributes or external data sources.
.DESCRIPTION
    This script automates group membership management by synchronizing memberships based on user
    attributes (department, title, location) or external data sources (CSV files, databases).
    Supports adding, removing, and auditing group memberships with comprehensive logging.
.PARAMETER SyncMode
    The synchronization mode: AttributeBased, CsvBased, or AuditOnly.
.PARAMETER CsvPath
    Path to CSV file for CSV-based synchronization.
.PARAMETER AttributeMappingPath
    Path to JSON file containing attribute-to-group mappings.
.PARAMETER DryRun
    If specified, shows what changes would be made without applying them.
.PARAMETER RemoveOrphaned
    If specified, removes users from groups where they no longer meet criteria.
.PARAMETER ExcludeGroups
    Array of group names to exclude from synchronization.
.EXAMPLE
    .\Sync-ADGroupMembership.ps1 -SyncMode "AttributeBased" -AttributeMappingPath "C:\Mappings.json"
.EXAMPLE
    .\Sync-ADGroupMembership.ps1 -SyncMode "CsvBased" -CsvPath "C:\GroupAssignments.csv" -DryRun
.NOTES
    Author: System Administrator
    Requires: ActiveDirectory module, PSAdminCore module
    
    AttributeMapping JSON Format:
    {
        "Department": {
            "IT": ["IT-Department", "VPN-Users"],
            "HR": ["HR-Department", "Confidential-Access"]
        },
        "Title": {
            "Manager": ["Managers-Group"],
            "Admin": ["Administrators"]
        }
    }
    
    CSV Format:
    Username,GroupName,Action
    jdoe,IT-Department,Add
    jsmith,Managers-Group,Remove
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("AttributeBased", "CsvBased", "AuditOnly")]
    [string]$SyncMode,
    
    [Parameter(Mandatory = $false)]
    [string]$CsvPath,
    
    [Parameter(Mandatory = $false)]
    [string]$AttributeMappingPath = "$PSScriptRoot\..\..\config\group-mappings.json",
    
    [Parameter(Mandatory = $false)]
    [switch]$DryRun,
    
    [Parameter(Mandatory = $false)]
    [switch]$RemoveOrphaned,
    
    [Parameter(Mandatory = $false)]
    [string[]]$ExcludeGroups = @("Domain Admins", "Schema Admins")
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

Write-AdminLog -Message "Starting group membership synchronization (Mode: $SyncMode)" -Level "Info"

try {
    $results = @()
    $addCount = 0
    $removeCount = 0
    $errorCount = 0
    
    switch ($SyncMode) {
        "AttributeBased" {
            Write-AdminLog -Message "Processing attribute-based synchronization" -Level "Info"
            
            # Load attribute mappings
            if (-not (Test-Path $AttributeMappingPath)) {
                throw "Attribute mapping file not found: $AttributeMappingPath"
            }
            
            $mappings = Get-Content $AttributeMappingPath | ConvertFrom-Json
            Write-AdminLog -Message "Loaded attribute mappings from: $AttributeMappingPath" -Level "Info"
            
            # Get all users with required attributes
            $users = Get-ADUser -Filter * -Properties Department, Title, City, Company, EmployeeType
            Write-AdminLog -Message "Processing $($users.Count) users for attribute-based sync" -Level "Info"
            
            foreach ($user in $users) {
                try {
                    $userGroups = Get-ADPrincipalGroupMembership -Identity $user.SamAccountName | Select-Object -ExpandProperty Name
                    $requiredGroups = @()
                    
                    # Check Department mappings
                    if ($mappings.Department -and $user.Department) {
                        $deptGroups = $mappings.Department.($user.Department)
                        if ($deptGroups) {
                            $requiredGroups += $deptGroups
                        }
                    }
                    
                    # Check Title mappings
                    if ($mappings.Title -and $user.Title) {
                        $titleGroups = $mappings.Title.($user.Title)
                        if ($titleGroups) {
                            $requiredGroups += $titleGroups
                        }
                    }
                    
                    # Check City mappings
                    if ($mappings.City -and $user.City) {
                        $cityGroups = $mappings.City.($user.City)
                        if ($cityGroups) {
                            $requiredGroups += $cityGroups
                        }
                    }
                    
                    # Check Company mappings
                    if ($mappings.Company -and $user.Company) {
                        $companyGroups = $mappings.Company.($user.Company)
                        if ($companyGroups) {
                            $requiredGroups += $companyGroups
                        }
                    }
                    
                    # Check EmployeeType mappings
                    if ($mappings.EmployeeType -and $user.EmployeeType) {
                        $typeGroups = $mappings.EmployeeType.($user.EmployeeType)
                        if ($typeGroups) {
                            $requiredGroups += $typeGroups
                        }
                    }
                    
                    $requiredGroups = $requiredGroups | Select-Object -Unique | Where-Object { $_ -notin $ExcludeGroups }
                    
                    # Add to missing groups
                    foreach ($group in $requiredGroups) {
                        if ($group -notin $userGroups) {
                            $result = [PSCustomObject]@{
                                Username = $user.SamAccountName
                                GroupName = $group
                                Action = "Add"
                                Reason = "Attribute-based mapping"
                                Status = if ($DryRun) { "Would Add" } else { "Unknown" }
                                Error = $null
                            }
                            
                            if (-not $DryRun) {
                                try {
                                    Add-ADGroupMember -Identity $group -Members $user.SamAccountName
                                    $result.Status = "Added"
                                    $addCount++
                                    Write-AdminLog -Message "Added $($user.SamAccountName) to $group" -Level "Success"
                                } catch {
                                    $result.Status = "Failed"
                                    $result.Error = $_.Exception.Message
                                    $errorCount++
                                    Write-AdminLog -Message "Failed to add $($user.SamAccountName) to $group`: $($_.Exception.Message)" -Level "Error"
                                }
                            } else {
                                Write-AdminLog -Message "DRY RUN: Would add $($user.SamAccountName) to $group" -Level "Info"
                            }
                            
                            $results += $result
                        }
                    }
                    
                    # Remove from orphaned groups if requested
                    if ($RemoveOrphaned) {
                        $managedGroups = @()
                        foreach ($attrType in $mappings.PSObject.Properties.Name) {
                            foreach ($value in $mappings.$attrType.PSObject.Properties.Name) {
                                $managedGroups += $mappings.$attrType.$value
                            }
                        }
                        $managedGroups = $managedGroups | Select-Object -Unique
                        
                        $orphanedGroups = $userGroups | Where-Object { 
                            $_ -in $managedGroups -and $_ -notin $requiredGroups -and $_ -notin $ExcludeGroups -and $_ -ne "Domain Users"
                        }
                        
                        foreach ($group in $orphanedGroups) {
                            $result = [PSCustomObject]@{
                                Username = $user.SamAccountName
                                GroupName = $group
                                Action = "Remove"
                                Reason = "No longer meets attribute criteria"
                                Status = if ($DryRun) { "Would Remove" } else { "Unknown" }
                                Error = $null
                            }
                            
                            if (-not $DryRun) {
                                try {
                                    Remove-ADGroupMember -Identity $group -Members $user.SamAccountName -Confirm:$false
                                    $result.Status = "Removed"
                                    $removeCount++
                                    Write-AdminLog -Message "Removed $($user.SamAccountName) from $group" -Level "Success"
                                } catch {
                                    $result.Status = "Failed"
                                    $result.Error = $_.Exception.Message
                                    $errorCount++
                                    Write-AdminLog -Message "Failed to remove $($user.SamAccountName) from $group`: $($_.Exception.Message)" -Level "Error"
                                }
                            } else {
                                Write-AdminLog -Message "DRY RUN: Would remove $($user.SamAccountName) from $group" -Level "Info"
                            }
                            
                            $results += $result
                        }
                    }
                    
                } catch {
                    Write-AdminLog -Message "Error processing user $($user.SamAccountName): $($_.Exception.Message)" -Level "Error"
                    $errorCount++
                }
            }
        }
        
        "CsvBased" {
            Write-AdminLog -Message "Processing CSV-based synchronization" -Level "Info"
            
            if (-not $CsvPath -or -not (Test-Path $CsvPath)) {
                throw "CSV file path is required and must exist for CSV-based sync"
            }
            
            $csvData = Import-Csv -Path $CsvPath
            Write-AdminLog -Message "Imported $($csvData.Count) group assignment records from CSV" -Level "Info"
            
            # Validate CSV columns
            $requiredColumns = @('Username', 'GroupName', 'Action')
            $csvColumns = $csvData[0].PSObject.Properties.Name
            
            foreach ($column in $requiredColumns) {
                if ($column -notin $csvColumns) {
                    throw "Required column '$column' not found in CSV file"
                }
            }
            
            foreach ($record in $csvData) {
                try {
                    # Validate user exists
                    $user = Get-ADUser -Identity $record.Username -ErrorAction Stop
                    
                    # Validate group exists
                    $group = Get-ADGroup -Identity $record.GroupName -ErrorAction Stop
                    
                    # Skip excluded groups
                    if ($record.GroupName -in $ExcludeGroups) {
                        Write-AdminLog -Message "Skipping excluded group: $($record.GroupName)" -Level "Warning"
                        continue
                    }
                    
                    $result = [PSCustomObject]@{
                        Username = $record.Username
                        GroupName = $record.GroupName
                        Action = $record.Action
                        Reason = "CSV-based assignment"
                        Status = if ($DryRun) { "Would $($record.Action)" } else { "Unknown" }
                        Error = $null
                    }
                    
                    if (-not $DryRun) {
                        switch ($record.Action.ToLower()) {
                            "add" {
                                try {
                                    Add-ADGroupMember -Identity $record.GroupName -Members $record.Username
                                    $result.Status = "Added"
                                    $addCount++
                                    Write-AdminLog -Message "Added $($record.Username) to $($record.GroupName)" -Level "Success"
                                } catch {
                                    $result.Status = "Failed"
                                    $result.Error = $_.Exception.Message
                                    $errorCount++
                                    Write-AdminLog -Message "Failed to add $($record.Username) to $($record.GroupName): $($_.Exception.Message)" -Level "Error"
                                }
                            }
                            "remove" {
                                try {
                                    Remove-ADGroupMember -Identity $record.GroupName -Members $record.Username -Confirm:$false
                                    $result.Status = "Removed"
                                    $removeCount++
                                    Write-AdminLog -Message "Removed $($record.Username) from $($record.GroupName)" -Level "Success"
                                } catch {
                                    $result.Status = "Failed"
                                    $result.Error = $_.Exception.Message
                                    $errorCount++
                                    Write-AdminLog -Message "Failed to remove $($record.Username) from $($record.GroupName): $($_.Exception.Message)" -Level "Error"
                                }
                            }
                            default {
                                $result.Status = "Invalid Action"
                                $result.Error = "Action must be 'Add' or 'Remove'"
                                $errorCount++
                                Write-AdminLog -Message "Invalid action '$($record.Action)' for $($record.Username)" -Level "Error"
                            }
                        }
                    } else {
                        Write-AdminLog -Message "DRY RUN: Would $($record.Action.ToLower()) $($record.Username) to/from $($record.GroupName)" -Level "Info"
                    }
                    
                    $results += $result
                    
                } catch {
                    $result = [PSCustomObject]@{
                        Username = $record.Username
                        GroupName = $record.GroupName
                        Action = $record.Action
                        Reason = "CSV-based assignment"
                        Status = "Failed"
                        Error = $_.Exception.Message
                    }
                    $results += $result
                    $errorCount++
                    Write-AdminLog -Message "Error processing CSV record: $($_.Exception.Message)" -Level "Error"
                }
            }
        }
        
        "AuditOnly" {
            Write-AdminLog -Message "Processing audit-only mode" -Level "Info"
            
            # Generate comprehensive group membership audit
            $users = Get-ADUser -Filter * -Properties Department, Title, City, Company
            $groups = Get-ADGroup -Filter *
            
            foreach ($user in $users) {
                try {
                    $userGroups = Get-ADPrincipalGroupMembership -Identity $user.SamAccountName
                    
                    foreach ($group in $userGroups) {
                        $result = [PSCustomObject]@{
                            Username = $user.SamAccountName
                            DisplayName = $user.DisplayName
                            Department = $user.Department
                            Title = $user.Title
                            City = $user.City
                            Company = $user.Company
                            GroupName = $group.Name
                            GroupType = $group.GroupCategory
                            GroupScope = $group.GroupScope
                            Action = "Audit"
                            Status = "Current Member"
                            LastLogon = $user.LastLogonDate
                        }
                        $results += $result
                    }
                } catch {
                    Write-AdminLog -Message "Error auditing user $($user.SamAccountName): $($_.Exception.Message)" -Level "Error"
                }
            }
            
            Write-AdminLog -Message "Audit completed for $($users.Count) users and $($groups.Count) groups" -Level "Success"
        }
    }
    
    # Generate summary report
    $report = New-AdminReport -ReportTitle "AD Group Membership Synchronization" -Data $results -Description "Active Directory group membership synchronization results" -Metadata @{
        SyncMode = $SyncMode
        DryRun = $DryRun.IsPresent
        RemoveOrphaned = $RemoveOrphaned.IsPresent
        TotalChanges = $results.Count
        AddCount = $addCount
        RemoveCount = $removeCount
        ErrorCount = $errorCount
        ExcludeGroups = $ExcludeGroups
        CsvPath = $CsvPath
        AttributeMappingPath = $AttributeMappingPath
    }
    
    Write-Output $report
    
    # Summary
    if ($DryRun) {
        Write-AdminLog -Message "DRY RUN COMPLETE: Would make $($results.Count) changes" -Level "Info"
    } else {
        Write-AdminLog -Message "Group sync complete. Added: $addCount, Removed: $removeCount, Errors: $errorCount" -Level "Success"
    }
    
} catch {
    Write-AdminLog -Message "Group membership synchronization failed: $($_.Exception.Message)" -Level "Error"
    throw
}
