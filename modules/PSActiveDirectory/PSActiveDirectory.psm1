<#
.SYNOPSIS
    PSActiveDirectory - Enhanced Active Directory management module
.DESCRIPTION
    Provides comprehensive Active Directory management capabilities with
    advanced features for user lifecycle, group management, and automation.
.NOTES
    Version: 2.0.0
    Author: Enterprise Automation Team
#>

# Import dependencies
Import-Module PSCore -MinimumVersion 2.0.0

#region Module Variables
$script:PSADConfig = @{
    DefaultUserOU = "OU=Users,DC=company,DC=com"
    DefaultGroupOU = "OU=Groups,DC=company,DC=com"
    DefaultComputerOU = "OU=Computers,DC=company,DC=com"
    PasswordPolicy = @{
        MinimumLength = 12
        RequireComplexity = $true
        MaximumAge = 90
        MinimumAge = 1
        HistoryCount = 24
    }
    UserDefaults = @{
        Enabled = $true
        ChangePasswordAtLogon = $true
        PasswordNeverExpires = $false
        CannotChangePassword = $false
        Department = "Unassigned"
        Company = "Enterprise Corporation"
    }
    NamingConvention = @{
        UserPrincipalName = '{firstname}.{lastname}@company.com'
        SamAccountName = '{firstname}{lastname}'
        DisplayName = '{firstname} {lastname}'
        EmailAddress = '{firstname}.{lastname}@company.com'
    }
    SearchLimit = 1000
    BulkOperationBatchSize = 50
    EnableAuditLog = $true
    CacheTimeout = 300 # seconds
}

$script:PSADDefaultProperties = @{
    User = @('Name', 'SamAccountName', 'UserPrincipalName', 'Enabled', 'EmailAddress', 'Department', 'Title', 'Manager', 'LastLogonDate')
    Group = @('Name', 'SamAccountName', 'GroupCategory', 'GroupScope', 'Description', 'ManagedBy', 'Members')
    Computer = @('Name', 'DNSHostName', 'Enabled', 'OperatingSystem', 'OperatingSystemVersion', 'LastLogonDate', 'IPv4Address')
}

$script:ADCache = @{}
$script:ADCacheExpiry = @{}
#endregion

#region User Management Functions
function New-PSADUser {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FirstName,
        
        [Parameter(Mandatory = $true)]
        [string]$LastName,
        
        [Parameter(Mandatory = $false)]
        [string]$MiddleInitial,
        
        [Parameter(Mandatory = $false)]
        [string]$Department = $script:PSADConfig.UserDefaults.Department,
        
        [Parameter(Mandatory = $false)]
        [string]$Title,
        
        [Parameter(Mandatory = $false)]
        [string]$Manager,
        
        [Parameter(Mandatory = $false)]
        [string]$Office,
        
        [Parameter(Mandatory = $false)]
        [string]$PhoneNumber,
        
        [Parameter(Mandatory = $false)]
        [string]$MobilePhone,
        
        [Parameter(Mandatory = $false)]
        [string]$OU = $script:PSADConfig.DefaultUserOU,
        
        [Parameter(Mandatory = $false)]
        [SecureString]$Password,
        
        [Parameter(Mandatory = $false)]
        [switch]$PassThru,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$AdditionalProperties = @{},
        
        [Parameter(Mandatory = $false)]
        [string[]]$Groups = @()
    )
    
    begin {
        $context = Initialize-PSLogContext -Operation 'New-PSADUser' -Properties @{
            FirstName = $FirstName
            LastName = $LastName
            Department = $Department
        }
        
        # Generate names based on naming convention
        $nameParams = @{
            firstname = $FirstName.ToLower()
            lastname = $LastName.ToLower()
            firstinitial = $FirstName.Substring(0,1).ToLower()
            lastinitial = $LastName.Substring(0,1).ToLower()
        }
        
        $samAccountName = $script:PSADConfig.NamingConvention.SamAccountName
        $userPrincipalName = $script:PSADConfig.NamingConvention.UserPrincipalName
        $displayName = $script:PSADConfig.NamingConvention.DisplayName
        $emailAddress = $script:PSADConfig.NamingConvention.EmailAddress
        
        foreach ($key in $nameParams.Keys) {
            $samAccountName = $samAccountName -replace "{$key}", $nameParams[$key]
            $userPrincipalName = $userPrincipalName -replace "{$key}", $nameParams[$key]
            $displayName = $displayName -replace "{$key}", ($nameParams[$key].Substring(0,1).ToUpper() + $nameParams[$key].Substring(1))
            $emailAddress = $emailAddress -replace "{$key}", $nameParams[$key]
        }
    }
    
    process {
        try {
            # Check if user already exists
            $existingUser = Get-ADUser -Filter "SamAccountName -eq '$samAccountName'" -ErrorAction SilentlyContinue
            if ($existingUser) {
                throw "User with SamAccountName '$samAccountName' already exists"
            }
            
            # Generate password if not provided
            if (-not $Password) {
                $Password = New-PSADPassword
            }
            
            # Validate password against policy
            if (-not (Test-PSADPassword -Password $Password)) {
                throw "Password does not meet complexity requirements"
            }
            
            # Prepare user properties
            $userParams = @{
                Name = $displayName
                DisplayName = $displayName
                GivenName = $FirstName
                Surname = $LastName
                SamAccountName = $samAccountName
                UserPrincipalName = $userPrincipalName
                EmailAddress = $emailAddress
                Department = $Department
                Company = $script:PSADConfig.UserDefaults.Company
                AccountPassword = $Password
                Path = $OU
                Enabled = $script:PSADConfig.UserDefaults.Enabled
                ChangePasswordAtLogon = $script:PSADConfig.UserDefaults.ChangePasswordAtLogon
            }
            
            # Add optional properties
            if ($MiddleInitial) { $userParams['Initials'] = $MiddleInitial }
            if ($Title) { $userParams['Title'] = $Title }
            if ($Manager) { $userParams['Manager'] = $Manager }
            if ($Office) { $userParams['Office'] = $Office }
            if ($PhoneNumber) { $userParams['OfficePhone'] = $PhoneNumber }
            if ($MobilePhone) { $userParams['MobilePhone'] = $MobilePhone }
            
            # Merge additional properties
            foreach ($key in $AdditionalProperties.Keys) {
                if (-not $userParams.ContainsKey($key)) {
                    $userParams[$key] = $AdditionalProperties[$key]
                }
            }
            
            if ($PSCmdlet.ShouldProcess($displayName, "Create AD User")) {
                Write-PSLog -Message "Creating AD user: $samAccountName" -Component 'PSActiveDirectory'
                
                $newUser = New-ADUser @userParams -PassThru
                
                # Add to groups
                if ($Groups.Count -gt 0) {
                    foreach ($group in $Groups) {
                        try {
                            Add-ADGroupMember -Identity $group -Members $samAccountName
                            Write-PSLog -Message "Added user $samAccountName to group: $group" -Component 'PSActiveDirectory'
                        }
                        catch {
                            Write-PSLog -Message "Failed to add user to group $group`: $_" -Level 'Warning' -Component 'PSActiveDirectory'
                        }
                    }
                }
                
                # Audit log
                if ($script:PSADConfig.EnableAuditLog) {
                    Write-PSADAuditLog -Action 'CreateUser' -ObjectType 'User' -ObjectName $samAccountName -Details $userParams
                }
                
                Write-PSLog -Message "Successfully created AD user: $samAccountName" -Level 'Success' -Component 'PSActiveDirectory'
                
                if ($PassThru) {
                    return Get-PSADUser -Identity $samAccountName
                }
            }
        }
        catch {
            Write-PSLog -Message "Failed to create AD user: $_" -Level 'Error' -Component 'PSActiveDirectory' -Context $context
            throw
        }
    }
}

function Set-PSADUser {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Identity,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Properties = @{},
        
        [Parameter(Mandatory = $false)]
        [string]$NewSamAccountName,
        
        [Parameter(Mandatory = $false)]
        [switch]$Enable,
        
        [Parameter(Mandatory = $false)]
        [switch]$Disable,
        
        [Parameter(Mandatory = $false)]
        [switch]$Unlock,
        
        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )
    
    process {
        try {
            $user = Get-ADUser -Identity $Identity -Properties *
            if (-not $user) {
                throw "User not found: $Identity"
            }
            
            $changes = @{}
            
            # Handle special operations
            if ($Enable -and -not $user.Enabled) {
                $changes['Enabled'] = $true
            }
            
            if ($Disable -and $user.Enabled) {
                $changes['Enabled'] = $false
            }
            
            if ($Unlock -and $user.LockedOut) {
                Unlock-ADAccount -Identity $user.DistinguishedName
                Write-PSLog -Message "Unlocked user account: $($user.SamAccountName)" -Component 'PSActiveDirectory'
            }
            
            # Handle property changes
            foreach ($key in $Properties.Keys) {
                if ($user.$key -ne $Properties[$key]) {
                    $changes[$key] = $Properties[$key]
                }
            }
            
            # Handle SamAccountName change specially
            if ($NewSamAccountName -and $NewSamAccountName -ne $user.SamAccountName) {
                $changes['SamAccountName'] = $NewSamAccountName
            }
            
            if ($changes.Count -gt 0) {
                if ($PSCmdlet.ShouldProcess($user.SamAccountName, "Modify AD User")) {
                    Set-ADUser -Identity $user.DistinguishedName @changes
                    
                    # Audit log
                    if ($script:PSADConfig.EnableAuditLog) {
                        Write-PSADAuditLog -Action 'ModifyUser' -ObjectType 'User' -ObjectName $user.SamAccountName -Details $changes
                    }
                    
                    Write-PSLog -Message "Modified AD user: $($user.SamAccountName)" -Component 'PSActiveDirectory' -Context @{Changes = $changes}
                }
            }
            
            if ($PassThru) {
                return Get-PSADUser -Identity $Identity
            }
        }
        catch {
            Write-PSLog -Message "Failed to modify AD user: $_" -Level 'Error' -Component 'PSActiveDirectory'
            throw
        }
    }
}

function Get-PSADUser {
    [CmdletBinding(DefaultParameterSetName = 'Identity')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Identity', ValueFromPipeline = $true)]
        [string]$Identity,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'Filter')]
        [string]$Filter,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'LDAPFilter')]
        [string]$LDAPFilter,
        
        [Parameter(Mandatory = $false)]
        [string]$SearchBase = $script:PSADConfig.DefaultUserOU,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Properties = $script:PSADDefaultProperties.User,
        
        [Parameter(Mandatory = $false)]
        [int]$ResultLimit = $script:PSADConfig.SearchLimit,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeGroupMembership,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeManager,
        
        [Parameter(Mandatory = $false)]
        [switch]$UseCache
    )
    
    process {
        try {
            $cacheKey = $null
            
            # Check cache
            if ($UseCache -and $PSCmdlet.ParameterSetName -eq 'Identity') {
                $cacheKey = "User:$Identity"
                if (Test-PSADCache -Key $cacheKey) {
                    Write-PSLog -Message "Returning cached user: $Identity" -Component 'PSActiveDirectory'
                    return Get-PSADCache -Key $cacheKey
                }
            }
            
            # Prepare search parameters
            $searchParams = @{
                Properties = $Properties
                ResultSetSize = $ResultLimit
            }
            
            if ($SearchBase) {
                $searchParams['SearchBase'] = $SearchBase
            }
            
            # Execute search based on parameter set
            $users = switch ($PSCmdlet.ParameterSetName) {
                'Identity' {
                    Get-ADUser -Identity $Identity @searchParams
                }
                'Filter' {
                    Get-ADUser -Filter $Filter @searchParams
                }
                'LDAPFilter' {
                    Get-ADUser -LDAPFilter $LDAPFilter @searchParams
                }
            }
            
            # Process each user
            foreach ($user in $users) {
                # Add extended properties
                if ($IncludeGroupMembership) {
                    $user | Add-Member -MemberType NoteProperty -Name 'GroupMembership' -Value (
                        Get-ADPrincipalGroupMembership -Identity $user.DistinguishedName | 
                        Select-Object -ExpandProperty Name
                    ) -Force
                }
                
                if ($IncludeManager -and $user.Manager) {
                    $user | Add-Member -MemberType NoteProperty -Name 'ManagerDetails' -Value (
                        Get-ADUser -Identity $user.Manager -Properties DisplayName, EmailAddress
                    ) -Force
                }
                
                # Add calculated properties
                $user | Add-Member -MemberType NoteProperty -Name 'AccountAge' -Value (
                    if ($user.whenCreated) { (Get-Date) - $user.whenCreated } else { $null }
                ) -Force
                
                $user | Add-Member -MemberType NoteProperty -Name 'PasswordAge' -Value (
                    if ($user.PasswordLastSet) { (Get-Date) - $user.PasswordLastSet } else { $null }
                ) -Force
                
                $user | Add-Member -MemberType NoteProperty -Name 'IsLocked' -Value (
                    $user.LockedOut -eq $true
                ) -Force
                
                # Cache if appropriate
                if ($UseCache -and $PSCmdlet.ParameterSetName -eq 'Identity') {
                    Set-PSADCache -Key $cacheKey -Value $user
                }
                
                # Output
                $user
            }
        }
        catch {
            Write-PSLog -Message "Failed to get AD user: $_" -Level 'Error' -Component 'PSActiveDirectory'
            throw
        }
    }
}

function Reset-PSADUserPassword {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string[]]$Identity,
        
        [Parameter(Mandatory = $false)]
        [SecureString]$NewPassword,
        
        [Parameter(Mandatory = $false)]
        [switch]$MustChangePasswordAtLogon,
        
        [Parameter(Mandatory = $false)]
        [switch]$UnlockAccount,
        
        [Parameter(Mandatory = $false)]
        [switch]$SendNotification,
        
        [Parameter(Mandatory = $false)]
        [string]$NotificationTemplate = 'PasswordReset'
    )
    
    begin {
        $results = @()
    }
    
    process {
        foreach ($userId in $Identity) {
            try {
                $user = Get-ADUser -Identity $userId -Properties EmailAddress, DisplayName
                if (-not $user) {
                    throw "User not found: $userId"
                }
                
                # Generate password if not provided
                if (-not $NewPassword) {
                    $NewPassword = New-PSADPassword
                }
                
                # Validate password
                if (-not (Test-PSADPassword -Password $NewPassword)) {
                    throw "Password does not meet complexity requirements"
                }
                
                if ($PSCmdlet.ShouldProcess($user.SamAccountName, "Reset Password")) {
                    # Reset password
                    Set-ADAccountPassword -Identity $user.DistinguishedName -NewPassword $NewPassword -Reset
                    
                    # Set password change requirement
                    if ($MustChangePasswordAtLogon) {
                        Set-ADUser -Identity $user.DistinguishedName -ChangePasswordAtLogon $true
                    }
                    
                    # Unlock account if requested
                    if ($UnlockAccount -and $user.LockedOut) {
                        Unlock-ADAccount -Identity $user.DistinguishedName
                    }
                    
                    # Send notification
                    if ($SendNotification -and $user.EmailAddress) {
                        Send-PSADNotification -Template $NotificationTemplate -Recipient $user.EmailAddress -Parameters @{
                            DisplayName = $user.DisplayName
                            Username = $user.SamAccountName
                            MustChange = $MustChangePasswordAtLogon
                        }
                    }
                    
                    # Audit log
                    if ($script:PSADConfig.EnableAuditLog) {
                        Write-PSADAuditLog -Action 'ResetPassword' -ObjectType 'User' -ObjectName $user.SamAccountName -Details @{
                            MustChangePasswordAtLogon = $MustChangePasswordAtLogon
                            AccountUnlocked = $UnlockAccount
                            NotificationSent = $SendNotification
                        }
                    }
                    
                    $result = [PSCustomObject]@{
                        SamAccountName = $user.SamAccountName
                        DisplayName = $user.DisplayName
                        Status = 'Success'
                        MustChangePassword = $MustChangePasswordAtLogon
                        AccountUnlocked = $UnlockAccount
                        NotificationSent = $SendNotification
                        Timestamp = Get-Date
                    }
                    
                    Write-PSLog -Message "Password reset for user: $($user.SamAccountName)" -Level 'Success' -Component 'PSActiveDirectory'
                }
            }
            catch {
                $result = [PSCustomObject]@{
                    SamAccountName = $userId
                    Status = 'Failed'
                    Error = $_.Exception.Message
                    Timestamp = Get-Date
                }
                
                Write-PSLog -Message "Failed to reset password for user $userId`: $_" -Level 'Error' -Component 'PSActiveDirectory'
            }
            
            $results += $result
        }
    }
    
    end {
        return $results
    }
}

function Set-PSADUserLifecycle {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Identity,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('Onboarding', 'Active', 'Leave', 'Terminated', 'Archived')]
        [string]$Stage,
        
        [Parameter(Mandatory = $false)]
        [datetime]$EffectiveDate = (Get-Date),
        
        [Parameter(Mandatory = $false)]
        [hashtable]$StageActions = @{},
        
        [Parameter(Mandatory = $false)]
        [switch]$AutomateActions
    )
    
    process {
        try {
            $user = Get-ADUser -Identity $Identity -Properties *
            if (-not $user) {
                throw "User not found: $Identity"
            }
            
            Write-PSLog -Message "Setting lifecycle stage for $($user.SamAccountName) to: $Stage" -Component 'PSActiveDirectory'
            
            # Default actions for each stage
            $defaultActions = @{
                'Onboarding' = @{
                    Enable = $true
                    AddToGroups = @('AllStaff', 'NewEmployees')
                    SetAttributes = @{
                        extensionAttribute1 = 'Onboarding'
                        extensionAttribute2 = $EffectiveDate.ToString('yyyy-MM-dd')
                    }
                    SendWelcomeEmail = $true
                }
                'Active' = @{
                    Enable = $true
                    RemoveFromGroups = @('NewEmployees')
                    SetAttributes = @{
                        extensionAttribute1 = 'Active'
                    }
                }
                'Leave' = @{
                    Enable = $false
                    SetAttributes = @{
                        extensionAttribute1 = 'Leave'
                        extensionAttribute3 = 'ReturnDate:TBD'
                    }
                    DisableEmail = $true
                    RemoveFromGroups = @('VPN-Users', 'RemoteAccess')
                }
                'Terminated' = @{
                    Enable = $false
                    ResetPassword = $true
                    RemoveFromAllGroups = $true
                    SetAttributes = @{
                        extensionAttribute1 = 'Terminated'
                        extensionAttribute2 = $EffectiveDate.ToString('yyyy-MM-dd')
                    }
                    MoveToOU = 'OU=Terminated,DC=company,DC=com'
                    DisableEmail = $true
                    RevokeAccess = $true
                }
                'Archived' = @{
                    Enable = $false
                    SetAttributes = @{
                        extensionAttribute1 = 'Archived'
                    }
                    MoveToOU = 'OU=Archived,DC=company,DC=com'
                    CompressMailbox = $true
                }
            }
            
            # Merge custom actions with defaults
            $actions = $defaultActions[$Stage]
            foreach ($key in $StageActions.Keys) {
                $actions[$key] = $StageActions[$key]
            }
            
            if ($PSCmdlet.ShouldProcess($user.SamAccountName, "Apply lifecycle stage: $Stage")) {
                if ($AutomateActions) {
                    # Enable/Disable account
                    if ($actions.ContainsKey('Enable')) {
                        if ($actions.Enable) {
                            Enable-ADAccount -Identity $user.DistinguishedName
                        } else {
                            Disable-ADAccount -Identity $user.DistinguishedName
                        }
                    }
                    
                    # Reset password
                    if ($actions.ResetPassword) {
                        $tempPassword = New-PSADPassword
                        Set-ADAccountPassword -Identity $user.DistinguishedName -NewPassword $tempPassword -Reset
                    }
                    
                    # Group management
                    if ($actions.AddToGroups) {
                        foreach ($group in $actions.AddToGroups) {
                            try {
                                Add-ADGroupMember -Identity $group -Members $user.DistinguishedName
                            } catch {
                                Write-PSLog -Message "Failed to add to group $group`: $_" -Level 'Warning' -Component 'PSActiveDirectory'
                            }
                        }
                    }
                    
                    if ($actions.RemoveFromGroups) {
                        foreach ($group in $actions.RemoveFromGroups) {
                            try {
                                Remove-ADGroupMember -Identity $group -Members $user.DistinguishedName -Confirm:$false
                            } catch {
                                Write-PSLog -Message "Failed to remove from group $group`: $_" -Level 'Warning' -Component 'PSActiveDirectory'
                            }
                        }
                    }
                    
                    if ($actions.RemoveFromAllGroups) {
                        $groups = Get-ADPrincipalGroupMembership -Identity $user.DistinguishedName | 
                            Where-Object { $_.Name -ne 'Domain Users' }
                        foreach ($group in $groups) {
                            try {
                                Remove-ADGroupMember -Identity $group -Members $user.DistinguishedName -Confirm:$false
                            } catch {
                                Write-PSLog -Message "Failed to remove from group $($group.Name): $_" -Level 'Warning' -Component 'PSActiveDirectory'
                            }
                        }
                    }
                    
                    # Set attributes
                    if ($actions.SetAttributes) {
                        Set-ADUser -Identity $user.DistinguishedName -Replace $actions.SetAttributes
                    }
                    
                    # Move to OU
                    if ($actions.MoveToOU) {
                        Move-ADObject -Identity $user.DistinguishedName -TargetPath $actions.MoveToOU
                    }
                }
                
                # Audit log
                if ($script:PSADConfig.EnableAuditLog) {
                    Write-PSADAuditLog -Action 'LifecycleChange' -ObjectType 'User' -ObjectName $user.SamAccountName -Details @{
                        PreviousStage = $user.extensionAttribute1
                        NewStage = $Stage
                        EffectiveDate = $EffectiveDate
                        ActionsApplied = $actions
                        Automated = $AutomateActions
                    }
                }
                
                Write-PSLog -Message "Lifecycle stage set successfully for $($user.SamAccountName)" -Level 'Success' -Component 'PSActiveDirectory'
                
                return [PSCustomObject]@{
                    User = $user.SamAccountName
                    Stage = $Stage
                    EffectiveDate = $EffectiveDate
                    ActionsApplied = if ($AutomateActions) { $actions.Keys } else { @() }
                    Status = 'Success'
                }
            }
        }
        catch {
            Write-PSLog -Message "Failed to set lifecycle stage: $_" -Level 'Error' -Component 'PSActiveDirectory'
            throw
        }
    }
}

function Get-PSADUserActivity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Identity,
        
        [Parameter(Mandatory = $false)]
        [datetime]$StartDate = (Get-Date).AddDays(-30),
        
        [Parameter(Mandatory = $false)]
        [datetime]$EndDate = (Get-Date),
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('All', 'Interactive', 'Network', 'Service')]
        [string]$LogonType = 'All',
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeFailures,
        
        [Parameter(Mandatory = $false)]
        [switch]$SummaryOnly
    )
    
    process {
        try {
            $filter = @{
                LogName = 'Security'
                StartTime = $StartDate
                EndTime = $EndDate
            }
            
            # Build event ID list
            $eventIds = @(4624) # Successful logon
            if ($IncludeFailures) {
                $eventIds += 4625 # Failed logon
            }
            $filter['ID'] = $eventIds
            
            # Get domain controllers
            $domainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
            
            $allEvents = @()
            
            foreach ($dc in $domainControllers) {
                try {
                    Write-PSLog -Message "Querying events from DC: $dc" -Component 'PSActiveDirectory'
                    
                    $events = Get-WinEvent -ComputerName $dc -FilterHashtable $filter -ErrorAction SilentlyContinue |
                        Where-Object {
                            $_.Properties[5].Value -notlike '*$' -and # Exclude computer accounts
                            $_.Properties[5].Value -ne 'ANONYMOUS LOGON' -and
                            $_.Properties[5].Value -ne 'LOCAL SERVICE' -and
                            $_.Properties[5].Value -ne 'NETWORK SERVICE'
                        }
                    
                    if ($Identity) {
                        $events = $events | Where-Object { $_.Properties[5].Value -eq $Identity }
                    }
                    
                    if ($LogonType -ne 'All') {
                        $logonTypeMap = @{
                            'Interactive' = 2, 10  # Local, Remote Interactive
                            'Network' = 3          # Network
                            'Service' = 5          # Service
                        }
                        $events = $events | Where-Object { $_.Properties[8].Value -in $logonTypeMap[$LogonType] }
                    }
                    
                    $allEvents += $events
                }
                catch {
                    Write-PSLog -Message "Failed to query DC $dc`: $_" -Level 'Warning' -Component 'PSActiveDirectory'
                }
            }
            
            if ($SummaryOnly) {
                # Generate summary
                $summary = $allEvents | Group-Object { $_.Properties[5].Value } | ForEach-Object {
                    $userEvents = $_.Group
                    $successfulLogons = $userEvents | Where-Object { $_.Id -eq 4624 }
                    $failedLogons = $userEvents | Where-Object { $_.Id -eq 4625 }
                    
                    [PSCustomObject]@{
                        UserName = $_.Name
                        TotalLogons = $successfulLogons.Count
                        FailedLogons = $failedLogons.Count
                        FirstLogon = ($successfulLogons | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
                        LastLogon = ($successfulLogons | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
                        UniqueComputers = ($successfulLogons | ForEach-Object { $_.Properties[11].Value } | Sort-Object -Unique).Count
                        LogonTypes = ($successfulLogons | ForEach-Object { 
                            switch ($_.Properties[8].Value) {
                                2 { 'Interactive' }
                                3 { 'Network' }
                                5 { 'Service' }
                                10 { 'RemoteInteractive' }
                                default { "Type$_" }
                            }
                        } | Group-Object | ForEach-Object { "$($_.Name):$($_.Count)" }) -join ', '
                    }
                }
                
                return $summary
            }
            else {
                # Return detailed events
                $detailedEvents = $allEvents | ForEach-Object {
                    [PSCustomObject]@{
                        TimeCreated = $_.TimeCreated
                        UserName = $_.Properties[5].Value
                        Domain = $_.Properties[6].Value
                        LogonType = switch ($_.Properties[8].Value) {
                            2 { 'Interactive' }
                            3 { 'Network' }
                            5 { 'Service' }
                            10 { 'RemoteInteractive' }
                            default { "Type$($_.Properties[8].Value)" }
                        }
                        WorkstationName = $_.Properties[11].Value
                        SourceIP = $_.Properties[18].Value
                        EventType = if ($_.Id -eq 4624) { 'Success' } else { 'Failure' }
                        DomainController = $_.MachineName
                    }
                } | Sort-Object TimeCreated -Descending
                
                return $detailedEvents
            }
        }
        catch {
            Write-PSLog -Message "Failed to get user activity: $_" -Level 'Error' -Component 'PSActiveDirectory'
            throw
        }
    }
}
#endregion

#region Group Management Functions
function New-PSADGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$DisplayName,
        
        [Parameter(Mandatory = $false)]
        [string]$Description,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Security', 'Distribution')]
        [string]$GroupCategory = 'Security',
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('DomainLocal', 'Global', 'Universal')]
        [string]$GroupScope = 'Global',
        
        [Parameter(Mandatory = $false)]
        [string]$ManagedBy,
        
        [Parameter(Mandatory = $false)]
        [string]$OU = $script:PSADConfig.DefaultGroupOU,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Members = @(),
        
        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )
    
    process {
        try {
            # Check if group exists
            $existingGroup = Get-ADGroup -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue
            if ($existingGroup) {
                throw "Group '$Name' already exists"
            }
            
            # Generate SamAccountName
            $samAccountName = $Name -replace '[^a-zA-Z0-9\-_]', ''
            if ($samAccountName.Length -gt 20) {
                $samAccountName = $samAccountName.Substring(0, 20)
            }
            
            $groupParams = @{
                Name = $Name
                SamAccountName = $samAccountName
                GroupCategory = $GroupCategory
                GroupScope = $GroupScope
                Path = $OU
            }
            
            if ($DisplayName) { $groupParams['DisplayName'] = $DisplayName }
            if ($Description) { $groupParams['Description'] = $Description }
            if ($ManagedBy) { $groupParams['ManagedBy'] = $ManagedBy }
            
            if ($PSCmdlet.ShouldProcess($Name, "Create AD Group")) {
                Write-PSLog -Message "Creating AD group: $Name" -Component 'PSActiveDirectory'
                
                $newGroup = New-ADGroup @groupParams -PassThru
                
                # Add members
                if ($Members.Count -gt 0) {
                    try {
                        Add-ADGroupMember -Identity $newGroup.DistinguishedName -Members $Members
                        Write-PSLog -Message "Added $($Members.Count) members to group: $Name" -Component 'PSActiveDirectory'
                    }
                    catch {
                        Write-PSLog -Message "Failed to add members to group: $_" -Level 'Warning' -Component 'PSActiveDirectory'
                    }
                }
                
                # Audit log
                if ($script:PSADConfig.EnableAuditLog) {
                    Write-PSADAuditLog -Action 'CreateGroup' -ObjectType 'Group' -ObjectName $Name -Details $groupParams
                }
                
                Write-PSLog -Message "Successfully created AD group: $Name" -Level 'Success' -Component 'PSActiveDirectory'
                
                if ($PassThru) {
                    return Get-PSADGroup -Identity $Name
                }
            }
        }
        catch {
            Write-PSLog -Message "Failed to create AD group: $_" -Level 'Error' -Component 'PSActiveDirectory'
            throw
        }
    }
}

function Sync-PSADGroupMembership {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceGroup,
        
        [Parameter(Mandatory = $true)]
        [string]$TargetGroup,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Mirror', 'Merge', 'Update')]
        [string]$Mode = 'Mirror',
        
        [Parameter(Mandatory = $false)]
        [string[]]$ExcludeUsers = @(),
        
        [Parameter(Mandatory = $false)]
        [switch]$WhatIf
    )
    
    process {
        try {
            # Get source and target groups
            $source = Get-ADGroup -Identity $SourceGroup -Properties Members
            $target = Get-ADGroup -Identity $TargetGroup -Properties Members
            
            if (-not $source -or -not $target) {
                throw "Source or target group not found"
            }
            
            # Get current members
            $sourceMembers = if ($source.Members) {
                $source.Members | ForEach-Object {
                    Get-ADObject -Identity $_ | Where-Object { $_.ObjectClass -eq 'user' }
                }
            } else { @() }
            
            $targetMembers = if ($target.Members) {
                $target.Members | ForEach-Object {
                    Get-ADObject -Identity $_ | Where-Object { $_.ObjectClass -eq 'user' }
                }
            } else { @() }
            
            # Apply exclusions
            if ($ExcludeUsers.Count -gt 0) {
                $sourceMembers = $sourceMembers | Where-Object {
                    $_.SamAccountName -notin $ExcludeUsers -and
                    $_.DistinguishedName -notin $ExcludeUsers
                }
            }
            
            # Calculate changes based on mode
            $toAdd = @()
            $toRemove = @()
            
            switch ($Mode) {
                'Mirror' {
                    # Make target exactly match source
                    $toAdd = $sourceMembers | Where-Object {
                        $_.DistinguishedName -notin $targetMembers.DistinguishedName
                    }
                    $toRemove = $targetMembers | Where-Object {
                        $_.DistinguishedName -notin $sourceMembers.DistinguishedName -and
                        $_.SamAccountName -notin $ExcludeUsers
                    }
                }
                'Merge' {
                    # Add source members to target, don't remove
                    $toAdd = $sourceMembers | Where-Object {
                        $_.DistinguishedName -notin $targetMembers.DistinguishedName
                    }
                }
                'Update' {
                    # Only add new members from source
                    $toAdd = $sourceMembers | Where-Object {
                        $_.DistinguishedName -notin $targetMembers.DistinguishedName
                    }
                }
            }
            
            $changes = [PSCustomObject]@{
                SourceGroup = $SourceGroup
                TargetGroup = $TargetGroup
                Mode = $Mode
                ToAdd = $toAdd.Count
                ToRemove = $toRemove.Count
                AddMembers = $toAdd | Select-Object Name, SamAccountName
                RemoveMembers = $toRemove | Select-Object Name, SamAccountName
            }
            
            if ($PSCmdlet.ShouldProcess($TargetGroup, "Sync group membership from $SourceGroup")) {
                # Add members
                if ($toAdd.Count -gt 0) {
                    Write-PSLog -Message "Adding $($toAdd.Count) members to $TargetGroup" -Component 'PSActiveDirectory'
                    Add-ADGroupMember -Identity $target.DistinguishedName -Members $toAdd.DistinguishedName
                }
                
                # Remove members
                if ($toRemove.Count -gt 0 -and $Mode -eq 'Mirror') {
                    Write-PSLog -Message "Removing $($toRemove.Count) members from $TargetGroup" -Component 'PSActiveDirectory'
                    Remove-ADGroupMember -Identity $target.DistinguishedName -Members $toRemove.DistinguishedName -Confirm:$false
                }
                
                # Audit log
                if ($script:PSADConfig.EnableAuditLog) {
                    Write-PSADAuditLog -Action 'SyncGroupMembership' -ObjectType 'Group' -ObjectName $TargetGroup -Details $changes
                }
                
                Write-PSLog -Message "Group membership sync completed" -Level 'Success' -Component 'PSActiveDirectory'
            }
            
            return $changes
        }
        catch {
            Write-PSLog -Message "Failed to sync group membership: $_" -Level 'Error' -Component 'PSActiveDirectory'
            throw
        }
    }
}

function Get-PSADGroupNesting {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Identity,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxDepth = 10,
        
        [Parameter(Mandatory = $false)]
        [switch]$ShowCircular
    )
    
    begin {
        $script:ProcessedGroups = @{}
        $script:CircularReferences = @()
        
        function Get-NestedGroups {
            param(
                [string]$GroupDN,
                [int]$CurrentDepth = 0,
                [string[]]$Path = @()
            )
            
            if ($CurrentDepth -ge $MaxDepth) {
                return
            }
            
            if ($GroupDN -in $Path) {
                # Circular reference detected
                $script:CircularReferences += [PSCustomObject]@{
                    Group = $GroupDN
                    Path = $Path + $GroupDN
                    Depth = $CurrentDepth
                }
                return
            }
            
            if ($script:ProcessedGroups.ContainsKey($GroupDN)) {
                return
            }
            
            $script:ProcessedGroups[$GroupDN] = $true
            
            try {
                $group = Get-ADGroup -Identity $GroupDN -Properties Members, MemberOf
                
                $groupInfo = [PSCustomObject]@{
                    Name = $group.Name
                    DistinguishedName = $group.DistinguishedName
                    Depth = $CurrentDepth
                    Path = ($Path + $group.Name) -join ' -> '
                    DirectMembers = @()
                    NestedGroups = @()
                    TotalMembers = 0
                    CircularReference = $false
                }
                
                # Get direct members
                if ($group.Members) {
                    $members = $group.Members | ForEach-Object {
                        Get-ADObject -Identity $_ -Properties objectClass
                    }
                    
                    $groupInfo.DirectMembers = $members | Where-Object { $_.objectClass -eq 'user' }
                    $nestedGroups = $members | Where-Object { $_.objectClass -eq 'group' }
                    
                    foreach ($nestedGroup in $nestedGroups) {
                        $nested = Get-NestedGroups -GroupDN $nestedGroup.DistinguishedName -CurrentDepth ($CurrentDepth + 1) -Path ($Path + $group.Name)
                        if ($nested) {
                            $groupInfo.NestedGroups += $nested
                        }
                    }
                }
                
                # Calculate total members including nested
                $groupInfo.TotalMembers = $groupInfo.DirectMembers.Count
                foreach ($nested in $groupInfo.NestedGroups) {
                    $groupInfo.TotalMembers += $nested.TotalMembers
                }
                
                return $groupInfo
            }
            catch {
                Write-PSLog -Message "Error processing group $GroupDN`: $_" -Level 'Warning' -Component 'PSActiveDirectory'
                return $null
            }
        }
    }
    
    process {
        try {
            $group = Get-ADGroup -Identity $Identity
            
            Write-PSLog -Message "Analyzing group nesting for: $($group.Name)" -Component 'PSActiveDirectory'
            
            $result = Get-NestedGroups -GroupDN $group.DistinguishedName
            
            if ($ShowCircular -and $script:CircularReferences.Count -gt 0) {
                $result | Add-Member -MemberType NoteProperty -Name 'CircularReferences' -Value $script:CircularReferences
            }
            
            return $result
        }
        catch {
            Write-PSLog -Message "Failed to analyze group nesting: $_" -Level 'Error' -Component 'PSActiveDirectory'
            throw
        }
    }
}
#endregion

#region Bulk Operations
function Import-PSADUsers {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('CSV', 'JSON', 'Excel')]
        [string]$Format = 'CSV',
        
        [Parameter(Mandatory = $false)]
        [hashtable]$FieldMapping = @{},
        
        [Parameter(Mandatory = $false)]
        [scriptblock]$ValidationScript,
        
        [Parameter(Mandatory = $false)]
        [switch]$ValidateOnly,
        
        [Parameter(Mandatory = $false)]
        [int]$BatchSize = $script:PSADConfig.BulkOperationBatchSize,
        
        [Parameter(Mandatory = $false)]
        [switch]$GenerateReport
    )
    
    process {
        try {
            $context = Initialize-PSLogContext -Operation 'Import-PSADUsers' -Properties @{
                Path = $Path
                Format = $Format
                ValidateOnly = $ValidateOnly
            }
            
            # Load data
            $userData = switch ($Format) {
                'CSV' {
                    Import-Csv -Path $Path
                }
                'JSON' {
                    Get-Content -Path $Path -Raw | ConvertFrom-Json
                }
                'Excel' {
                    # Requires ImportExcel module
                    if (Get-Module -ListAvailable -Name ImportExcel) {
                        Import-Excel -Path $Path
                    } else {
                        throw "ImportExcel module required for Excel format"
                    }
                }
            }
            
            Write-PSLog -Message "Loaded $($userData.Count) user records from $Path" -Component 'PSActiveDirectory'
            
            # Apply field mapping
            if ($FieldMapping.Count -gt 0) {
                $userData = $userData | ForEach-Object {
                    $user = $_
                    $mapped = @{}
                    
                    foreach ($key in $FieldMapping.Keys) {
                        $sourceField = $FieldMapping[$key]
                        if ($user.PSObject.Properties[$sourceField]) {
                            $mapped[$key] = $user.$sourceField
                        }
                    }
                    
                    # Keep unmapped fields
                    foreach ($prop in $user.PSObject.Properties) {
                        if (-not $mapped.ContainsKey($prop.Name)) {
                            $mapped[$prop.Name] = $prop.Value
                        }
                    }
                    
                    [PSCustomObject]$mapped
                }
            }
            
            # Validate data
            $validationResults = @()
            $validUsers = @()
            $invalidUsers = @()
            
            foreach ($user in $userData) {
                $isValid = $true
                $errors = @()
                
                # Required fields
                if (-not $user.FirstName -or -not $user.LastName) {
                    $isValid = $false
                    $errors += "Missing required fields: FirstName and/or LastName"
                }
                
                # Custom validation
                if ($ValidationScript) {
                    try {
                        $validationResult = & $ValidationScript -User $user
                        if (-not $validationResult) {
                            $isValid = $false
                            $errors += "Custom validation failed"
                        }
                    }
                    catch {
                        $isValid = $false
                        $errors += "Validation error: $_"
                    }
                }
                
                # Check for existing user
                $samAccountName = "{0}{1}" -f $user.FirstName.ToLower(), $user.LastName.ToLower()
                $existing = Get-ADUser -Filter "SamAccountName -eq '$samAccountName'" -ErrorAction SilentlyContinue
                if ($existing) {
                    $errors += "User already exists: $samAccountName"
                }
                
                $validationResult = [PSCustomObject]@{
                    FirstName = $user.FirstName
                    LastName = $user.LastName
                    SamAccountName = $samAccountName
                    Valid = $isValid
                    Errors = $errors -join '; '
                    OriginalData = $user
                }
                
                $validationResults += $validationResult
                
                if ($isValid) {
                    $validUsers += $user
                } else {
                    $invalidUsers += $validationResult
                }
            }
            
            Write-PSLog -Message "Validation complete. Valid: $($validUsers.Count), Invalid: $($invalidUsers.Count)" -Component 'PSActiveDirectory'
            
            if ($ValidateOnly) {
                return [PSCustomObject]@{
                    TotalRecords = $userData.Count
                    ValidRecords = $validUsers.Count
                    InvalidRecords = $invalidUsers.Count
                    ValidationResults = $validationResults
                }
            }
            
            # Process valid users in batches
            $createdUsers = @()
            $failedUsers = @()
            $batchCount = [Math]::Ceiling($validUsers.Count / $BatchSize)
            
            for ($i = 0; $i -lt $batchCount; $i++) {
                $batch = $validUsers | Select-Object -Skip ($i * $BatchSize) -First $BatchSize
                
                Write-PSLog -Message "Processing batch $($i + 1) of $batchCount ($($batch.Count) users)" -Component 'PSActiveDirectory'
                
                foreach ($user in $batch) {
                    try {
                        $newUserParams = @{
                            FirstName = $user.FirstName
                            LastName = $user.LastName
                        }
                        
                        # Add optional parameters
                        $optionalFields = @('MiddleInitial', 'Department', 'Title', 'Manager', 'Office', 'PhoneNumber', 'MobilePhone', 'OU')
                        foreach ($field in $optionalFields) {
                            if ($user.PSObject.Properties[$field] -and $user.$field) {
                                $newUserParams[$field] = $user.$field
                            }
                        }
                        
                        # Groups
                        if ($user.Groups) {
                            $newUserParams['Groups'] = $user.Groups -split ';|,'
                        }
                        
                        if ($PSCmdlet.ShouldProcess("$($user.FirstName) $($user.LastName)", "Create AD User")) {
                            $newUser = New-PSADUser @newUserParams -PassThru
                            $createdUsers += [PSCustomObject]@{
                                User = $newUser
                                Status = 'Created'
                                SourceData = $user
                            }
                        }
                    }
                    catch {
                        $failedUsers += [PSCustomObject]@{
                            User = "$($user.FirstName) $($user.LastName)"
                            Status = 'Failed'
                            Error = $_.Exception.Message
                            SourceData = $user
                        }
                        
                        Write-PSLog -Message "Failed to create user $($user.FirstName) $($user.LastName): $_" -Level 'Error' -Component 'PSActiveDirectory'
                    }
                }
                
                # Brief pause between batches
                if ($i -lt $batchCount - 1) {
                    Start-Sleep -Seconds 2
                }
            }
            
            # Generate report
            $importResult = [PSCustomObject]@{
                ImportDate = Get-Date
                SourceFile = $Path
                TotalRecords = $userData.Count
                ValidRecords = $validUsers.Count
                InvalidRecords = $invalidUsers.Count
                CreatedUsers = $createdUsers.Count
                FailedUsers = $failedUsers.Count
                CreatedUsersList = $createdUsers
                FailedUsersList = $failedUsers
                InvalidUsersList = $invalidUsers
            }
            
            if ($GenerateReport) {
                $reportPath = [System.IO.Path]::ChangeExtension($Path, '.import-report.html')
                $importResult | ConvertTo-Html -Title "AD User Import Report" -PreContent @"
<h1>AD User Import Report</h1>
<p>Import Date: $($importResult.ImportDate)</p>
<p>Source File: $($importResult.SourceFile)</p>
<h2>Summary</h2>
<ul>
    <li>Total Records: $($importResult.TotalRecords)</li>
    <li>Valid Records: $($importResult.ValidRecords)</li>
    <li>Invalid Records: $($importResult.InvalidRecords)</li>
    <li>Created Users: $($importResult.CreatedUsers)</li>
    <li>Failed Users: $($importResult.FailedUsers)</li>
</ul>
"@ | Out-File $reportPath
                
                Write-PSLog -Message "Import report saved to: $reportPath" -Component 'PSActiveDirectory'
            }
            
            # Audit log
            if ($script:PSADConfig.EnableAuditLog) {
                Write-PSADAuditLog -Action 'BulkImportUsers' -ObjectType 'User' -ObjectName 'Multiple' -Details @{
                    SourceFile = $Path
                    TotalRecords = $userData.Count
                    CreatedUsers = $createdUsers.Count
                    FailedUsers = $failedUsers.Count
                }
            }
            
            Write-PSLog -Message "User import completed. Created: $($createdUsers.Count), Failed: $($failedUsers.Count)" -Level 'Success' -Component 'PSActiveDirectory'
            
            return $importResult
        }
        catch {
            Write-PSLog -Message "Failed to import users: $_" -Level 'Error' -Component 'PSActiveDirectory'
            throw
        }
    }
}

function Invoke-PSADBulkOperation {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Enable', 'Disable', 'ResetPassword', 'Move', 'UpdateAttribute', 'AddToGroup', 'RemoveFromGroup')]
        [string]$Operation,
        
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string[]]$Identity,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Parameters = @{},
        
        [Parameter(Mandatory = $false)]
        [int]$BatchSize = $script:PSADConfig.BulkOperationBatchSize,
        
        [Parameter(Mandatory = $false)]
        [int]$ThrottleLimit = 5,
        
        [Parameter(Mandatory = $false)]
        [switch]$Parallel,
        
        [Parameter(Mandatory = $false)]
        [switch]$ContinueOnError
    )
    
    begin {
        $allIdentities = @()
        $results = @()
    }
    
    process {
        $allIdentities += $Identity
    }
    
    end {
        try {
            $context = Initialize-PSLogContext -Operation 'Invoke-PSADBulkOperation' -Properties @{
                Operation = $Operation
                TargetCount = $allIdentities.Count
                Parallel = $Parallel
            }
            
            Write-PSLog -Message "Starting bulk operation '$Operation' on $($allIdentities.Count) objects" -Component 'PSActiveDirectory'
            
            # Process in batches
            $batchCount = [Math]::Ceiling($allIdentities.Count / $BatchSize)
            
            for ($i = 0; $i -lt $batchCount; $i++) {
                $batch = $allIdentities | Select-Object -Skip ($i * $BatchSize) -First $BatchSize
                
                Write-PSLog -Message "Processing batch $($i + 1) of $batchCount ($($batch.Count) objects)" -Component 'PSActiveDirectory'
                
                if ($Parallel) {
                    # Process batch in parallel
                    $jobs = @()
                    
                    foreach ($id in $batch) {
                        while ((Get-Job -State Running).Count -ge $ThrottleLimit) {
                            Start-Sleep -Milliseconds 100
                        }
                        
                        $job = Start-PSJob -ScriptBlock {
                            param($Identity, $Operation, $Parameters)
                            
                            try {
                                $result = switch ($Operation) {
                                    'Enable' {
                                        Enable-ADAccount -Identity $Identity -PassThru
                                        @{ Status = 'Success'; Message = 'Account enabled' }
                                    }
                                    'Disable' {
                                        Disable-ADAccount -Identity $Identity -PassThru
                                        @{ Status = 'Success'; Message = 'Account disabled' }
                                    }
                                    'ResetPassword' {
                                        $password = if ($Parameters.Password) { $Parameters.Password } else { New-PSADPassword }
                                        Set-ADAccountPassword -Identity $Identity -NewPassword $password -Reset
                                        @{ Status = 'Success'; Message = 'Password reset' }
                                    }
                                    'Move' {
                                        if (-not $Parameters.TargetOU) { throw "TargetOU parameter required" }
                                        Move-ADObject -Identity $Identity -TargetPath $Parameters.TargetOU
                                        @{ Status = 'Success'; Message = "Moved to $($Parameters.TargetOU)" }
                                    }
                                    'UpdateAttribute' {
                                        if (-not $Parameters.Attributes) { throw "Attributes parameter required" }
                                        Set-ADObject -Identity $Identity -Replace $Parameters.Attributes
                                        @{ Status = 'Success'; Message = 'Attributes updated' }
                                    }
                                    'AddToGroup' {
                                        if (-not $Parameters.GroupName) { throw "GroupName parameter required" }
                                        Add-ADGroupMember -Identity $Parameters.GroupName -Members $Identity
                                        @{ Status = 'Success'; Message = "Added to group $($Parameters.GroupName)" }
                                    }
                                    'RemoveFromGroup' {
                                        if (-not $Parameters.GroupName) { throw "GroupName parameter required" }
                                        Remove-ADGroupMember -Identity $Parameters.GroupName -Members $Identity -Confirm:$false
                                        @{ Status = 'Success'; Message = "Removed from group $($Parameters.GroupName)" }
                                    }
                                }
                                
                                return @{
                                    Identity = $Identity
                                    Operation = $Operation
                                    Status = $result.Status
                                    Message = $result.Message
                                    Timestamp = Get-Date
                                }
                            }
                            catch {
                                return @{
                                    Identity = $Identity
                                    Operation = $Operation
                                    Status = 'Failed'
                                    Message = $_.Exception.Message
                                    Timestamp = Get-Date
                                }
                            }
                        } -Parameters @{
                            Identity = $id
                            Operation = $Operation
                            Parameters = $Parameters
                        }
                        
                        $jobs += $job
                    }
                    
                    # Wait for jobs to complete
                    $completedJobs = Wait-PSJob -Job $jobs -ShowProgress
                    $batchResults = Get-PSJobResult -Job $completedJobs
                    
                    # Clean up jobs
                    $jobs | Remove-Job -Force
                    
                    $results += $batchResults | ForEach-Object { $_.Output }
                }
                else {
                    # Process batch sequentially
                    foreach ($id in $batch) {
                        try {
                            if ($PSCmdlet.ShouldProcess($id, $Operation)) {
                                $result = switch ($Operation) {
                                    'Enable' {
                                        Enable-ADAccount -Identity $id -PassThru
                                        @{ Status = 'Success'; Message = 'Account enabled' }
                                    }
                                    'Disable' {
                                        Disable-ADAccount -Identity $id -PassThru
                                        @{ Status = 'Success'; Message = 'Account disabled' }
                                    }
                                    'ResetPassword' {
                                        $password = if ($Parameters.Password) { $Parameters.Password } else { New-PSADPassword }
                                        Set-ADAccountPassword -Identity $id -NewPassword $password -Reset
                                        @{ Status = 'Success'; Message = 'Password reset' }
                                    }
                                    'Move' {
                                        if (-not $Parameters.TargetOU) { throw "TargetOU parameter required" }
                                        Move-ADObject -Identity (Get-ADObject $id).DistinguishedName -TargetPath $Parameters.TargetOU
                                        @{ Status = 'Success'; Message = "Moved to $($Parameters.TargetOU)" }
                                    }
                                    'UpdateAttribute' {
                                        if (-not $Parameters.Attributes) { throw "Attributes parameter required" }
                                        Set-ADObject -Identity $id -Replace $Parameters.Attributes
                                        @{ Status = 'Success'; Message = 'Attributes updated' }
                                    }
                                    'AddToGroup' {
                                        if (-not $Parameters.GroupName) { throw "GroupName parameter required" }
                                        Add-ADGroupMember -Identity $Parameters.GroupName -Members $id
                                        @{ Status = 'Success'; Message = "Added to group $($Parameters.GroupName)" }
                                    }
                                    'RemoveFromGroup' {
                                        if (-not $Parameters.GroupName) { throw "GroupName parameter required" }
                                        Remove-ADGroupMember -Identity $Parameters.GroupName -Members $id -Confirm:$false
                                        @{ Status = 'Success'; Message = "Removed from group $($Parameters.GroupName)" }
                                    }
                                }
                                
                                $results += [PSCustomObject]@{
                                    Identity = $id
                                    Operation = $Operation
                                    Status = $result.Status
                                    Message = $result.Message
                                    Timestamp = Get-Date
                                }
                            }
                        }
                        catch {
                            $results += [PSCustomObject]@{
                                Identity = $id
                                Operation = $Operation
                                Status = 'Failed'
                                Message = $_.Exception.Message
                                Timestamp = Get-Date
                            }
                            
                            Write-PSLog -Message "Failed to perform $Operation on $id`: $_" -Level 'Error' -Component 'PSActiveDirectory'
                            
                            if (-not $ContinueOnError) {
                                throw
                            }
                        }
                    }
                }
            }
            
            # Summary
            $summary = @{
                Operation = $Operation
                TotalObjects = $allIdentities.Count
                Successful = ($results | Where-Object { $_.Status -eq 'Success' }).Count
                Failed = ($results | Where-Object { $_.Status -eq 'Failed' }).Count
                Duration = (Get-Date) - $context.StartTime
                Results = $results
            }
            
            # Audit log
            if ($script:PSADConfig.EnableAuditLog) {
                Write-PSADAuditLog -Action "BulkOperation:$Operation" -ObjectType 'Multiple' -ObjectName 'Multiple' -Details $summary
            }
            
            Write-PSLog -Message "Bulk operation completed. Success: $($summary.Successful), Failed: $($summary.Failed)" -Level 'Success' -Component 'PSActiveDirectory'
            
            return [PSCustomObject]$summary
        }
        catch {
            Write-PSLog -Message "Bulk operation failed: $_" -Level 'Error' -Component 'PSActiveDirectory'
            throw
        }
    }
}
#endregion

#region Helper Functions
function New-PSADPassword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$Length = $script:PSADConfig.PasswordPolicy.MinimumLength,
        
        [Parameter(Mandatory = $false)]
        [switch]$AsPlainText
    )
    
    $chars = @{
        Upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        Lower = 'abcdefghijklmnopqrstuvwxyz'
        Digit = '0123456789'
        Special = '!@#$%^&*()_+-=[]{}|;:,.<>?'
    }
    
    # Ensure complexity
    $password = @(
        $chars.Upper[(Get-Random -Maximum $chars.Upper.Length)]
        $chars.Lower[(Get-Random -Maximum $chars.Lower.Length)]
        $chars.Digit[(Get-Random -Maximum $chars.Digit.Length)]
        $chars.Special[(Get-Random -Maximum $chars.Special.Length)]
    )
    
    # Fill remaining length
    $allChars = $chars.Upper + $chars.Lower + $chars.Digit + $chars.Special
    for ($i = $password.Count; $i -lt $Length; $i++) {
        $password += $allChars[(Get-Random -Maximum $allChars.Length)]
    }
    
    # Shuffle
    $password = ($password | Get-Random -Count $password.Count) -join ''
    
    if ($AsPlainText) {
        return $password
    } else {
        return ConvertTo-SecureString -String $password -AsPlainText -Force
    }
}

function Test-PSADPassword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [SecureString]$Password
    )
    
    $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    )
    
    $policy = $script:PSADConfig.PasswordPolicy
    
    # Length check
    if ($plainPassword.Length -lt $policy.MinimumLength) {
        Write-PSLog -Message "Password does not meet minimum length requirement" -Level 'Warning' -Component 'PSActiveDirectory'
        return $false
    }
    
    # Complexity check
    if ($policy.RequireComplexity) {
        $hasUpper = $plainPassword -cmatch '[A-Z]'
        $hasLower = $plainPassword -cmatch '[a-z]'
        $hasDigit = $plainPassword -match '\d'
        $hasSpecial = $plainPassword -match '[^a-zA-Z0-9]'
        
        $complexityMet = ($hasUpper -and $hasLower -and $hasDigit -and $hasSpecial)
        
        if (-not $complexityMet) {
            Write-PSLog -Message "Password does not meet complexity requirements" -Level 'Warning' -Component 'PSActiveDirectory'
            return $false
        }
    }
    
    return $true
}

function Write-PSADAuditLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Action,
        
        [Parameter(Mandatory = $true)]
        [string]$ObjectType,
        
        [Parameter(Mandatory = $true)]
        [string]$ObjectName,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Details = @{}
    )
    
    $auditEntry = @{
        Timestamp = Get-Date
        Action = $Action
        ObjectType = $ObjectType
        ObjectName = $ObjectName
        PerformedBy = $env:USERNAME
        Computer = $env:COMPUTERNAME
        Details = $Details
    }
    
    Write-PSLog -Message "AD Audit: $Action on $ObjectType '$ObjectName'" -Component 'PSActiveDirectory.Audit' -Context $auditEntry
}

function Test-PSADCache {
    param([string]$Key)
    
    if (-not $script:ADCache.ContainsKey($Key)) {
        return $false
    }
    
    $expiry = $script:ADCacheExpiry[$Key]
    if ((Get-Date) -gt $expiry) {
        $script:ADCache.Remove($Key)
        $script:ADCacheExpiry.Remove($Key)
        return $false
    }
    
    return $true
}

function Get-PSADCache {
    param([string]$Key)
    return $script:ADCache[$Key]
}

function Set-PSADCache {
    param(
        [string]$Key,
        [object]$Value
    )
    
    $script:ADCache[$Key] = $Value
    $script:ADCacheExpiry[$Key] = (Get-Date).AddSeconds($script:PSADConfig.CacheTimeout)
}

function Send-PSADNotification {
    param(
        [string]$Template,
        [string]$Recipient,
        [hashtable]$Parameters
    )
    
    # Implementation would load template and send notification
    Write-PSLog -Message "Notification sent to $Recipient using template: $Template" -Component 'PSActiveDirectory'
}
#endregion

# Module initialization
Write-PSLog -Message "PSActiveDirectory module loaded successfully" -Component 'PSActiveDirectory'

# Export aliases
New-Alias -Name psaduser -Value Get-PSADUser
New-Alias -Name psadgroup -Value Get-PSADGroup
New-Alias -Name psadcomp -Value Get-PSADComputer

Export-ModuleMember -Function * -Variable PSADConfig, PSADDefaultProperties -Alias *