#Requires -Version 5.1
#Requires -Modules PSAutomationCore, PSConfigurationManager

<#
.SYNOPSIS
    PSBackupService - Enterprise backup service with plugin architecture
.DESCRIPTION
    Provides comprehensive backup capabilities using the new service-oriented
    architecture with support for multiple backup providers, policies, and
    advanced features like deduplication and compression.
.NOTES
    Author: Enterprise Automation Team
    Version: 2.0.0
#>

using module PSAutomationCore
using module PSConfigurationManager

# Module-level variables
$script:BackupService = $null
$script:BackupProviders = @{}
$script:BackupJobs = @{}
$script:BackupPolicies = @{}

#region Service Initialization

function Initialize-BackupService {
    <#
    .SYNOPSIS
        Initializes the backup service with dependency injection
    .DESCRIPTION
        Sets up the backup service using the PSAutomationCore platform,
        registering services, loading configuration, and initializing providers.
    .PARAMETER ConfigurationPath
        Path to backup service configuration
    .PARAMETER LoadProviders
        Automatically load available backup providers
    .EXAMPLE
        Initialize-BackupService -ConfigurationPath ".\backup-config.json"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ConfigurationPath = (Join-Path $PSScriptRoot "Configuration"),
        
        [Parameter(Mandatory = $false)]
        [switch]$LoadProviders = $true
    )
    
    try {
        Write-AutomationLog -Message "Initializing Backup Service" -Level Info
        
        # Initialize the automation platform if not already done
        if (-not (Test-AutomationPlatform)) {
            Initialize-AutomationPlatform -ConfigurationPath $ConfigurationPath
        }
        
        # Register backup service
        Register-Service -ServiceType 'IBackupService' -Implementation 'BackupService' -Lifetime Singleton
        
        # Load backup configuration
        $config = Get-Configuration -Section "Backup"
        
        # Initialize service instance
        $script:BackupService = [PSCustomObject]@{
            Status = 'Initialized'
            StartTime = Get-Date
            Configuration = $config
            Providers = @{}
            Jobs = @{}
            Policies = @{}
            Statistics = @{
                TotalBackups = 0
                SuccessfulBackups = 0
                FailedBackups = 0
                TotalDataSize = 0
                CompressedSize = 0
                LastBackupTime = $null
            }
        }
        
        # Register performance counters
        Register-PerformanceCounter -Category "BackupService" -Counters @(
            "BackupsPerMinute"
            "DataThroughputMBps"
            "CompressionRatio"
            "ActiveJobs"
            "QueuedJobs"
        )
        
        # Load backup providers
        if ($LoadProviders) {
            Load-BackupProviders
        }
        
        # Initialize backup storage
        Initialize-BackupStorage -Config $config
        
        # Start background maintenance
        Start-BackupMaintenance
        
        Write-AutomationLog -Message "Backup Service initialized successfully" -Level Success
        
        return $script:BackupService
        
    } catch {
        Write-AutomationLog -Message "Failed to initialize Backup Service: $_" -Level Error
        throw
    }
}

function Start-BackupService {
    <#
    .SYNOPSIS
        Starts the backup service and begins processing jobs
    .DESCRIPTION
        Activates the backup service, starts job processing, and enables
        scheduled backups according to defined policies.
    .PARAMETER ProcessExistingJobs
        Process any existing queued jobs
    .EXAMPLE
        Start-BackupService -ProcessExistingJobs
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$ProcessExistingJobs
    )
    
    try {
        if (-not $script:BackupService) {
            throw "Backup service not initialized. Run Initialize-BackupService first."
        }
        
        Write-AutomationLog -Message "Starting Backup Service" -Level Info
        
        # Update service status
        $script:BackupService.Status = 'Running'
        
        # Start job processor
        Start-JobProcessor
        
        # Enable scheduled backups
        Enable-ScheduledBackups
        
        # Process existing jobs if requested
        if ($ProcessExistingJobs) {
            $queuedJobs = Get-BackupJob -Status Queued
            foreach ($job in $queuedJobs) {
                Start-BackupJob -JobId $job.Id
            }
        }
        
        # Start monitoring
        Start-BackupMonitoring
        
        Write-AutomationLog -Message "Backup Service started successfully" -Level Success
        
    } catch {
        Write-AutomationLog -Message "Failed to start Backup Service: $_" -Level Error
        throw
    }
}

#endregion

#region Backup Operations

function New-BackupJob {
    <#
    .SYNOPSIS
        Creates a new backup job
    .DESCRIPTION
        Creates a backup job with specified parameters, policy, and provider.
        Jobs can be executed immediately or queued for later processing.
    .PARAMETER Name
        Name of the backup job
    .PARAMETER Source
        Source path(s) to backup
    .PARAMETER Destination
        Destination for backup
    .PARAMETER Policy
        Backup policy to apply
    .PARAMETER Provider
        Backup provider to use
    .PARAMETER Schedule
        Schedule for recurring backups
    .PARAMETER Priority
        Job priority (Low, Normal, High, Critical)
    .PARAMETER Tags
        Tags for categorization
    .EXAMPLE
        New-BackupJob -Name "Database Backup" -Source "C:\Database" -Policy "Daily" -Provider "FileSystem"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [string[]]$Source,
        
        [Parameter(Mandatory = $true)]
        [string]$Destination,
        
        [Parameter(Mandatory = $false)]
        [string]$Policy = "Default",
        
        [Parameter(Mandatory = $false)]
        [string]$Provider = "FileSystem",
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Schedule,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Low', 'Normal', 'High', 'Critical')]
        [string]$Priority = 'Normal',
        
        [Parameter(Mandatory = $false)]
        [string[]]$Tags = @(),
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Options = @{}
    )
    
    try {
        Write-AutomationLog -Message "Creating backup job: $Name" -Level Info
        
        # Validate provider
        if (-not $script:BackupProviders.ContainsKey($Provider)) {
            throw "Backup provider '$Provider' not found"
        }
        
        # Get policy
        $backupPolicy = Get-BackupPolicy -Name $Policy
        if (-not $backupPolicy) {
            throw "Backup policy '$Policy' not found"
        }
        
        # Create job ID
        $jobId = [guid]::NewGuid().ToString()
        
        # Create job object
        $job = [PSCustomObject]@{
            Id = $jobId
            Name = $Name
            Source = $Source
            Destination = $Destination
            Provider = $Provider
            Policy = $backupPolicy
            Schedule = $Schedule
            Priority = $Priority
            Tags = $Tags
            Options = $Options
            Status = 'Created'
            CreatedAt = Get-Date
            LastRun = $null
            NextRun = $null
            Statistics = @{
                TotalRuns = 0
                SuccessfulRuns = 0
                FailedRuns = 0
                LastDuration = $null
                AverageDataSize = 0
                AverageCompressionRatio = 0
            }
        }
        
        # Validate job with provider
        $provider = $script:BackupProviders[$Provider]
        if ($provider.ValidateJob) {
            $validation = & $provider.ValidateJob $job
            if (-not $validation.IsValid) {
                throw "Job validation failed: $($validation.Errors -join ', ')"
            }
        }
        
        # Register job
        $script:BackupJobs[$jobId] = $job
        
        # Setup schedule if provided
        if ($Schedule) {
            New-BackupSchedule -JobId $jobId -Schedule $Schedule
        }
        
        # Log creation
        Write-AutomationLog -Message "Backup job created successfully" -Level Success -Metadata @{
            JobId = $jobId
            Name = $Name
            Provider = $Provider
            Policy = $Policy
        }
        
        return $job
        
    } catch {
        Write-AutomationLog -Message "Failed to create backup job: $_" -Level Error
        throw
    }
}

function Start-BackupJob {
    <#
    .SYNOPSIS
        Starts a backup job
    .DESCRIPTION
        Executes a backup job using the configured provider and policy.
        Supports both synchronous and asynchronous execution.
    .PARAMETER JobId
        ID of the job to start
    .PARAMETER JobName
        Name of the job to start
    .PARAMETER Async
        Run job asynchronously
    .PARAMETER Force
        Force job execution even if recently run
    .EXAMPLE
        Start-BackupJob -JobName "Database Backup" -Async
    #>
    [CmdletBinding(DefaultParameterSetName = 'ById')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
        [string]$JobId,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'ByName')]
        [string]$JobName,
        
        [Parameter(Mandatory = $false)]
        [switch]$Async,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    try {
        # Get job
        if ($PSCmdlet.ParameterSetName -eq 'ByName') {
            $job = Get-BackupJob -Name $JobName
            if (-not $job) {
                throw "Backup job '$JobName' not found"
            }
            $JobId = $job.Id
        } else {
            $job = $script:BackupJobs[$JobId]
            if (-not $job) {
                throw "Backup job with ID '$JobId' not found"
            }
        }
        
        Write-AutomationLog -Message "Starting backup job: $($job.Name)" -Level Info
        
        # Check if already running
        if ($job.Status -eq 'Running') {
            throw "Job is already running"
        }
        
        # Check if recently run (unless forced)
        if (-not $Force -and $job.LastRun) {
            $policy = $job.Policy
            if ($policy.MinimumInterval) {
                $timeSinceLastRun = (Get-Date) - $job.LastRun
                if ($timeSinceLastRun.TotalMinutes -lt $policy.MinimumInterval) {
                    throw "Job was run $([int]$timeSinceLastRun.TotalMinutes) minutes ago. Minimum interval is $($policy.MinimumInterval) minutes"
                }
            }
        }
        
        # Create execution context
        $executionContext = [PSCustomObject]@{
            JobId = $JobId
            Job = $job
            StartTime = Get-Date
            EndTime = $null
            Status = 'Running'
            Progress = 0
            CurrentOperation = 'Initializing'
            Errors = @()
            Warnings = @()
            Statistics = @{
                FilesProcessed = 0
                BytesProcessed = 0
                BytesCompressed = 0
                Duration = $null
            }
        }
        
        # Update job status
        $job.Status = 'Running'
        $job.LastRun = $executionContext.StartTime
        
        # Get provider
        $provider = $script:BackupProviders[$job.Provider]
        
        if ($Async) {
            # Start async job
            $scriptBlock = {
                param($Context, $Provider)
                
                try {
                    # Execute backup
                    $result = & $Provider.ExecuteBackup $Context
                    $Context.Status = 'Completed'
                    $Context.EndTime = Get-Date
                    $Context.Statistics = $result.Statistics
                } catch {
                    $Context.Status = 'Failed'
                    $Context.Errors += $_.Exception.Message
                    throw
                }
            }
            
            $asyncJob = Start-Job -ScriptBlock $scriptBlock -ArgumentList $executionContext, $provider
            $executionContext.AsyncJobId = $asyncJob.Id
            
            Write-AutomationLog -Message "Backup job started asynchronously" -Level Info -Metadata @{
                JobId = $JobId
                AsyncJobId = $asyncJob.Id
            }
            
        } else {
            # Execute synchronously
            try {
                # Pre-execution hooks
                Invoke-BackupHook -Job $job -Hook 'PreBackup' -Context $executionContext
                
                # Execute backup
                $result = & $provider.ExecuteBackup $executionContext
                
                # Update context
                $executionContext.Status = 'Completed'
                $executionContext.EndTime = Get-Date
                $executionContext.Statistics = $result.Statistics
                
                # Post-execution hooks
                Invoke-BackupHook -Job $job -Hook 'PostBackup' -Context $executionContext
                
                # Update job statistics
                Update-BackupJobStatistics -Job $job -Context $executionContext
                
                Write-AutomationLog -Message "Backup job completed successfully" -Level Success -Metadata @{
                    JobId = $JobId
                    Duration = ($executionContext.EndTime - $executionContext.StartTime).TotalSeconds
                    BytesProcessed = $executionContext.Statistics.BytesProcessed
                }
                
            } catch {
                $executionContext.Status = 'Failed'
                $executionContext.Errors += $_.Exception.Message
                
                # Error hooks
                Invoke-BackupHook -Job $job -Hook 'OnError' -Context $executionContext
                
                Write-AutomationLog -Message "Backup job failed: $_" -Level Error
                throw
            } finally {
                # Update job status
                $job.Status = $executionContext.Status
                
                # Cleanup
                Invoke-BackupHook -Job $job -Hook 'Cleanup' -Context $executionContext
            }
        }
        
        return $executionContext
        
    } catch {
        Write-AutomationLog -Message "Failed to start backup job: $_" -Level Error
        throw
    }
}

#endregion

#region Backup Policies

function New-BackupPolicy {
    <#
    .SYNOPSIS
        Creates a new backup policy
    .DESCRIPTION
        Defines a backup policy with retention rules, compression settings,
        encryption options, and other parameters.
    .PARAMETER Name
        Policy name
    .PARAMETER RetentionDays
        Number of days to retain backups
    .PARAMETER RetentionCount
        Number of backup sets to retain
    .PARAMETER Compression
        Enable compression
    .PARAMETER CompressionLevel
        Compression level (Fastest, Fast, Normal, Maximum, Ultra)
    .PARAMETER Encryption
        Enable encryption
    .PARAMETER EncryptionAlgorithm
        Encryption algorithm
    .PARAMETER Deduplication
        Enable deduplication
    .PARAMETER VerifyBackup
        Verify backup after completion
    .PARAMETER MinimumInterval
        Minimum interval between backups (minutes)
    .EXAMPLE
        New-BackupPolicy -Name "Weekly" -RetentionDays 30 -Compression -CompressionLevel Maximum
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [int]$RetentionDays = 30,
        
        [Parameter(Mandatory = $false)]
        [int]$RetentionCount = 10,
        
        [Parameter(Mandatory = $false)]
        [switch]$Compression,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Fastest', 'Fast', 'Normal', 'Maximum', 'Ultra')]
        [string]$CompressionLevel = 'Normal',
        
        [Parameter(Mandatory = $false)]
        [switch]$Encryption,
        
        [Parameter(Mandatory = $false)]
        [string]$EncryptionAlgorithm = 'AES256',
        
        [Parameter(Mandatory = $false)]
        [switch]$Deduplication,
        
        [Parameter(Mandatory = $false)]
        [switch]$VerifyBackup = $true,
        
        [Parameter(Mandatory = $false)]
        [int]$MinimumInterval = 60,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$AdvancedOptions = @{}
    )
    
    try {
        Write-AutomationLog -Message "Creating backup policy: $Name" -Level Info
        
        # Check if policy exists
        if ($script:BackupPolicies.ContainsKey($Name)) {
            throw "Backup policy '$Name' already exists"
        }
        
        # Create policy object
        $policy = [PSCustomObject]@{
            Name = $Name
            RetentionDays = $RetentionDays
            RetentionCount = $RetentionCount
            Compression = @{
                Enabled = $Compression.IsPresent
                Level = $CompressionLevel
            }
            Encryption = @{
                Enabled = $Encryption.IsPresent
                Algorithm = $EncryptionAlgorithm
                KeyVaultName = $null
            }
            Deduplication = @{
                Enabled = $Deduplication.IsPresent
                BlockSize = 64KB
                Algorithm = 'SHA256'
            }
            Verification = @{
                Enabled = $VerifyBackup.IsPresent
                Type = 'Checksum'
                SampleRate = 100
            }
            MinimumInterval = $MinimumInterval
            AdvancedOptions = $AdvancedOptions
            CreatedAt = Get-Date
            ModifiedAt = Get-Date
        }
        
        # Validate policy
        $validation = Test-BackupPolicy -Policy $policy
        if (-not $validation.IsValid) {
            throw "Policy validation failed: $($validation.Errors -join ', ')"
        }
        
        # Register policy
        $script:BackupPolicies[$Name] = $policy
        
        # Save to configuration
        Save-BackupPolicy -Policy $policy
        
        Write-AutomationLog -Message "Backup policy created successfully" -Level Success -Metadata @{
            PolicyName = $Name
            RetentionDays = $RetentionDays
            Compression = $Compression.IsPresent
            Encryption = $Encryption.IsPresent
        }
        
        return $policy
        
    } catch {
        Write-AutomationLog -Message "Failed to create backup policy: $_" -Level Error
        throw
    }
}

function Test-BackupPolicy {
    <#
    .SYNOPSIS
        Validates a backup policy
    .DESCRIPTION
        Checks if a backup policy configuration is valid and compatible
        with the current environment.
    .PARAMETER Policy
        Policy object to validate
    .PARAMETER PolicyName
        Name of existing policy to validate
    .EXAMPLE
        Test-BackupPolicy -PolicyName "Weekly"
    #>
    [CmdletBinding(DefaultParameterSetName = 'ByObject')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'ByObject')]
        [PSCustomObject]$Policy,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'ByName')]
        [string]$PolicyName
    )
    
    try {
        # Get policy if name provided
        if ($PSCmdlet.ParameterSetName -eq 'ByName') {
            $Policy = Get-BackupPolicy -Name $PolicyName
            if (-not $Policy) {
                throw "Policy '$PolicyName' not found"
            }
        }
        
        $result = [PSCustomObject]@{
            IsValid = $true
            Errors = @()
            Warnings = @()
            Recommendations = @()
        }
        
        # Validate retention settings
        if ($Policy.RetentionDays -lt 1) {
            $result.IsValid = $false
            $result.Errors += "RetentionDays must be at least 1"
        }
        
        if ($Policy.RetentionCount -lt 1) {
            $result.IsValid = $false
            $result.Errors += "RetentionCount must be at least 1"
        }
        
        # Validate compression settings
        if ($Policy.Compression.Enabled) {
            if ($Policy.Compression.Level -notin @('Fastest', 'Fast', 'Normal', 'Maximum', 'Ultra')) {
                $result.IsValid = $false
                $result.Errors += "Invalid compression level"
            }
            
            if ($Policy.Compression.Level -eq 'Ultra') {
                $result.Warnings += "Ultra compression may significantly increase backup time"
            }
        }
        
        # Validate encryption settings
        if ($Policy.Encryption.Enabled) {
            if (-not $Policy.Encryption.Algorithm) {
                $result.IsValid = $false
                $result.Errors += "Encryption algorithm must be specified"
            }
            
            # Check if encryption is available
            if (-not (Test-EncryptionCapability -Algorithm $Policy.Encryption.Algorithm)) {
                $result.IsValid = $false
                $result.Errors += "Encryption algorithm '$($Policy.Encryption.Algorithm)' not available"
            }
        }
        
        # Validate deduplication settings
        if ($Policy.Deduplication.Enabled) {
            if ($Policy.Deduplication.BlockSize -lt 4KB -or $Policy.Deduplication.BlockSize -gt 1MB) {
                $result.Warnings += "Deduplication block size outside recommended range (4KB-1MB)"
            }
        }
        
        # Recommendations
        if (-not $Policy.Compression.Enabled -and -not $Policy.Deduplication.Enabled) {
            $result.Recommendations += "Consider enabling compression or deduplication to save storage space"
        }
        
        if ($Policy.RetentionDays -gt 365) {
            $result.Recommendations += "Long retention periods may consume significant storage"
        }
        
        return $result
        
    } catch {
        Write-AutomationLog -Message "Failed to validate backup policy: $_" -Level Error
        throw
    }
}

#endregion

#region Backup Providers

function Register-BackupProvider {
    <#
    .SYNOPSIS
        Registers a backup provider plugin
    .DESCRIPTION
        Registers a new backup provider that implements the IBackupProvider interface.
        Providers handle the actual backup operations for different storage types.
    .PARAMETER Name
        Provider name
    .PARAMETER Type
        Provider type
    .PARAMETER ScriptPath
        Path to provider implementation
    .PARAMETER Configuration
        Provider-specific configuration
    .EXAMPLE
        Register-BackupProvider -Name "AzureBlob" -Type "CloudStorage" -ScriptPath ".\Providers\AzureBlobProvider.ps1"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('FileSystem', 'CloudStorage', 'Database', 'Tape', 'NetworkShare', 'Custom')]
        [string]$Type,
        
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Configuration = @{}
    )
    
    try {
        Write-AutomationLog -Message "Registering backup provider: $Name" -Level Info
        
        # Check if provider already registered
        if ($script:BackupProviders.ContainsKey($Name)) {
            throw "Provider '$Name' already registered"
        }
        
        # Load provider script
        if (-not (Test-Path $ScriptPath)) {
            throw "Provider script not found: $ScriptPath"
        }
        
        $provider = . $ScriptPath
        
        # Validate provider interface
        $requiredMethods = @(
            'Initialize'
            'ValidateJob'
            'ExecuteBackup'
            'RestoreBackup'
            'GetCapabilities'
            'TestConnection'
        )
        
        foreach ($method in $requiredMethods) {
            if (-not $provider.$method) {
                throw "Provider missing required method: $method"
            }
        }
        
        # Initialize provider
        $initResult = & $provider.Initialize $Configuration
        if (-not $initResult.Success) {
            throw "Provider initialization failed: $($initResult.Error)"
        }
        
        # Get provider capabilities
        $capabilities = & $provider.GetCapabilities
        
        # Register provider
        $providerInfo = [PSCustomObject]@{
            Name = $Name
            Type = $Type
            ScriptPath = $ScriptPath
            Configuration = $Configuration
            Capabilities = $capabilities
            Provider = $provider
            RegisteredAt = Get-Date
            Status = 'Active'
        }
        
        $script:BackupProviders[$Name] = $providerInfo
        
        # Register as plugin
        Register-Plugin -Name "BackupProvider.$Name" -Type 'BackupProvider' -Instance $provider
        
        Write-AutomationLog -Message "Backup provider registered successfully" -Level Success -Metadata @{
            Provider = $Name
            Type = $Type
            Capabilities = $capabilities.Features -join ', '
        }
        
        return $providerInfo
        
    } catch {
        Write-AutomationLog -Message "Failed to register backup provider: $_" -Level Error
        throw
    }
}

function Test-BackupProvider {
    <#
    .SYNOPSIS
        Tests a backup provider connection and capabilities
    .DESCRIPTION
        Verifies that a backup provider is properly configured and can
        perform backup operations.
    .PARAMETER Name
        Provider name to test
    .PARAMETER TestBackup
        Perform a test backup operation
    .PARAMETER TestRestore
        Perform a test restore operation
    .EXAMPLE
        Test-BackupProvider -Name "AzureBlob" -TestBackup
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [switch]$TestBackup,
        
        [Parameter(Mandatory = $false)]
        [switch]$TestRestore
    )
    
    try {
        Write-AutomationLog -Message "Testing backup provider: $Name" -Level Info
        
        # Get provider
        $providerInfo = $script:BackupProviders[$Name]
        if (-not $providerInfo) {
            throw "Provider '$Name' not found"
        }
        
        $provider = $providerInfo.Provider
        $results = [PSCustomObject]@{
            Provider = $Name
            ConnectionTest = $null
            BackupTest = $null
            RestoreTest = $null
            OverallStatus = 'Unknown'
            Timestamp = Get-Date
        }
        
        # Test connection
        Write-AutomationLog -Message "Testing provider connection" -Level Debug
        $connectionResult = & $provider.TestConnection
        $results.ConnectionTest = $connectionResult
        
        if (-not $connectionResult.Success) {
            $results.OverallStatus = 'Failed'
            Write-AutomationLog -Message "Provider connection test failed" -Level Error
            return $results
        }
        
        # Test backup if requested
        if ($TestBackup) {
            Write-AutomationLog -Message "Performing test backup" -Level Debug
            
            # Create test data
            $testPath = New-TemporaryFile
            "Test backup data - $(Get-Date)" | Set-Content $testPath
            
            try {
                $testJob = [PSCustomObject]@{
                    Id = [guid]::NewGuid().ToString()
                    Name = "Test Backup"
                    Source = @($testPath.FullName)
                    Destination = "test-backup-$([guid]::NewGuid().ToString())"
                    Policy = [PSCustomObject]@{
                        Compression = @{ Enabled = $true; Level = 'Fast' }
                        Encryption = @{ Enabled = $false }
                        Verification = @{ Enabled = $true }
                    }
                }
                
                $testContext = [PSCustomObject]@{
                    Job = $testJob
                    StartTime = Get-Date
                }
                
                $backupResult = & $provider.ExecuteBackup $testContext
                $results.BackupTest = $backupResult
                
                if ($backupResult.Success) {
                    Write-AutomationLog -Message "Test backup successful" -Level Success
                } else {
                    Write-AutomationLog -Message "Test backup failed" -Level Error
                }
                
            } finally {
                Remove-Item $testPath -Force -ErrorAction SilentlyContinue
            }
        }
        
        # Test restore if requested
        if ($TestRestore -and $results.BackupTest -and $results.BackupTest.Success) {
            Write-AutomationLog -Message "Performing test restore" -Level Debug
            
            $restoreContext = [PSCustomObject]@{
                BackupSet = $results.BackupTest.BackupSet
                Destination = New-TemporaryFile
            }
            
            try {
                $restoreResult = & $provider.RestoreBackup $restoreContext
                $results.RestoreTest = $restoreResult
                
                if ($restoreResult.Success) {
                    Write-AutomationLog -Message "Test restore successful" -Level Success
                } else {
                    Write-AutomationLog -Message "Test restore failed" -Level Error
                }
                
            } finally {
                if (Test-Path $restoreContext.Destination) {
                    Remove-Item $restoreContext.Destination -Force -ErrorAction SilentlyContinue
                }
            }
        }
        
        # Determine overall status
        $results.OverallStatus = if ($results.ConnectionTest.Success -and 
                                    (!$TestBackup -or $results.BackupTest.Success) -and
                                    (!$TestRestore -or $results.RestoreTest.Success)) {
            'Success'
        } else {
            'Failed'
        }
        
        return $results
        
    } catch {
        Write-AutomationLog -Message "Failed to test backup provider: $_" -Level Error
        throw
    }
}

#endregion

#region Backup Storage Management

function Initialize-BackupStorage {
    <#
    .SYNOPSIS
        Initializes backup storage locations
    .DESCRIPTION
        Sets up and validates backup storage locations based on configuration.
        Creates necessary directory structures and validates permissions.
    .PARAMETER Config
        Backup configuration object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )
    
    try {
        Write-AutomationLog -Message "Initializing backup storage" -Level Info
        
        # Primary storage
        if ($Config.Storage.Primary) {
            $primary = $Config.Storage.Primary
            
            if ($primary.Type -eq 'FileSystem') {
                # Create directory if needed
                if (-not (Test-Path $primary.Path)) {
                    New-Item -Path $primary.Path -ItemType Directory -Force | Out-Null
                    Write-AutomationLog -Message "Created primary backup directory: $($primary.Path)" -Level Info
                }
                
                # Validate permissions
                $acl = Get-Acl $primary.Path
                $hasWrite = $false
                $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                
                foreach ($access in $acl.Access) {
                    if ($access.IdentityReference.Value -eq $currentUser -and 
                        $access.FileSystemRights -match 'Write') {
                        $hasWrite = $true
                        break
                    }
                }
                
                if (-not $hasWrite) {
                    throw "No write permission on primary backup path: $($primary.Path)"
                }
                
                # Create subdirectories
                $subdirs = @('Active', 'Archive', 'Staging', 'Logs')
                foreach ($subdir in $subdirs) {
                    $subdirPath = Join-Path $primary.Path $subdir
                    if (-not (Test-Path $subdirPath)) {
                        New-Item -Path $subdirPath -ItemType Directory -Force | Out-Null
                    }
                }
            }
        }
        
        # Secondary storage (if configured)
        if ($Config.Storage.Secondary) {
            foreach ($secondary in $Config.Storage.Secondary) {
                Write-AutomationLog -Message "Configuring secondary storage: $($secondary.Name)" -Level Info
                
                # Provider-specific initialization
                if ($secondary.Provider) {
                    $provider = Get-BackupProvider -Name $secondary.Provider
                    if ($provider -and $provider.InitializeStorage) {
                        & $provider.InitializeStorage $secondary
                    }
                }
            }
        }
        
        # Initialize deduplication store if enabled
        if ($Config.Features.Deduplication.Enabled) {
            Initialize-DeduplicationStore -Path (Join-Path $Config.Storage.Primary.Path "Dedup")
        }
        
        Write-AutomationLog -Message "Backup storage initialized successfully" -Level Success
        
    } catch {
        Write-AutomationLog -Message "Failed to initialize backup storage: $_" -Level Error
        throw
    }
}

function Optimize-BackupStorage {
    <#
    .SYNOPSIS
        Optimizes backup storage by cleaning up and reorganizing
    .DESCRIPTION
        Performs storage optimization including deduplication, compression
        of old backups, and removal of expired backup sets.
    .PARAMETER StoragePath
        Path to optimize (defaults to primary storage)
    .PARAMETER CompressOldBackups
        Compress backups older than specified days
    .PARAMETER RemoveExpired
        Remove expired backup sets
    .PARAMETER Defragment
        Defragment deduplication store
    .EXAMPLE
        Optimize-BackupStorage -CompressOldBackups 30 -RemoveExpired
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $false)]
        [string]$StoragePath,
        
        [Parameter(Mandatory = $false)]
        [int]$CompressOldBackups = 0,
        
        [Parameter(Mandatory = $false)]
        [switch]$RemoveExpired,
        
        [Parameter(Mandatory = $false)]
        [switch]$Defragment
    )
    
    try {
        Write-AutomationLog -Message "Starting backup storage optimization" -Level Info
        
        # Get storage path
        if (-not $StoragePath) {
            $StoragePath = $script:BackupService.Configuration.Storage.Primary.Path
        }
        
        $stats = [PSCustomObject]@{
            StartTime = Get-Date
            SpaceBefore = 0
            SpaceAfter = 0
            BackupsProcessed = 0
            BackupsCompressed = 0
            BackupsRemoved = 0
            Errors = @()
        }
        
        # Calculate initial space
        $stats.SpaceBefore = (Get-ChildItem $StoragePath -Recurse | 
            Measure-Object -Property Length -Sum).Sum
        
        # Remove expired backups
        if ($RemoveExpired) {
            Write-AutomationLog -Message "Removing expired backup sets" -Level Info
            
            $backupSets = Get-BackupSet -StoragePath $StoragePath
            foreach ($backupSet in $backupSets) {
                $policy = Get-BackupPolicy -Name $backupSet.PolicyName
                
                if ($policy) {
                    $expirationDate = $backupSet.CreatedAt.AddDays($policy.RetentionDays)
                    
                    if ($expirationDate -lt (Get-Date)) {
                        if ($PSCmdlet.ShouldProcess($backupSet.Id, "Remove expired backup set")) {
                            try {
                                Remove-BackupSet -Id $backupSet.Id -Force
                                $stats.BackupsRemoved++
                                Write-AutomationLog -Message "Removed expired backup set: $($backupSet.Id)" -Level Info
                            } catch {
                                $stats.Errors += "Failed to remove backup set $($backupSet.Id): $_"
                            }
                        }
                    }
                }
            }
        }
        
        # Compress old backups
        if ($CompressOldBackups -gt 0) {
            Write-AutomationLog -Message "Compressing backups older than $CompressOldBackups days" -Level Info
            
            $cutoffDate = (Get-Date).AddDays(-$CompressOldBackups)
            $backupsToCompress = Get-BackupSet -StoragePath $StoragePath | 
                Where-Object { $_.CreatedAt -lt $cutoffDate -and -not $_.IsCompressed }
            
            foreach ($backup in $backupsToCompress) {
                if ($PSCmdlet.ShouldProcess($backup.Id, "Compress backup set")) {
                    try {
                        Compress-BackupSet -Id $backup.Id
                        $stats.BackupsCompressed++
                        Write-AutomationLog -Message "Compressed backup set: $($backup.Id)" -Level Info
                    } catch {
                        $stats.Errors += "Failed to compress backup set $($backup.Id): $_"
                    }
                }
                $stats.BackupsProcessed++
            }
        }
        
        # Defragment deduplication store
        if ($Defragment) {
            Write-AutomationLog -Message "Defragmenting deduplication store" -Level Info
            
            $dedupPath = Join-Path $StoragePath "Dedup"
            if (Test-Path $dedupPath) {
                Optimize-DeduplicationStore -Path $dedupPath
            }
        }
        
        # Calculate final space
        $stats.SpaceAfter = (Get-ChildItem $StoragePath -Recurse | 
            Measure-Object -Property Length -Sum).Sum
        
        $stats.SpaceSaved = $stats.SpaceBefore - $stats.SpaceAfter
        $stats.Duration = (Get-Date) - $stats.StartTime
        
        # Log results
        Write-AutomationLog -Message "Storage optimization completed" -Level Success -Metadata @{
            SpaceSaved = "$([Math]::Round($stats.SpaceSaved / 1GB, 2)) GB"
            BackupsRemoved = $stats.BackupsRemoved
            BackupsCompressed = $stats.BackupsCompressed
            Duration = $stats.Duration.TotalMinutes
        }
        
        return $stats
        
    } catch {
        Write-AutomationLog -Message "Failed to optimize backup storage: $_" -Level Error
        throw
    }
}

#endregion

#region Helper Functions

function Load-BackupProviders {
    <#
    .SYNOPSIS
        Loads available backup providers
    .DESCRIPTION
        Discovers and loads backup provider plugins from the providers directory.
    #>
    [CmdletBinding()]
    param()
    
    try {
        $providersPath = Join-Path $PSScriptRoot "Providers"
        
        if (Test-Path $providersPath) {
            $providerScripts = Get-ChildItem -Path $providersPath -Filter "*Provider.ps1"
            
            foreach ($script in $providerScripts) {
                try {
                    # Extract provider name
                    $providerName = $script.BaseName -replace 'Provider$', ''
                    
                    # Load provider metadata
                    $metadata = . $script.FullName -GetMetadata
                    
                    if ($metadata) {
                        Register-BackupProvider -Name $providerName `
                            -Type $metadata.Type `
                            -ScriptPath $script.FullName `
                            -Configuration $metadata.DefaultConfiguration
                    }
                } catch {
                    Write-AutomationLog -Message "Failed to load provider $($script.Name): $_" -Level Warning
                }
            }
        }
        
        # Load built-in FileSystem provider
        Register-BuiltInProviders
        
    } catch {
        Write-AutomationLog -Message "Failed to load backup providers: $_" -Level Error
        throw
    }
}

function Register-BuiltInProviders {
    <#
    .SYNOPSIS
        Registers built-in backup providers
    #>
    [CmdletBinding()]
    param()
    
    # FileSystem Provider
    $fileSystemProvider = [PSCustomObject]@{
        Initialize = {
            param($Config)
            return @{ Success = $true }
        }
        
        GetCapabilities = {
            return @{
                Features = @('LocalBackup', 'Compression', 'Incremental', 'Verification')
                MaxFileSize = 1TB
                SupportsEncryption = $true
                SupportsDeduplication = $true
            }
        }
        
        TestConnection = {
            return @{ Success = $true; Message = "FileSystem provider ready" }
        }
        
        ValidateJob = {
            param($Job)
            $result = @{ IsValid = $true; Errors = @() }
            
            foreach ($source in $Job.Source) {
                if (-not (Test-Path $source)) {
                    $result.IsValid = $false
                    $result.Errors += "Source not found: $source"
                }
            }
            
            return $result
        }
        
        ExecuteBackup = {
            param($Context)
            
            try {
                $job = $Context.Job
                $backupId = [guid]::NewGuid().ToString()
                $backupPath = Join-Path $job.Destination $backupId
                
                # Create backup directory
                New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
                
                $stats = @{
                    FilesProcessed = 0
                    BytesProcessed = 0
                    BytesCompressed = 0
                }
                
                # Copy files
                foreach ($source in $job.Source) {
                    if (Test-Path $source -PathType Container) {
                        $files = Get-ChildItem -Path $source -Recurse -File
                        foreach ($file in $files) {
                            $relativePath = $file.FullName.Substring($source.Length).TrimStart('\', '/')
                            $destPath = Join-Path $backupPath $relativePath
                            
                            $destDir = Split-Path $destPath -Parent
                            if (-not (Test-Path $destDir)) {
                                New-Item -Path $destDir -ItemType Directory -Force | Out-Null
                            }
                            
                            Copy-Item -Path $file.FullName -Destination $destPath -Force
                            $stats.FilesProcessed++
                            $stats.BytesProcessed += $file.Length
                        }
                    } else {
                        $file = Get-Item $source
                        $destPath = Join-Path $backupPath $file.Name
                        Copy-Item -Path $file.FullName -Destination $destPath -Force
                        $stats.FilesProcessed++
                        $stats.BytesProcessed += $file.Length
                    }
                }
                
                # Apply compression if enabled
                if ($job.Policy.Compression.Enabled) {
                    Compress-Archive -Path "$backupPath\*" -DestinationPath "$backupPath.zip" -CompressionLevel $job.Policy.Compression.Level
                    Remove-Item -Path $backupPath -Recurse -Force
                    $stats.BytesCompressed = (Get-Item "$backupPath.zip").Length
                }
                
                return @{
                    Success = $true
                    BackupSet = @{
                        Id = $backupId
                        Path = if ($job.Policy.Compression.Enabled) { "$backupPath.zip" } else { $backupPath }
                        CreatedAt = Get-Date
                    }
                    Statistics = $stats
                }
                
            } catch {
                return @{
                    Success = $false
                    Error = $_.Exception.Message
                }
            }
        }
        
        RestoreBackup = {
            param($Context)
            
            try {
                $backupPath = $Context.BackupSet.Path
                $destination = $Context.Destination
                
                if ($backupPath -match '\.zip$') {
                    Expand-Archive -Path $backupPath -DestinationPath $destination -Force
                } else {
                    Copy-Item -Path "$backupPath\*" -Destination $destination -Recurse -Force
                }
                
                return @{
                    Success = $true
                    RestoredPath = $destination
                }
                
            } catch {
                return @{
                    Success = $false
                    Error = $_.Exception.Message
                }
            }
        }
    }
    
    # Register FileSystem provider
    $script:BackupProviders['FileSystem'] = [PSCustomObject]@{
        Name = 'FileSystem'
        Type = 'FileSystem'
        Provider = $fileSystemProvider
        Capabilities = & $fileSystemProvider.GetCapabilities
        Status = 'Active'
    }
}

function Update-BackupJobStatistics {
    <#
    .SYNOPSIS
        Updates job statistics after execution
    #>
    param($Job, $Context)
    
    $Job.Statistics.TotalRuns++
    
    if ($Context.Status -eq 'Completed') {
        $Job.Statistics.SuccessfulRuns++
    } else {
        $Job.Statistics.FailedRuns++
    }
    
    if ($Context.Statistics.Duration) {
        $Job.Statistics.LastDuration = $Context.Statistics.Duration
    }
    
    # Update global statistics
    $script:BackupService.Statistics.TotalBackups++
    if ($Context.Status -eq 'Completed') {
        $script:BackupService.Statistics.SuccessfulBackups++
        $script:BackupService.Statistics.TotalDataSize += $Context.Statistics.BytesProcessed
        $script:BackupService.Statistics.CompressedSize += $Context.Statistics.BytesCompressed
    } else {
        $script:BackupService.Statistics.FailedBackups++
    }
    
    $script:BackupService.Statistics.LastBackupTime = Get-Date
}

function Invoke-BackupHook {
    <#
    .SYNOPSIS
        Invokes backup lifecycle hooks
    #>
    param($Job, [string]$Hook, $Context)
    
    try {
        # Built-in hooks
        switch ($Hook) {
            'PreBackup' {
                # Create backup manifest
                $manifest = @{
                    JobId = $Job.Id
                    JobName = $Job.Name
                    StartTime = $Context.StartTime
                    Sources = $Job.Source
                    Policy = $Job.Policy.Name
                }
                $Context.Manifest = $manifest
            }
            
            'PostBackup' {
                # Update manifest with results
                if ($Context.Manifest) {
                    $Context.Manifest.EndTime = $Context.EndTime
                    $Context.Manifest.Status = $Context.Status
                    $Context.Manifest.Statistics = $Context.Statistics
                }
            }
            
            'OnError' {
                # Send error notification
                if ($script:BackupService.Configuration.Notifications.OnError) {
                    Send-BackupNotification -Type 'Error' -Job $Job -Context $Context
                }
            }
            
            'Cleanup' {
                # Clean up temporary files
                if ($Context.TempFiles) {
                    foreach ($tempFile in $Context.TempFiles) {
                        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }
        
        # Custom hooks from policy
        if ($Job.Policy.Hooks -and $Job.Policy.Hooks.$Hook) {
            & $Job.Policy.Hooks.$Hook $Context
        }
        
    } catch {
        Write-AutomationLog -Message "Hook '$Hook' failed: $_" -Level Warning
    }
}

function Start-BackupMaintenance {
    <#
    .SYNOPSIS
        Starts background maintenance tasks
    #>
    [CmdletBinding()]
    param()
    
    # Schedule periodic maintenance
    $action = {
        try {
            # Clean up old logs
            $logPath = Join-Path $script:BackupService.Configuration.Storage.Primary.Path "Logs"
            $cutoffDate = (Get-Date).AddDays(-30)
            Get-ChildItem -Path $logPath -Filter "*.log" | 
                Where-Object { $_.LastWriteTime -lt $cutoffDate } |
                Remove-Item -Force
            
            # Update statistics
            $script:BackupService.Statistics.LastMaintenanceRun = Get-Date
            
        } catch {
            Write-AutomationLog -Message "Maintenance task failed: $_" -Level Warning
        }
    }
    
    # Register scheduled task
    Register-ScheduledJob -Name "BackupMaintenance" `
        -ScriptBlock $action `
        -Trigger (New-JobTrigger -Daily -At "2:00AM") `
        -ErrorAction SilentlyContinue
}

#endregion

#region Export
Export-ModuleMember -Function @(
    # Service Management
    'Initialize-BackupService'
    'Start-BackupService'
    'Stop-BackupService'
    'Get-BackupServiceStatus'
    
    # Backup Operations
    'New-BackupJob'
    'Start-BackupJob'
    'Stop-BackupJob'
    'Get-BackupJob'
    'Remove-BackupJob'
    
    # Backup Policies
    'New-BackupPolicy'
    'Set-BackupPolicy'
    'Get-BackupPolicy'
    'Remove-BackupPolicy'
    'Test-BackupPolicy'
    
    # Backup Providers
    'Register-BackupProvider'
    'Get-BackupProvider'
    'Test-BackupProvider'
    
    # Storage Management
    'Optimize-BackupStorage'
    'Clean-BackupStorage'
) -Alias @('backup', 'restore', 'bkpjob')
#endregion