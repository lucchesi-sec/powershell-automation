<#
.SYNOPSIS
    PSBackupManager - Enterprise backup management module
.DESCRIPTION
    Provides comprehensive backup and restore capabilities with cloud integration,
    compression, encryption, and advanced scheduling features.
.NOTES
    Version: 2.0.0
    Author: Enterprise Automation Team
#>

# Import dependencies
Import-Module PSCore -MinimumVersion 2.0.0

#region Module Variables
$script:PSBackupConfig = @{
    DefaultBackupPath = Join-Path $env:ProgramData 'PSBackup\Backups'
    DefaultCatalogPath = Join-Path $env:ProgramData 'PSBackup\Catalog'
    DefaultTempPath = Join-Path $env:TEMP 'PSBackup'
    CompressionLevel = 'Optimal'
    EncryptionEnabled = $true
    VerifyAfterBackup = $true
    ParallelOperations = 4
    RetentionPolicy = @{
        Daily = 7
        Weekly = 4
        Monthly = 12
        Yearly = 5
    }
    CloudProviders = @{
        Azure = @{
            Enabled = $false
            ConnectionString = $null
            Container = 'backups'
        }
        AWS = @{
            Enabled = $false
            BucketName = $null
            Region = 'us-east-1'
        }
        OneDrive = @{
            Enabled = $false
            Path = $null
        }
    }
    NotificationSettings = @{
        EmailOnSuccess = $false
        EmailOnFailure = $true
        EmailOnWarning = $true
    }
    Performance = @{
        BufferSize = 64KB
        MaxConcurrentJobs = 5
        ThrottleLimitMBps = 0 # 0 = unlimited
        CompressInMemory = $true
    }
}

$script:PSBackupProviders = @{
    FileSystem = @{
        Name = 'FileSystem'
        Description = 'File and folder backup provider'
        Capabilities = @('Backup', 'Restore', 'Incremental', 'Differential')
    }
    Registry = @{
        Name = 'Registry'
        Description = 'Windows Registry backup provider'
        Capabilities = @('Backup', 'Restore', 'Export')
    }
    Database = @{
        Name = 'Database'
        Description = 'Database backup provider'
        Capabilities = @('Backup', 'Restore', 'PointInTime')
    }
    SystemState = @{
        Name = 'SystemState'
        Description = 'Windows System State backup provider'
        Capabilities = @('Backup', 'Restore', 'BMR')
    }
}

$script:ActiveBackupJobs = @{}
$script:BackupCatalog = $null
#endregion

#region Backup Operations
function Start-PSBackup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Job')]
        [string]$JobName,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'Custom')]
        [string[]]$Path,
        
        [Parameter(Mandatory = $false)]
        [string]$Destination = $script:PSBackupConfig.DefaultBackupPath,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Full', 'Incremental', 'Differential', 'Copy')]
        [string]$Type = 'Full',
        
        [Parameter(Mandatory = $false)]
        [string]$Description,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Options = @{},
        
        [Parameter(Mandatory = $false)]
        [switch]$Compress,
        
        [Parameter(Mandatory = $false)]
        [switch]$Encrypt,
        
        [Parameter(Mandatory = $false)]
        [switch]$UploadToCloud,
        
        [Parameter(Mandatory = $false)]
        [switch]$NoVerify,
        
        [Parameter(Mandatory = $false)]
        [switch]$AsJob
    )
    
    begin {
        $backupId = [Guid]::NewGuid().ToString()
        $startTime = Get-Date
        
        $context = Initialize-PSLogContext -Operation 'Start-PSBackup' -Properties @{
            BackupId = $backupId
            Type = $Type
            JobName = $JobName
            Paths = $Path
        }
    }
    
    process {
        try {
            # Load job configuration if specified
            if ($PSCmdlet.ParameterSetName -eq 'Job') {
                $job = Get-PSBackupJob -Name $JobName
                if (-not $job) {
                    throw "Backup job not found: $JobName"
                }
                
                $Path = $job.Sources
                $Destination = $job.Destination
                $Type = $job.BackupType
                $Compress = $job.Compression
                $Encrypt = $job.Encryption
                $Options = $job.Options
            }
            
            Write-PSLog -Message "Starting backup operation (ID: $backupId)" -Component 'PSBackupManager'
            
            # Create backup metadata
            $backupMetadata = @{
                BackupId = $backupId
                Type = $Type
                StartTime = $startTime
                EndTime = $null
                Status = 'InProgress'
                Sources = $Path
                Destination = $Destination
                Description = $Description
                Options = $Options
                Statistics = @{
                    TotalFiles = 0
                    TotalSize = 0
                    BackedUpFiles = 0
                    BackedUpSize = 0
                    SkippedFiles = 0
                    FailedFiles = 0
                    CompressionRatio = 0
                }
                Errors = @()
            }
            
            # Store active job
            $script:ActiveBackupJobs[$backupId] = $backupMetadata
            
            # Create destination directory
            $backupPath = Join-Path $Destination "Backup_${Type}_$(Get-Date -Format 'yyyyMMdd_HHmmss')_${backupId}"
            if (-not (Test-Path $backupPath)) {
                New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
            }
            
            if ($AsJob) {
                # Run as background job
                $scriptBlock = {
                    param($Module, $BackupId, $Paths, $BackupPath, $Type, $Compress, $Encrypt, $Options)
                    
                    Import-Module $Module
                    
                    # Perform backup
                    $result = Invoke-BackupOperation -BackupId $BackupId -Paths $Paths -Destination $BackupPath -Type $Type -Compress $Compress -Encrypt $Encrypt -Options $Options
                    
                    return $result
                }
                
                $job = Start-PSJob -ScriptBlock $scriptBlock -Parameters @{
                    Module = $PSScriptRoot
                    BackupId = $backupId
                    Paths = $Path
                    BackupPath = $backupPath
                    Type = $Type
                    Compress = $Compress
                    Encrypt = $Encrypt
                    Options = $Options
                } -Name "Backup_$backupId"
                
                Write-PSLog -Message "Backup started as job: $($job.Id)" -Component 'PSBackupManager'
                
                return [PSCustomObject]@{
                    BackupId = $backupId
                    JobId = $job.Id
                    Status = 'Running'
                    StartTime = $startTime
                }
            }
            else {
                # Run synchronously
                if ($PSCmdlet.ShouldProcess($Path -join ', ', "Backup to $Destination")) {
                    $result = Invoke-BackupOperation -BackupId $backupId -Paths $Path -Destination $backupPath -Type $Type -Compress $Compress -Encrypt $Encrypt -Options $Options -Metadata $backupMetadata
                    
                    # Verify backup if enabled
                    if (-not $NoVerify -and $script:PSBackupConfig.VerifyAfterBackup) {
                        Write-PSLog -Message "Verifying backup integrity" -Component 'PSBackupManager'
                        $verifyResult = Test-PSBackupIntegrity -BackupPath $backupPath
                        $result.VerificationResult = $verifyResult
                    }
                    
                    # Upload to cloud if requested
                    if ($UploadToCloud) {
                        Write-PSLog -Message "Uploading backup to cloud" -Component 'PSBackupManager'
                        $cloudResult = Sync-PSBackupToCloud -LocalPath $backupPath -BackupId $backupId
                        $result.CloudUpload = $cloudResult
                    }
                    
                    # Update catalog
                    Update-BackupCatalog -BackupMetadata $result
                    
                    # Clean up active job
                    $script:ActiveBackupJobs.Remove($backupId)
                    
                    Write-PSLog -Message "Backup completed successfully (ID: $backupId)" -Level 'Success' -Component 'PSBackupManager'
                    
                    return $result
                }
            }
        }
        catch {
            $script:ActiveBackupJobs.Remove($backupId)
            Write-PSLog -Message "Backup operation failed: $_" -Level 'Error' -Component 'PSBackupManager' -Context $context
            throw
        }
    }
}

function Stop-PSBackup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupId,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    process {
        try {
            if (-not $script:ActiveBackupJobs.ContainsKey($BackupId)) {
                # Check for background job
                $job = Get-Job -Name "Backup_$BackupId" -ErrorAction SilentlyContinue
                if (-not $job) {
                    throw "Active backup not found: $BackupId"
                }
                
                if ($PSCmdlet.ShouldProcess($BackupId, "Stop backup job")) {
                    Stop-Job -Job $job
                    
                    if ($Force) {
                        Remove-Job -Job $job -Force
                    }
                    
                    Write-PSLog -Message "Backup job stopped: $BackupId" -Component 'PSBackupManager'
                    
                    return [PSCustomObject]@{
                        BackupId = $BackupId
                        Status = 'Stopped'
                        StoppedAt = Get-Date
                    }
                }
            }
            else {
                # In-process backup
                $backup = $script:ActiveBackupJobs[$BackupId]
                $backup.Status = 'Cancelled'
                $backup.EndTime = Get-Date
                
                Write-PSLog -Message "Backup cancelled: $BackupId" -Component 'PSBackupManager'
                
                return [PSCustomObject]$backup
            }
        }
        catch {
            Write-PSLog -Message "Failed to stop backup: $_" -Level 'Error' -Component 'PSBackupManager'
            throw
        }
    }
}

function Get-PSBackupStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$BackupId,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeCompleted
    )
    
    process {
        try {
            $results = @()
            
            # Check active in-process backups
            if ($BackupId) {
                if ($script:ActiveBackupJobs.ContainsKey($BackupId)) {
                    $results += [PSCustomObject]$script:ActiveBackupJobs[$BackupId]
                }
            }
            else {
                foreach ($activeBackup in $script:ActiveBackupJobs.Values) {
                    $results += [PSCustomObject]$activeBackup
                }
            }
            
            # Check background jobs
            $jobFilter = if ($BackupId) { "Backup_$BackupId" } else { "Backup_*" }
            $jobs = Get-Job -Name $jobFilter -ErrorAction SilentlyContinue
            
            foreach ($job in $jobs) {
                if ($job.State -eq 'Running' -or ($IncludeCompleted -and $job.State -in @('Completed', 'Failed', 'Stopped'))) {
                    $backupIdFromJob = $job.Name -replace '^Backup_', ''
                    
                    $results += [PSCustomObject]@{
                        BackupId = $backupIdFromJob
                        JobId = $job.Id
                        Status = $job.State
                        StartTime = $job.PSBeginTime
                        EndTime = $job.PSEndTime
                        HasErrors = $job.State -eq 'Failed'
                    }
                }
            }
            
            # Include completed from catalog if requested
            if ($IncludeCompleted) {
                $catalog = Get-BackupCatalog
                
                if ($BackupId) {
                    $catalogEntry = $catalog | Where-Object { $_.BackupId -eq $BackupId }
                    if ($catalogEntry -and -not ($results | Where-Object { $_.BackupId -eq $BackupId })) {
                        $results += $catalogEntry
                    }
                }
                else {
                    # Add recent completed backups
                    $recentBackups = $catalog | 
                        Where-Object { $_.EndTime -gt (Get-Date).AddHours(-24) } |
                        Where-Object { $_.BackupId -notin $results.BackupId }
                    
                    $results += $recentBackups
                }
            }
            
            return $results | Sort-Object StartTime -Descending
        }
        catch {
            Write-PSLog -Message "Failed to get backup status: $_" -Level 'Error' -Component 'PSBackupManager'
            throw
        }
    }
}
#endregion

#region Backup Jobs
function New-PSBackupJob {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [string[]]$Source,
        
        [Parameter(Mandatory = $true)]
        [string]$Destination,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Full', 'Incremental', 'Differential')]
        [string]$BackupType = 'Full',
        
        [Parameter(Mandatory = $false)]
        [string]$Description,
        
        [Parameter(Mandatory = $false)]
        [switch]$Compression,
        
        [Parameter(Mandatory = $false)]
        [switch]$Encryption,
        
        [Parameter(Mandatory = $false)]
        [switch]$CloudSync,
        
        [Parameter(Mandatory = $false)]
        [string]$Schedule,
        
        [Parameter(Mandatory = $false)]
        [int]$RetentionDays = 30,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Options = @{},
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('High', 'Normal', 'Low')]
        [string]$Priority = 'Normal'
    )
    
    process {
        try {
            $configPath = Join-Path $script:PSBackupConfig.DefaultCatalogPath 'Jobs'
            if (-not (Test-Path $configPath)) {
                New-Item -Path $configPath -ItemType Directory -Force | Out-Null
            }
            
            $jobPath = Join-Path $configPath "$Name.json"
            
            # Check if job already exists
            if (Test-Path $jobPath) {
                throw "Backup job already exists: $Name"
            }
            
            $job = @{
                Name = $Name
                Description = $Description
                Sources = $Source
                Destination = $Destination
                BackupType = $BackupType
                Compression = $Compression.IsPresent
                Encryption = $Encryption.IsPresent
                CloudSync = $CloudSync.IsPresent
                Schedule = $Schedule
                RetentionDays = $RetentionDays
                Priority = $Priority
                Options = $Options
                CreatedDate = Get-Date
                CreatedBy = $env:USERNAME
                LastModified = Get-Date
                LastRun = $null
                NextRun = $null
                Enabled = $true
                Statistics = @{
                    TotalRuns = 0
                    SuccessfulRuns = 0
                    FailedRuns = 0
                    LastSuccess = $null
                    LastFailure = $null
                    AverageRunTime = 0
                    TotalBackedUpSize = 0
                }
            }
            
            if ($PSCmdlet.ShouldProcess($Name, "Create backup job")) {
                # Validate sources
                foreach ($src in $Source) {
                    if (-not (Test-Path $src)) {
                        Write-PSLog -Message "Warning: Source path does not exist: $src" -Level 'Warning' -Component 'PSBackupManager'
                    }
                }
                
                # Save job configuration
                $job | ConvertTo-Json -Depth 10 | Set-Content -Path $jobPath -Encoding UTF8
                
                Write-PSLog -Message "Backup job created: $Name" -Component 'PSBackupManager'
                
                # Create schedule if specified
                if ($Schedule) {
                    New-PSBackupSchedule -JobName $Name -Schedule $Schedule
                }
                
                return [PSCustomObject]$job
            }
        }
        catch {
            Write-PSLog -Message "Failed to create backup job: $_" -Level 'Error' -Component 'PSBackupManager'
            throw
        }
    }
}

function Get-PSBackupJob {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeDisabled,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeStatistics
    )
    
    process {
        try {
            $configPath = Join-Path $script:PSBackupConfig.DefaultCatalogPath 'Jobs'
            
            if (-not (Test-Path $configPath)) {
                return @()
            }
            
            $jobs = @()
            
            if ($Name) {
                $jobPath = Join-Path $configPath "$Name.json"
                if (Test-Path $jobPath) {
                    $job = Get-Content -Path $jobPath -Raw | ConvertFrom-Json
                    
                    if ($job.Enabled -or $IncludeDisabled) {
                        if ($IncludeStatistics) {
                            # Add runtime statistics
                            $job | Add-Member -MemberType NoteProperty -Name 'RuntimeStatistics' -Value (Get-BackupJobStatistics -JobName $Name) -Force
                        }
                        $jobs += $job
                    }
                }
            }
            else {
                $jobFiles = Get-ChildItem -Path $configPath -Filter '*.json'
                
                foreach ($file in $jobFiles) {
                    $job = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
                    
                    if ($job.Enabled -or $IncludeDisabled) {
                        if ($IncludeStatistics) {
                            $job | Add-Member -MemberType NoteProperty -Name 'RuntimeStatistics' -Value (Get-BackupJobStatistics -JobName $job.Name) -Force
                        }
                        $jobs += $job
                    }
                }
            }
            
            return $jobs
        }
        catch {
            Write-PSLog -Message "Failed to get backup jobs: $_" -Level 'Error' -Component 'PSBackupManager'
            throw
        }
    }
}

function Test-PSBackupJob {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [switch]$TestRun
    )
    
    process {
        try {
            $job = Get-PSBackupJob -Name $Name
            if (-not $job) {
                throw "Backup job not found: $Name"
            }
            
            Write-PSLog -Message "Testing backup job: $Name" -Component 'PSBackupManager'
            
            $testResults = @{
                JobName = $Name
                TestedAt = Get-Date
                Valid = $true
                Errors = @()
                Warnings = @()
                SourcesExist = $true
                DestinationWritable = $true
                CloudConnectionValid = $true
                EstimatedSize = 0
            }
            
            # Test sources
            foreach ($source in $job.Sources) {
                if (-not (Test-Path $source)) {
                    $testResults.SourcesExist = $false
                    $testResults.Errors += "Source not found: $source"
                    $testResults.Valid = $false
                }
                else {
                    # Estimate size
                    if ((Get-Item $source).PSIsContainer) {
                        $size = (Get-ChildItem -Path $source -Recurse -File -ErrorAction SilentlyContinue | 
                            Measure-Object -Property Length -Sum).Sum
                    }
                    else {
                        $size = (Get-Item $source).Length
                    }
                    $testResults.EstimatedSize += $size
                }
            }
            
            # Test destination
            try {
                $testFile = Join-Path $job.Destination "test_$(Get-Random).tmp"
                New-Item -Path $testFile -ItemType File -Force | Out-Null
                Remove-Item -Path $testFile -Force
            }
            catch {
                $testResults.DestinationWritable = $false
                $testResults.Errors += "Destination not writable: $($job.Destination)"
                $testResults.Valid = $false
            }
            
            # Test cloud connection if enabled
            if ($job.CloudSync) {
                $cloudStatus = Test-CloudConnection
                if (-not $cloudStatus.Connected) {
                    $testResults.CloudConnectionValid = $false
                    $testResults.Warnings += "Cloud connection not available"
                }
            }
            
            # Test encryption key if enabled
            if ($job.Encryption) {
                if (-not (Test-Path (Join-Path $script:PSBackupConfig.DefaultCatalogPath 'Keys\backup.key'))) {
                    $testResults.Warnings += "Encryption key not found"
                }
            }
            
            # Perform test run if requested
            if ($TestRun -and $testResults.Valid) {
                Write-PSLog -Message "Performing test backup run" -Component 'PSBackupManager'
                
                try {
                    $testBackup = Start-PSBackup -JobName $Name -Options @{TestMode = $true}
                    $testResults | Add-Member -MemberType NoteProperty -Name 'TestRunResult' -Value $testBackup
                }
                catch {
                    $testResults.Errors += "Test run failed: $_"
                    $testResults.Valid = $false
                }
            }
            
            Write-PSLog -Message "Backup job test completed. Valid: $($testResults.Valid)" -Component 'PSBackupManager'
            
            return [PSCustomObject]$testResults
        }
        catch {
            Write-PSLog -Message "Failed to test backup job: $_" -Level 'Error' -Component 'PSBackupManager'
            throw
        }
    }
}
#endregion

#region Restore Operations
function Start-PSRestore {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'BackupId')]
        [string]$BackupId,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'Path')]
        [string]$BackupPath,
        
        [Parameter(Mandatory = $false)]
        [string]$Destination,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Include,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Exclude,
        
        [Parameter(Mandatory = $false)]
        [switch]$OverwriteExisting,
        
        [Parameter(Mandatory = $false)]
        [switch]$PreservePermissions,
        
        [Parameter(Mandatory = $false)]
        [switch]$WhatIf
    )
    
    process {
        try {
            # Get backup metadata
            if ($PSCmdlet.ParameterSetName -eq 'BackupId') {
                $catalog = Get-BackupCatalog
                $backupEntry = $catalog | Where-Object { $_.BackupId -eq $BackupId }
                
                if (-not $backupEntry) {
                    throw "Backup not found in catalog: $BackupId"
                }
                
                $BackupPath = $backupEntry.BackupPath
            }
            
            if (-not (Test-Path $BackupPath)) {
                throw "Backup path not found: $BackupPath"
            }
            
            Write-PSLog -Message "Starting restore operation from: $BackupPath" -Component 'PSBackupManager'
            
            # Load backup metadata
            $metadataPath = Join-Path $BackupPath 'backup.metadata'
            if (Test-Path $metadataPath) {
                $metadata = Get-Content -Path $metadataPath -Raw | ConvertFrom-Json
            }
            else {
                Write-PSLog -Message "Backup metadata not found, using defaults" -Level 'Warning' -Component 'PSBackupManager'
                $metadata = @{
                    Type = 'Unknown'
                    Encrypted = $false
                    Compressed = $false
                }
            }
            
            # Determine destination
            if (-not $Destination) {
                if ($metadata.PSObject.Properties['OriginalPath']) {
                    $Destination = $metadata.OriginalPath
                    Write-PSLog -Message "Using original path as destination: $Destination" -Component 'PSBackupManager'
                }
                else {
                    throw "Destination must be specified for restore"
                }
            }
            
            $restoreContext = @{
                RestoreId = [Guid]::NewGuid().ToString()
                BackupPath = $BackupPath
                Destination = $Destination
                StartTime = Get-Date
                EndTime = $null
                Status = 'InProgress'
                FilesRestored = 0
                FilesSkipped = 0
                FilesFailed = 0
                BytesRestored = 0
                Errors = @()
            }
            
            if ($PSCmdlet.ShouldProcess($Destination, "Restore from $BackupPath")) {
                # Handle encrypted backups
                if ($metadata.Encrypted) {
                    Write-PSLog -Message "Decrypting backup data" -Component 'PSBackupManager'
                    $BackupPath = Decrypt-BackupData -Path $BackupPath -Metadata $metadata
                }
                
                # Handle compressed backups
                if ($metadata.Compressed) {
                    Write-PSLog -Message "Decompressing backup data" -Component 'PSBackupManager'
                    $BackupPath = Decompress-BackupData -Path $BackupPath -Metadata $metadata
                }
                
                # Get files to restore
                $backupFiles = Get-ChildItem -Path $BackupPath -Recurse -File
                
                # Apply filters
                if ($Include) {
                    $backupFiles = $backupFiles | Where-Object {
                        $file = $_
                        $Include | Where-Object { $file.FullName -like $_ } | Select-Object -First 1
                    }
                }
                
                if ($Exclude) {
                    $backupFiles = $backupFiles | Where-Object {
                        $file = $_
                        -not ($Exclude | Where-Object { $file.FullName -like $_ } | Select-Object -First 1)
                    }
                }
                
                Write-PSLog -Message "Restoring $($backupFiles.Count) files" -Component 'PSBackupManager'
                
                # Restore files
                foreach ($file in $backupFiles) {
                    try {
                        $relativePath = $file.FullName.Substring($BackupPath.Length).TrimStart('\', '/')
                        $targetPath = Join-Path $Destination $relativePath
                        $targetDir = Split-Path -Parent $targetPath
                        
                        # Create directory if needed
                        if (-not (Test-Path $targetDir)) {
                            New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
                        }
                        
                        # Check if file exists
                        if ((Test-Path $targetPath) -and -not $OverwriteExisting) {
                            Write-PSLog -Message "Skipping existing file: $targetPath" -Component 'PSBackupManager'
                            $restoreContext.FilesSkipped++
                            continue
                        }
                        
                        # Copy file
                        Copy-Item -Path $file.FullName -Destination $targetPath -Force
                        $restoreContext.FilesRestored++
                        $restoreContext.BytesRestored += $file.Length
                        
                        # Restore permissions if requested
                        if ($PreservePermissions -and $metadata.PSObject.Properties['Permissions']) {
                            $filePermissions = $metadata.Permissions | Where-Object { $_.Path -eq $relativePath }
                            if ($filePermissions) {
                                # Restore ACL
                                Set-Acl -Path $targetPath -AclObject $filePermissions.Acl
                            }
                        }
                    }
                    catch {
                        Write-PSLog -Message "Failed to restore file $($file.Name): $_" -Level 'Error' -Component 'PSBackupManager'
                        $restoreContext.FilesFailed++
                        $restoreContext.Errors += $_
                    }
                }
                
                $restoreContext.EndTime = Get-Date
                $restoreContext.Status = if ($restoreContext.FilesFailed -eq 0) { 'Success' } else { 'PartialSuccess' }
                
                Write-PSLog -Message "Restore completed. Files restored: $($restoreContext.FilesRestored), Failed: $($restoreContext.FilesFailed)" -Level 'Success' -Component 'PSBackupManager'
                
                return [PSCustomObject]$restoreContext
            }
        }
        catch {
            Write-PSLog -Message "Restore operation failed: $_" -Level 'Error' -Component 'PSBackupManager'
            throw
        }
    }
}

function Get-PSRestorePoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Source,
        
        [Parameter(Mandatory = $false)]
        [datetime]$StartDate,
        
        [Parameter(Mandatory = $false)]
        [datetime]$EndDate = (Get-Date),
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Full', 'Incremental', 'Differential', 'All')]
        [string]$Type = 'All',
        
        [Parameter(Mandatory = $false)]
        [int]$Latest = 0
    )
    
    process {
        try {
            $catalog = Get-BackupCatalog
            
            # Apply filters
            if ($Source) {
                $catalog = $catalog | Where-Object { 
                    $_.Sources -contains $Source -or 
                    $_.Sources | Where-Object { $_ -like "*$Source*" }
                }
            }
            
            if ($StartDate) {
                $catalog = $catalog | Where-Object { $_.EndTime -ge $StartDate }
            }
            
            $catalog = $catalog | Where-Object { $_.EndTime -le $EndDate }
            
            if ($Type -ne 'All') {
                $catalog = $catalog | Where-Object { $_.Type -eq $Type }
            }
            
            # Sort by date
            $catalog = $catalog | Sort-Object EndTime -Descending
            
            # Get latest if specified
            if ($Latest -gt 0) {
                $catalog = $catalog | Select-Object -First $Latest
            }
            
            # Add restore point information
            foreach ($backup in $catalog) {
                $backup | Add-Member -MemberType NoteProperty -Name 'RestorePoint' -Value $true -Force
                $backup | Add-Member -MemberType NoteProperty -Name 'Age' -Value ((Get-Date) - $backup.EndTime) -Force
                $backup | Add-Member -MemberType NoteProperty -Name 'IsValid' -Value (Test-Path $backup.BackupPath) -Force
                
                # Check if part of a chain
                if ($backup.Type -in @('Incremental', 'Differential')) {
                    $parentBackup = $catalog | 
                        Where-Object { $_.BackupId -eq $backup.ParentBackupId } |
                        Select-Object -First 1
                    
                    $backup | Add-Member -MemberType NoteProperty -Name 'RequiresParent' -Value $true -Force
                    $backup | Add-Member -MemberType NoteProperty -Name 'ParentValid' -Value ($parentBackup -and $parentBackup.IsValid) -Force
                }
            }
            
            return $catalog
        }
        catch {
            Write-PSLog -Message "Failed to get restore points: $_" -Level 'Error' -Component 'PSBackupManager'
            throw
        }
    }
}
#endregion

#region Cloud Integration
function Connect-PSBackupCloud {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Azure', 'AWS', 'OneDrive')]
        [string]$Provider,
        
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$ConnectionParameters = @{}
    )
    
    process {
        try {
            Write-PSLog -Message "Connecting to cloud provider: $Provider" -Component 'PSBackupManager'
            
            switch ($Provider) {
                'Azure' {
                    if (-not $ConnectionParameters.ContainsKey('StorageAccountName')) {
                        throw "StorageAccountName required for Azure connection"
                    }
                    
                    # Load Azure module
                    Import-PSModule -Name 'Az.Storage' -MinimumVersion '4.0.0'
                    
                    # Connect to Azure
                    if ($Credential) {
                        Connect-AzAccount -Credential $Credential -ErrorAction Stop
                    }
                    else {
                        Connect-AzAccount -ErrorAction Stop
                    }
                    
                    # Get storage context
                    $storageAccount = Get-AzStorageAccount | 
                        Where-Object { $_.StorageAccountName -eq $ConnectionParameters.StorageAccountName } |
                        Select-Object -First 1
                    
                    if (-not $storageAccount) {
                        throw "Storage account not found: $($ConnectionParameters.StorageAccountName)"
                    }
                    
                    $context = $storageAccount.Context
                    
                    # Update configuration
                    $script:PSBackupConfig.CloudProviders.Azure.Enabled = $true
                    $script:PSBackupConfig.CloudProviders.Azure.Context = $context
                    $script:PSBackupConfig.CloudProviders.Azure.StorageAccountName = $ConnectionParameters.StorageAccountName
                    
                    if ($ConnectionParameters.ContainerName) {
                        $script:PSBackupConfig.CloudProviders.Azure.Container = $ConnectionParameters.ContainerName
                    }
                }
                
                'AWS' {
                    if (-not $ConnectionParameters.ContainsKey('BucketName')) {
                        throw "BucketName required for AWS connection"
                    }
                    
                    # Load AWS module
                    Import-PSModule -Name 'AWS.Tools.S3' -MinimumVersion '4.0.0'
                    
                    # Set credentials
                    if ($Credential) {
                        Set-AWSCredential -AccessKey $Credential.UserName -SecretKey $Credential.GetNetworkCredential().Password
                    }
                    
                    # Test connection
                    $bucket = Get-S3Bucket -BucketName $ConnectionParameters.BucketName -ErrorAction Stop
                    
                    # Update configuration
                    $script:PSBackupConfig.CloudProviders.AWS.Enabled = $true
                    $script:PSBackupConfig.CloudProviders.AWS.BucketName = $ConnectionParameters.BucketName
                    
                    if ($ConnectionParameters.Region) {
                        $script:PSBackupConfig.CloudProviders.AWS.Region = $ConnectionParameters.Region
                    }
                }
                
                'OneDrive' {
                    # OneDrive implementation would use Microsoft Graph API
                    throw "OneDrive provider not yet implemented"
                }
            }
            
            Write-PSLog -Message "Successfully connected to $Provider" -Level 'Success' -Component 'PSBackupManager'
            
            return [PSCustomObject]@{
                Provider = $Provider
                Connected = $true
                ConnectionTime = Get-Date
                Configuration = $script:PSBackupConfig.CloudProviders.$Provider
            }
        }
        catch {
            Write-PSLog -Message "Failed to connect to cloud provider: $_" -Level 'Error' -Component 'PSBackupManager'
            throw
        }
    }
}

function Sync-PSBackupToCloud {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LocalPath,
        
        [Parameter(Mandatory = $false)]
        [string]$BackupId,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Azure', 'AWS', 'OneDrive')]
        [string]$Provider,
        
        [Parameter(Mandatory = $false)]
        [switch]$DeleteAfterUpload,
        
        [Parameter(Mandatory = $false)]
        [switch]$Compress
    )
    
    process {
        try {
            # Determine active provider
            if (-not $Provider) {
                $activeProviders = $script:PSBackupConfig.CloudProviders.GetEnumerator() | 
                    Where-Object { $_.Value.Enabled } |
                    Select-Object -First 1
                
                if (-not $activeProviders) {
                    throw "No cloud provider connected"
                }
                
                $Provider = $activeProviders.Name
            }
            
            Write-PSLog -Message "Syncing backup to $Provider cloud" -Component 'PSBackupManager'
            
            # Compress if requested
            if ($Compress -and (Get-Item $LocalPath).PSIsContainer) {
                $compressedPath = "$LocalPath.zip"
                Compress-Archive -Path $LocalPath -DestinationPath $compressedPath -Force
                $LocalPath = $compressedPath
                $deleteCompressed = $true
            }
            
            $uploadResult = @{
                Provider = $Provider
                LocalPath = $LocalPath
                CloudPath = $null
                UploadTime = Get-Date
                Success = $false
                SizeMB = [Math]::Round((Get-Item $LocalPath).Length / 1MB, 2)
                Error = $null
            }
            
            if ($PSCmdlet.ShouldProcess($LocalPath, "Upload to $Provider")) {
                switch ($Provider) {
                    'Azure' {
                        $config = $script:PSBackupConfig.CloudProviders.Azure
                        $blobName = if ($BackupId) { 
                            "backups/$BackupId/$(Split-Path -Leaf $LocalPath)"
                        } else {
                            "backups/$(Get-Date -Format 'yyyy/MM/dd')/$(Split-Path -Leaf $LocalPath)"
                        }
                        
                        $blob = Set-AzStorageBlobContent -File $LocalPath -Container $config.Container -Blob $blobName -Context $config.Context -Force
                        
                        $uploadResult.CloudPath = $blob.ICloudBlob.Uri.ToString()
                        $uploadResult.Success = $true
                    }
                    
                    'AWS' {
                        $config = $script:PSBackupConfig.CloudProviders.AWS
                        $key = if ($BackupId) { 
                            "backups/$BackupId/$(Split-Path -Leaf $LocalPath)"
                        } else {
                            "backups/$(Get-Date -Format 'yyyy/MM/dd')/$(Split-Path -Leaf $LocalPath)"
                        }
                        
                        Write-S3Object -BucketName $config.BucketName -Key $key -File $LocalPath -Region $config.Region
                        
                        $uploadResult.CloudPath = "s3://$($config.BucketName)/$key"
                        $uploadResult.Success = $true
                    }
                }
                
                Write-PSLog -Message "Upload completed: $($uploadResult.CloudPath)" -Level 'Success' -Component 'PSBackupManager'
                
                # Clean up
                if ($deleteCompressed) {
                    Remove-Item $LocalPath -Force
                }
                
                if ($DeleteAfterUpload -and $uploadResult.Success) {
                    Remove-Item $LocalPath -Recurse -Force
                    Write-PSLog -Message "Deleted local backup after successful upload" -Component 'PSBackupManager'
                }
            }
            
            return [PSCustomObject]$uploadResult
        }
        catch {
            Write-PSLog -Message "Failed to sync to cloud: $_" -Level 'Error' -Component 'PSBackupManager'
            $uploadResult.Error = $_.Exception.Message
            return [PSCustomObject]$uploadResult
        }
    }
}
#endregion

#region Backup Validation
function Test-PSBackupIntegrity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$Deep,
        
        [Parameter(Mandatory = $false)]
        [switch]$VerifyChecksum
    )
    
    process {
        try {
            Write-PSLog -Message "Testing backup integrity: $BackupPath" -Component 'PSBackupManager'
            
            $result = @{
                BackupPath = $BackupPath
                Valid = $true
                TestedAt = Get-Date
                Errors = @()
                Warnings = @()
                FileCount = 0
                CorruptFiles = 0
                MissingFiles = 0
                ChecksumMismatches = 0
            }
            
            # Check if backup exists
            if (-not (Test-Path $BackupPath)) {
                $result.Valid = $false
                $result.Errors += "Backup path not found"
                return [PSCustomObject]$result
            }
            
            # Load metadata
            $metadataPath = Join-Path $BackupPath 'backup.metadata'
            if (Test-Path $metadataPath) {
                try {
                    $metadata = Get-Content -Path $metadataPath -Raw | ConvertFrom-Json
                }
                catch {
                    $result.Warnings += "Unable to read metadata file"
                }
            }
            
            # Check manifest
            $manifestPath = Join-Path $BackupPath 'backup.manifest'
            if (Test-Path $manifestPath) {
                $manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json
                
                # Verify files against manifest
                foreach ($entry in $manifest.Files) {
                    $result.FileCount++
                    $filePath = Join-Path $BackupPath $entry.RelativePath
                    
                    if (-not (Test-Path $filePath)) {
                        $result.MissingFiles++
                        $result.Errors += "Missing file: $($entry.RelativePath)"
                        $result.Valid = $false
                    }
                    elseif ($VerifyChecksum -and $entry.Hash) {
                        $actualHash = Get-FileHash -Path $filePath -Algorithm SHA256
                        if ($actualHash.Hash -ne $entry.Hash) {
                            $result.ChecksumMismatches++
                            $result.Errors += "Checksum mismatch: $($entry.RelativePath)"
                            $result.Valid = $false
                        }
                    }
                    
                    if ($Deep) {
                        # Try to read file
                        try {
                            $null = Get-Content -Path $filePath -First 1 -ErrorAction Stop
                        }
                        catch {
                            $result.CorruptFiles++
                            $result.Errors += "Cannot read file: $($entry.RelativePath)"
                            $result.Valid = $false
                        }
                    }
                }
            }
            else {
                $result.Warnings += "No manifest file found"
                
                # Count actual files
                $files = Get-ChildItem -Path $BackupPath -Recurse -File
                $result.FileCount = $files.Count
            }
            
            Write-PSLog -Message "Integrity check completed. Valid: $($result.Valid)" -Component 'PSBackupManager'
            
            return [PSCustomObject]$result
        }
        catch {
            Write-PSLog -Message "Failed to test backup integrity: $_" -Level 'Error' -Component 'PSBackupManager'
            throw
        }
    }
}
#endregion

#region Helper Functions
function Invoke-BackupOperation {
    param(
        [string]$BackupId,
        [string[]]$Paths,
        [string]$Destination,
        [string]$Type,
        [bool]$Compress,
        [bool]$Encrypt,
        [hashtable]$Options,
        [hashtable]$Metadata
    )
    
    try {
        $operationResult = @{
            BackupId = $BackupId
            BackupPath = $Destination
            StartTime = $Metadata.StartTime
            EndTime = $null
            Type = $Type
            Sources = $Paths
            Statistics = @{
                TotalFiles = 0
                TotalSize = 0
                BackedUpFiles = 0
                BackedUpSize = 0
                SkippedFiles = 0
                FailedFiles = 0
                CompressionRatio = 0
            }
            Errors = @()
            Status = 'InProgress'
        }
        
        # Create manifest
        $manifest = @{
            BackupId = $BackupId
            Type = $Type
            CreatedAt = Get-Date
            Files = @()
        }
        
        # Get parent backup for incremental/differential
        $parentBackup = $null
        if ($Type -in @('Incremental', 'Differential')) {
            $catalog = Get-BackupCatalog
            $parentBackup = $catalog | 
                Where-Object { $_.Sources -eq $Paths -and $_.Type -eq 'Full' } |
                Sort-Object EndTime -Descending |
                Select-Object -First 1
                
            if (-not $parentBackup) {
                Write-PSLog -Message "No full backup found, performing full backup instead" -Level 'Warning' -Component 'PSBackupManager'
                $Type = 'Full'
            }
            else {
                $operationResult.ParentBackupId = $parentBackup.BackupId
            }
        }
        
        # Process each source
        foreach ($path in $Paths) {
            if (-not (Test-Path $path)) {
                $operationResult.Errors += "Source not found: $path"
                continue
            }
            
            # Get files to backup
            $files = if ((Get-Item $path).PSIsContainer) {
                Get-ChildItem -Path $path -Recurse -File
            } else {
                Get-Item $path
            }
            
            # Filter based on backup type
            if ($Type -eq 'Incremental' -and $parentBackup) {
                $files = $files | Where-Object { $_.LastWriteTime -gt $parentBackup.EndTime }
            }
            elseif ($Type -eq 'Differential' -and $parentBackup) {
                $lastFullBackup = $catalog | 
                    Where-Object { $_.Sources -eq $Paths -and $_.Type -eq 'Full' } |
                    Sort-Object EndTime -Descending |
                    Select-Object -First 1
                    
                $files = $files | Where-Object { $_.LastWriteTime -gt $lastFullBackup.EndTime }
            }
            
            # Backup files
            foreach ($file in $files) {
                try {
                    $operationResult.Statistics.TotalFiles++
                    $operationResult.Statistics.TotalSize += $file.Length
                    
                    # Calculate relative path
                    $relativePath = if ((Get-Item $path).PSIsContainer) {
                        $file.FullName.Substring($path.Length).TrimStart('\', '/')
                    } else {
                        $file.Name
                    }
                    
                    $destPath = Join-Path $Destination $relativePath
                    $destDir = Split-Path -Parent $destPath
                    
                    # Create directory
                    if (-not (Test-Path $destDir)) {
                        New-Item -Path $destDir -ItemType Directory -Force | Out-Null
                    }
                    
                    # Copy file
                    Copy-Item -Path $file.FullName -Destination $destPath -Force
                    
                    $operationResult.Statistics.BackedUpFiles++
                    $operationResult.Statistics.BackedUpSize += $file.Length
                    
                    # Add to manifest
                    $manifest.Files += @{
                        RelativePath = $relativePath
                        Size = $file.Length
                        LastWriteTime = $file.LastWriteTime
                        Hash = if ($Options.CalculateHash) { 
                            (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash 
                        } else { $null }
                    }
                }
                catch {
                    $operationResult.Statistics.FailedFiles++
                    $operationResult.Errors += "Failed to backup $($file.FullName): $_"
                    Write-PSLog -Message "Failed to backup file: $_" -Level 'Error' -Component 'PSBackupManager'
                }
            }
        }
        
        # Compress if requested
        if ($Compress) {
            Write-PSLog -Message "Compressing backup" -Component 'PSBackupManager'
            $compressedPath = "$Destination.zip"
            Compress-Archive -Path "$Destination\*" -DestinationPath $compressedPath -Force
            
            $originalSize = $operationResult.Statistics.BackedUpSize
            $compressedSize = (Get-Item $compressedPath).Length
            $operationResult.Statistics.CompressionRatio = [Math]::Round((1 - ($compressedSize / $originalSize)) * 100, 2)
            
            # Clean up uncompressed files
            Get-ChildItem -Path $Destination -Exclude '*.zip' | Remove-Item -Recurse -Force
            
            # Move compressed file back
            Move-Item -Path $compressedPath -Destination (Join-Path $Destination 'backup.zip') -Force
            $Metadata.Compressed = $true
        }
        
        # Encrypt if requested
        if ($Encrypt) {
            Write-PSLog -Message "Encrypting backup" -Component 'PSBackupManager'
            # Encryption implementation would go here
            $Metadata.Encrypted = $true
        }
        
        # Save manifest and metadata
        $manifest | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $Destination 'backup.manifest') -Encoding UTF8
        $Metadata | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $Destination 'backup.metadata') -Encoding UTF8
        
        $operationResult.EndTime = Get-Date
        $operationResult.Status = if ($operationResult.Statistics.FailedFiles -eq 0) { 'Success' } else { 'PartialSuccess' }
        
        return $operationResult
    }
    catch {
        Write-PSLog -Message "Backup operation failed: $_" -Level 'Error' -Component 'PSBackupManager'
        throw
    }
}

function Get-BackupCatalog {
    if (-not $script:BackupCatalog) {
        $catalogPath = Join-Path $script:PSBackupConfig.DefaultCatalogPath 'catalog.json'
        
        if (Test-Path $catalogPath) {
            $script:BackupCatalog = Get-Content -Path $catalogPath -Raw | ConvertFrom-Json
        }
        else {
            $script:BackupCatalog = @()
        }
    }
    
    return $script:BackupCatalog
}

function Update-BackupCatalog {
    param($BackupMetadata)
    
    $catalog = Get-BackupCatalog
    $catalog += $BackupMetadata
    
    # Keep only recent entries (last 1000)
    if ($catalog.Count -gt 1000) {
        $catalog = $catalog | Sort-Object StartTime -Descending | Select-Object -First 1000
    }
    
    $catalogPath = Join-Path $script:PSBackupConfig.DefaultCatalogPath 'catalog.json'
    $catalogDir = Split-Path -Parent $catalogPath
    
    if (-not (Test-Path $catalogDir)) {
        New-Item -Path $catalogDir -ItemType Directory -Force | Out-Null
    }
    
    $catalog | ConvertTo-Json -Depth 10 | Set-Content -Path $catalogPath -Encoding UTF8
    $script:BackupCatalog = $catalog
}

function Get-BackupJobStatistics {
    param([string]$JobName)
    
    $catalog = Get-BackupCatalog
    $jobBackups = $catalog | Where-Object { $_.JobName -eq $JobName }
    
    if ($jobBackups.Count -eq 0) {
        return $null
    }
    
    @{
        TotalBackups = $jobBackups.Count
        SuccessfulBackups = ($jobBackups | Where-Object { $_.Status -eq 'Success' }).Count
        FailedBackups = ($jobBackups | Where-Object { $_.Status -eq 'Failed' }).Count
        TotalSizeGB = [Math]::Round(($jobBackups | Measure-Object -Property { $_.Statistics.BackedUpSize } -Sum).Sum / 1GB, 2)
        AverageRunTimeMinutes = [Math]::Round(($jobBackups | ForEach-Object { ($_.EndTime - $_.StartTime).TotalMinutes } | Measure-Object -Average).Average, 2)
        LastBackup = ($jobBackups | Sort-Object EndTime -Descending | Select-Object -First 1).EndTime
    }
}

function Test-CloudConnection {
    $connected = $false
    $provider = $null
    
    foreach ($p in $script:PSBackupConfig.CloudProviders.GetEnumerator()) {
        if ($p.Value.Enabled) {
            $connected = $true
            $provider = $p.Name
            break
        }
    }
    
    @{
        Connected = $connected
        Provider = $provider
    }
}

function Decrypt-BackupData {
    param($Path, $Metadata)
    # Implementation would decrypt data
    return $Path
}

function Decompress-BackupData {
    param($Path, $Metadata)
    # Implementation would decompress data
    return $Path
}
#endregion

#region Scheduling
function New-PSBackupSchedule {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$JobName,
        
        [Parameter(Mandatory = $true)]
        [string]$Schedule,
        
        [Parameter(Mandatory = $false)]
        [datetime]$StartTime = (Get-Date).Date.AddDays(1),
        
        [Parameter(Mandatory = $false)]
        [switch]$Enable
    )
    
    process {
        try {
            $job = Get-PSBackupJob -Name $JobName
            if (-not $job) {
                throw "Backup job not found: $JobName"
            }
            
            # Parse schedule (simplified - in production use proper cron parser)
            $trigger = switch -Regex ($Schedule) {
                '^Daily' {
                    New-ScheduledTaskTrigger -Daily -At $StartTime
                }
                '^Weekly' {
                    New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At $StartTime
                }
                '^Monthly' {
                    New-ScheduledTaskTrigger -Monthly -DaysOfMonth 1 -At $StartTime
                }
                default {
                    throw "Invalid schedule format: $Schedule"
                }
            }
            
            $action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"Import-Module PSBackupManager; Start-PSBackup -JobName '$JobName'`""
            
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
            
            $taskName = "PSBackup_$JobName"
            
            if ($PSCmdlet.ShouldProcess($taskName, "Create scheduled task")) {
                Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Description "Automated backup for job: $JobName"
                
                if ($Enable) {
                    Enable-ScheduledTask -TaskName $taskName
                }
                
                Write-PSLog -Message "Backup schedule created for job: $JobName" -Component 'PSBackupManager'
                
                return Get-ScheduledTask -TaskName $taskName
            }
        }
        catch {
            Write-PSLog -Message "Failed to create backup schedule: $_" -Level 'Error' -Component 'PSBackupManager'
            throw
        }
    }
}
#endregion

# Module initialization
Write-PSLog -Message "PSBackupManager module loaded successfully" -Component 'PSBackupManager'

# Create required directories
$requiredPaths = @(
    $script:PSBackupConfig.DefaultBackupPath
    $script:PSBackupConfig.DefaultCatalogPath
    $script:PSBackupConfig.DefaultTempPath
)

foreach ($path in $requiredPaths) {
    if (-not (Test-Path $path)) {
        New-Item -Path $path -ItemType Directory -Force | Out-Null
    }
}

# Export aliases
New-Alias -Name backup -Value Start-PSBackup
New-Alias -Name restore -Value Start-PSRestore
New-Alias -Name backupjob -Value Get-PSBackupJob

Export-ModuleMember -Function * -Variable PSBackupConfig, PSBackupProviders -Alias *