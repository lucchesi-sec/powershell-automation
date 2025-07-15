function New-BackupJob {
    <#
    .SYNOPSIS
        Creates a new backup job with an intuitive, guided experience
    
    .DESCRIPTION
        New-BackupJob provides a delightful wizard-driven interface for creating backup jobs:
        - Interactive selection of files and folders
        - Smart suggestions based on common backup patterns
        - Real-time size estimation and validation
        - Schedule builder with conflict detection
        - Cloud provider setup assistance
        - Test run capability before saving
        - Template library for quick setup
        
        The wizard ensures your backup job is configured correctly the first time!
    
    .PARAMETER Name
        Name for the backup job
    
    .PARAMETER Source
        Source paths to backup (can be multiple)
    
    .PARAMETER Destination
        Primary backup destination
    
    .PARAMETER Schedule
        Backup schedule (Daily, Weekly, Monthly, or custom cron expression)
    
    .PARAMETER Template
        Use a predefined template: UserProfile, Documents, Database, FullSystem, Custom
    
    .PARAMETER Interactive
        Launch interactive wizard (default: true)
    
    .PARAMETER CloudBackup
        Enable cloud backup with guided setup
    
    .PARAMETER TestRun
        Perform a test run after configuration
    
    .EXAMPLE
        New-BackupJob
        Launches the interactive backup job wizard
    
    .EXAMPLE
        New-BackupJob -Name "Daily Documents" -Template Documents
        Creates a backup job using the Documents template
    
    .EXAMPLE
        New-BackupJob -Name "SQL Backup" -Source "C:\SQLData" -Destination "\\NAS\Backups" -Schedule Daily
        Creates a backup job with specified parameters
    #>
    
    [CmdletBinding()]
    [Alias('backup-wizard')]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Source,
        
        [Parameter(Mandatory = $false)]
        [string]$Destination,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Daily', 'Weekly', 'Monthly', 'Hourly', 'Custom')]
        [string]$Schedule,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('UserProfile', 'Documents', 'Database', 'FullSystem', 'Custom')]
        [string]$Template = 'Custom',
        
        [Parameter(Mandatory = $false)]
        [bool]$Interactive = $true,
        
        [Parameter(Mandatory = $false)]
        [switch]$CloudBackup,
        
        [Parameter(Mandatory = $false)]
        [switch]$TestRun
    )
    
    begin {
        $jobConfig = @{
            Name = $Name
            Source = @()
            Destination = $Destination
            CloudDestination = $null
            Schedule = @{}
            Options = @{
                Compression = $true
                CompressionLevel = 'Optimal'
                Encryption = $false
                Verification = $true
                RetentionDays = 30
                ExcludePatterns = @()
                IncludePatterns = @()
            }
            Notifications = @{
                OnSuccess = $true
                OnFailure = $true
                Recipients = @()
            }
            CreatedDate = Get-Date
            CreatedBy = $env:USERNAME
            Enabled = $true
        }
    }
    
    process {
        try {
            if ($Interactive -or -not $Name) {
                # Launch interactive wizard
                $jobConfig = Start-BackupJobWizard -InitialConfig $jobConfig -Template $Template
            }
            else {
                # Apply template if specified
                if ($Template -ne 'Custom') {
                    $jobConfig = Apply-BackupTemplate -Config $jobConfig -Template $Template
                }
                
                # Apply parameters
                if ($Source) { $jobConfig.Source = $Source }
                if ($Schedule) { $jobConfig.Schedule = Convert-ToScheduleObject -Schedule $Schedule }
            }
            
            # Cloud backup setup if requested
            if ($CloudBackup) {
                $jobConfig.CloudDestination = Setup-CloudBackup -JobName $jobConfig.Name
            }
            
            # Validate configuration
            $validation = Test-BackupJobConfiguration -Config $jobConfig
            if (-not $validation.IsValid) {
                Show-ValidationIssues -Issues $validation.Issues
                
                if ($Interactive) {
                    Write-Host "`nWould you like to fix these issues? (Y/N): " -ForegroundColor Cyan -NoNewline
                    $fix = Read-Host
                    
                    if ($fix -match '^[Yy]') {
                        $jobConfig = Fix-BackupConfiguration -Config $jobConfig -Issues $validation.Issues
                    }
                    else {
                        throw "Backup job configuration is invalid"
                    }
                }
                else {
                    throw "Backup job configuration validation failed"
                }
            }
            
            # Test run if requested
            if ($TestRun) {
                Write-Host "`n🧪 Performing test run..." -ForegroundColor Cyan
                $testResult = Test-BackupJob -Config $jobConfig
                
                Show-TestResults -Results $testResult
                
                if (-not $testResult.Success) {
                    Write-Host "`n⚠️  Test run encountered issues. Save anyway? (Y/N): " -ForegroundColor Yellow -NoNewline
                    $save = Read-Host
                    
                    if ($save -notmatch '^[Yy]') {
                        Write-Host "Backup job creation cancelled." -ForegroundColor Yellow
                        return
                    }
                }
            }
            
            # Save backup job
            $savedJob = Save-BackupJob -Config $jobConfig
            
            # Show success and next steps
            Show-BackupJobSuccess -Job $savedJob
            
            return $savedJob
        }
        catch {
            Write-Error "Failed to create backup job: $_"
            throw
        }
    }
}

# Start backup job wizard
function Start-BackupJobWizard {
    param(
        [hashtable]$InitialConfig,
        [string]$Template
    )
    
    Clear-Host
    
    Write-Host @"
    
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║              Backup Job Creation Wizard                       ║
    ║                                                               ║
    ║         Let's create the perfect backup strategy!             ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    
"@ -ForegroundColor Cyan
    
    # Step 1: Basic Information
    Write-Host "📋 Step 1: Basic Information" -ForegroundColor Yellow
    Write-Host "═══════════════════════════" -ForegroundColor Yellow
    
    if (-not $InitialConfig.Name) {
        do {
            Write-Host "`nBackup job name: " -ForegroundColor Cyan -NoNewline
            $name = Read-Host
            
            # Check if name already exists
            if (Test-BackupJobExists -Name $name) {
                Write-Host "❌ A backup job with this name already exists." -ForegroundColor Red
                Write-Host "Please choose a different name." -ForegroundColor Gray
                $name = ""
            }
        } while ([string]::IsNullOrWhiteSpace($name))
        
        $InitialConfig.Name = $name
    }
    
    Write-Host "Description (optional): " -ForegroundColor Cyan -NoNewline
    $description = Read-Host
    if ($description) {
        $InitialConfig.Description = $description
    }
    
    # Step 2: Template Selection
    if ($Template -eq 'Custom') {
        Write-Host "`n📑 Step 2: Template Selection" -ForegroundColor Yellow
        Write-Host "════════════════════════════" -ForegroundColor Yellow
        Write-Host "`nWould you like to start with a template?" -ForegroundColor White
        
        $templates = @(
            @{ Name = "User Profile"; Description = "Documents, Desktop, Pictures, etc." }
            @{ Name = "Documents Only"; Description = "Just your important documents" }
            @{ Name = "Development"; Description = "Code, projects, and repositories" }
            @{ Name = "Full System"; Description = "Complete system backup" }
            @{ Name = "Custom"; Description = "Build from scratch" }
        )
        
        for ($i = 0; $i -lt $templates.Count; $i++) {
            Write-Host "  [$($i+1)] $($templates[$i].Name) - " -ForegroundColor White -NoNewline
            Write-Host $templates[$i].Description -ForegroundColor Gray
        }
        
        Write-Host "`nSelect template (1-$($templates.Count)): " -ForegroundColor Cyan -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le $templates.Count) {
            $selectedTemplate = $templates[[int]$choice - 1].Name.Replace(' ', '')
            if ($selectedTemplate -ne 'Custom') {
                $InitialConfig = Apply-BackupTemplate -Config $InitialConfig -Template $selectedTemplate
                Write-Host "✅ Template applied!" -ForegroundColor Green
            }
        }
    }
    
    # Step 3: Source Selection
    Write-Host "`n📁 Step 3: What to Backup" -ForegroundColor Yellow
    Write-Host "════════════════════════" -ForegroundColor Yellow
    
    if ($InitialConfig.Source.Count -eq 0) {
        $InitialConfig.Source = Get-BackupSourcesInteractive
    }
    else {
        Write-Host "`nTemplate includes these locations:" -ForegroundColor White
        foreach ($source in $InitialConfig.Source) {
            Write-Host "  • $source" -ForegroundColor Cyan
        }
        
        Write-Host "`nWould you like to add more locations? (Y/N): " -ForegroundColor Yellow -NoNewline
        $addMore = Read-Host
        
        if ($addMore -match '^[Yy]') {
            $additionalSources = Get-BackupSourcesInteractive
            $InitialConfig.Source += $additionalSources
        }
    }
    
    # Estimate backup size
    Write-Host "`nCalculating backup size..." -ForegroundColor Cyan
    $sizeInfo = Get-BackupSizeEstimate -Paths $InitialConfig.Source
    Show-BackupSizeInfo -SizeInfo $sizeInfo
    
    # Step 4: Destination
    Write-Host "`n💾 Step 4: Where to Store Backups" -ForegroundColor Yellow
    Write-Host "═════════════════════════════════" -ForegroundColor Yellow
    
    $InitialConfig.Destination = Get-BackupDestinationInteractive -SizeRequired $sizeInfo.TotalSize
    
    # Optional cloud backup
    Write-Host "`n☁️  Would you like to add cloud backup? (Y/N): " -ForegroundColor Cyan -NoNewline
    $cloudChoice = Read-Host
    
    if ($cloudChoice -match '^[Yy]') {
        $InitialConfig.CloudDestination = Setup-CloudBackupInteractive
    }
    
    # Step 5: Schedule
    Write-Host "`n⏰ Step 5: Backup Schedule" -ForegroundColor Yellow
    Write-Host "═════════════════════════" -ForegroundColor Yellow
    
    $InitialConfig.Schedule = Get-BackupScheduleInteractive
    
    # Step 6: Options
    Write-Host "`n⚙️  Step 6: Backup Options" -ForegroundColor Yellow
    Write-Host "═════════════════════════" -ForegroundColor Yellow
    
    $InitialConfig.Options = Get-BackupOptionsInteractive -CurrentOptions $InitialConfig.Options
    
    # Step 7: Notifications
    Write-Host "`n📧 Step 7: Notifications" -ForegroundColor Yellow
    Write-Host "═══════════════════════" -ForegroundColor Yellow
    
    Write-Host "`nWould you like email notifications? (Y/N): " -ForegroundColor Cyan -NoNewline
    $notifyChoice = Read-Host
    
    if ($notifyChoice -match '^[Yy]') {
        Write-Host "Email address: " -ForegroundColor Cyan -NoNewline
        $email = Read-Host
        
        if ($email -match '^[^@]+@[^@]+\.[^@]+$') {
            $InitialConfig.Notifications.Recipients = @($email)
            
            Write-Host "`nNotify on:" -ForegroundColor White
            Write-Host "  [1] Failures only" -ForegroundColor Gray
            Write-Host "  [2] Success and failures (recommended)" -ForegroundColor Gray
            Write-Host "  [3] All events (verbose)" -ForegroundColor Gray
            
            Write-Host "`nChoice (1-3): " -ForegroundColor Cyan -NoNewline
            $notifyLevel = Read-Host
            
            switch ($notifyLevel) {
                '1' { 
                    $InitialConfig.Notifications.OnSuccess = $false
                    $InitialConfig.Notifications.OnFailure = $true
                }
                '3' {
                    $InitialConfig.Notifications.Verbose = $true
                }
            }
        }
    }
    
    # Step 8: Review and Confirm
    Write-Host "`n✅ Step 8: Review Configuration" -ForegroundColor Yellow
    Write-Host "═══════════════════════════════" -ForegroundColor Yellow
    
    Show-BackupJobSummary -Config $InitialConfig
    
    Write-Host "`nIs everything correct? (Y/N): " -ForegroundColor Cyan -NoNewline
    $confirm = Read-Host
    
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "`nWhat would you like to change?" -ForegroundColor Yellow
        $InitialConfig = Edit-BackupConfiguration -Config $InitialConfig
    }
    
    return $InitialConfig
}

# Get backup sources interactively
function Get-BackupSourcesInteractive {
    $sources = @()
    
    Write-Host "`nHow would you like to select files to backup?" -ForegroundColor White
    Write-Host "  [1] Quick selection (common folders)" -ForegroundColor Gray
    Write-Host "  [2] Browse and select" -ForegroundColor Gray
    Write-Host "  [3] Type paths manually" -ForegroundColor Gray
    
    Write-Host "`nChoice (1-3): " -ForegroundColor Cyan -NoNewline
    $method = Read-Host
    
    switch ($method) {
        '1' {
            # Quick selection
            $commonFolders = @(
                @{ Path = [Environment]::GetFolderPath('MyDocuments'); Name = 'Documents' }
                @{ Path = [Environment]::GetFolderPath('Desktop'); Name = 'Desktop' }
                @{ Path = [Environment]::GetFolderPath('MyPictures'); Name = 'Pictures' }
                @{ Path = [Environment]::GetFolderPath('MyVideos'); Name = 'Videos' }
                @{ Path = [Environment]::GetFolderPath('MyMusic'); Name = 'Music' }
                @{ Path = "$env:USERPROFILE\Downloads"; Name = 'Downloads' }
                @{ Path = "$env:APPDATA"; Name = 'Application Data' }
            )
            
            Write-Host "`nSelect folders to backup (space-separated numbers):" -ForegroundColor White
            
            for ($i = 0; $i -lt $commonFolders.Count; $i++) {
                if (Test-Path $commonFolders[$i].Path) {
                    $size = Get-FolderSize -Path $commonFolders[$i].Path
                    Write-Host "  [$($i+1)] $($commonFolders[$i].Name) ($size)" -ForegroundColor Gray
                }
            }
            
            Write-Host "`nYour selection: " -ForegroundColor Cyan -NoNewline
            $selection = Read-Host
            
            $indices = $selection -split '\s+' | Where-Object { $_ -match '^\d+$' }
            foreach ($index in $indices) {
                $idx = [int]$index - 1
                if ($idx -ge 0 -and $idx -lt $commonFolders.Count) {
                    $sources += $commonFolders[$idx].Path
                }
            }
        }
        '2' {
            # Browse and select
            Write-Host "`nOpening folder browser..." -ForegroundColor Cyan
            
            Add-Type -AssemblyName System.Windows.Forms
            
            do {
                $browser = New-Object System.Windows.Forms.FolderBrowserDialog
                $browser.Description = "Select a folder to backup"
                $browser.ShowNewFolderButton = $false
                
                if ($browser.ShowDialog() -eq 'OK') {
                    $sources += $browser.SelectedPath
                    Write-Host "✅ Added: $($browser.SelectedPath)" -ForegroundColor Green
                    
                    Write-Host "Add another folder? (Y/N): " -ForegroundColor Cyan -NoNewline
                    $more = Read-Host
                } else {
                    $more = 'N'
                }
            } while ($more -match '^[Yy]')
        }
        '3' {
            # Manual entry
            Write-Host "`nEnter paths to backup (one per line, empty line to finish):" -ForegroundColor White
            
            do {
                Write-Host "> " -ForegroundColor Cyan -NoNewline
                $path = Read-Host
                
                if ($path) {
                    if (Test-Path $path) {
                        $sources += $path
                        Write-Host "✅ Valid path" -ForegroundColor Green
                    }
                    else {
                        Write-Host "❌ Path not found: $path" -ForegroundColor Red
                    }
                }
            } while ($path)
        }
    }
    
    return $sources
}

# Get backup size estimate
function Get-BackupSizeEstimate {
    param([string[]]$Paths)
    
    $totalSize = 0
    $fileCount = 0
    $issues = @()
    
    foreach ($path in $Paths) {
        if (Test-Path $path) {
            try {
                $items = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue
                $pathSize = ($items | Measure-Object Length -Sum).Sum
                $totalSize += $pathSize
                $fileCount += $items.Count
            }
            catch {
                $issues += "Cannot access some files in: $path"
            }
        }
    }
    
    return @{
        TotalSize = $totalSize
        FileCount = $fileCount
        FormattedSize = Format-ByteSize -Bytes $totalSize
        EstimatedCompressed = Format-ByteSize -Bytes ([Math]::Round($totalSize * 0.6))
        Issues = $issues
    }
}

# Format byte size
function Format-ByteSize {
    param([long]$Bytes)
    
    $sizes = 'B', 'KB', 'MB', 'GB', 'TB'
    $index = 0
    $size = $Bytes
    
    while ($size -ge 1024 -and $index -lt $sizes.Count - 1) {
        $size = $size / 1024
        $index++
    }
    
    return "{0:N2} {1}" -f $size, $sizes[$index]
}

# Show backup size info
function Show-BackupSizeInfo {
    param($SizeInfo)
    
    Write-Host "`n📊 Backup Size Estimate:" -ForegroundColor White
    Write-Host "  Files to backup:      $($SizeInfo.FileCount)" -ForegroundColor Gray
    Write-Host "  Total size:           $($SizeInfo.FormattedSize)" -ForegroundColor Gray
    Write-Host "  Compressed (est.):    $($SizeInfo.EstimatedCompressed)" -ForegroundColor Green
    
    if ($SizeInfo.Issues.Count -gt 0) {
        Write-Host "`n⚠️  Some files may not be accessible:" -ForegroundColor Yellow
        foreach ($issue in $SizeInfo.Issues) {
            Write-Host "  • $issue" -ForegroundColor Gray
        }
    }
}

# Get backup destination interactively
function Get-BackupDestinationInteractive {
    param([long]$SizeRequired)
    
    Write-Host "`nWhere would you like to store your backups?" -ForegroundColor White
    Write-Host "  [1] Local drive" -ForegroundColor Gray
    Write-Host "  [2] Network location (NAS/Server)" -ForegroundColor Gray
    Write-Host "  [3] External USB drive" -ForegroundColor Gray
    Write-Host "  [4] Let me type the path" -ForegroundColor Gray
    
    Write-Host "`nChoice (1-4): " -ForegroundColor Cyan -NoNewline
    $choice = Read-Host
    
    switch ($choice) {
        '1' {
            # Local drive selection
            $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -ne $null }
            
            Write-Host "`nAvailable drives:" -ForegroundColor White
            foreach ($drive in $drives) {
                $free = Format-ByteSize -Bytes $drive.Free
                $used = Format-ByteSize -Bytes $drive.Used
                $percent = [Math]::Round(($drive.Used / ($drive.Used + $drive.Free)) * 100)
                
                Write-Host "  [$($drive.Name):] " -NoNewline
                Write-Host "$free free " -ForegroundColor Green -NoNewline
                Write-Host "of $(Format-ByteSize -Bytes ($drive.Used + $drive.Free)) " -NoNewline
                Write-Host "($percent% used)" -ForegroundColor Gray
            }
            
            Write-Host "`nSelect drive letter: " -ForegroundColor Cyan -NoNewline
            $driveLetter = Read-Host
            
            $destination = "${driveLetter}:\Backups\$($InitialConfig.Name)"
        }
        '2' {
            # Network location
            Write-Host "`nEnter network path (e.g., \\\\server\\share): " -ForegroundColor Cyan -NoNewline
            $netPath = Read-Host
            
            if (Test-Path $netPath) {
                Write-Host "✅ Network location is accessible" -ForegroundColor Green
                $destination = Join-Path $netPath "Backups\$($InitialConfig.Name)"
            }
            else {
                Write-Host "⚠️  Cannot access network location. It will be created during first backup." -ForegroundColor Yellow
                $destination = Join-Path $netPath "Backups\$($InitialConfig.Name)"
            }
        }
        '3' {
            # External drive
            $externalDrives = Get-WmiObject Win32_LogicalDisk | 
                Where-Object { $_.DriveType -eq 2 -or ($_.DriveType -eq 3 -and $_.VolumeName) }
            
            if ($externalDrives) {
                Write-Host "`nDetected external drives:" -ForegroundColor White
                foreach ($drive in $externalDrives) {
                    $free = Format-ByteSize -Bytes $drive.FreeSpace
                    Write-Host "  [$($drive.DeviceID)] $($drive.VolumeName) - $free free" -ForegroundColor Gray
                }
                
                Write-Host "`nSelect drive letter: " -ForegroundColor Cyan -NoNewline
                $driveLetter = Read-Host
                $destination = "${driveLetter}:\Backups\$($InitialConfig.Name)"
            }
            else {
                Write-Host "❌ No external drives detected. Please connect one and try again." -ForegroundColor Red
                return Get-BackupDestinationInteractive -SizeRequired $SizeRequired
            }
        }
        '4' {
            Write-Host "`nEnter backup destination path: " -ForegroundColor Cyan -NoNewline
            $destination = Read-Host
        }
    }
    
    # Verify destination has enough space
    if ($destination -match '^[A-Z]:\\') {
        $drive = Get-PSDrive -Name $destination[0]
        if ($drive.Free -lt ($SizeRequired * 2)) {
            Write-Host "`n⚠️  Warning: Limited space on destination drive" -ForegroundColor Yellow
            Write-Host "  Required: $(Format-ByteSize -Bytes ($SizeRequired * 2))" -ForegroundColor Gray
            Write-Host "  Available: $(Format-ByteSize -Bytes $drive.Free)" -ForegroundColor Gray
        }
    }
    
    return $destination
}

# Show backup job summary
function Show-BackupJobSummary {
    param($Config)
    
    Write-Host "`n📋 Backup Job Configuration Summary" -ForegroundColor Cyan
    Write-Host "══════════════════════════════════" -ForegroundColor Cyan
    
    Write-Host "`nName:        " -ForegroundColor Gray -NoNewline
    Write-Host $Config.Name -ForegroundColor White
    
    if ($Config.Description) {
        Write-Host "Description: " -ForegroundColor Gray -NoNewline
        Write-Host $Config.Description -ForegroundColor White
    }
    
    Write-Host "`nSources:" -ForegroundColor Gray
    foreach ($source in $Config.Source) {
        Write-Host "  • $source" -ForegroundColor Cyan
    }
    
    Write-Host "`nDestination: " -ForegroundColor Gray -NoNewline
    Write-Host $Config.Destination -ForegroundColor Cyan
    
    if ($Config.CloudDestination) {
        Write-Host "Cloud:       " -ForegroundColor Gray -NoNewline
        Write-Host $Config.CloudDestination.Provider -ForegroundColor Cyan
    }
    
    Write-Host "`nSchedule:    " -ForegroundColor Gray -NoNewline
    Write-Host (Format-BackupSchedule -Schedule $Config.Schedule) -ForegroundColor Yellow
    
    Write-Host "`nOptions:" -ForegroundColor Gray
    Write-Host "  • Compression: $($Config.Options.Compression) ($($Config.Options.CompressionLevel))" -ForegroundColor Gray
    Write-Host "  • Encryption: $($Config.Options.Encryption)" -ForegroundColor Gray
    Write-Host "  • Verification: $($Config.Options.Verification)" -ForegroundColor Gray
    Write-Host "  • Retention: $($Config.Options.RetentionDays) days" -ForegroundColor Gray
    
    if ($Config.Notifications.Recipients.Count -gt 0) {
        Write-Host "`nNotifications: " -ForegroundColor Gray -NoNewline
        Write-Host ($Config.Notifications.Recipients -join ', ') -ForegroundColor Cyan
    }
}

# Show backup job success
function Show-BackupJobSuccess {
    param($Job)
    
    Write-Host "`n✅ Backup Job Created Successfully!" -ForegroundColor Green
    Write-Host "══════════════════════════════════" -ForegroundColor Green
    
    Write-Host "`n📁 Job saved to: " -ForegroundColor Gray -NoNewline
    Write-Host $Job.ConfigPath -ForegroundColor Cyan
    
    # Calculate next run time
    $nextRun = Get-NextScheduledTime -Schedule $Job.Schedule
    Write-Host "`n⏰ Next scheduled run: " -ForegroundColor Gray -NoNewline
    Write-Host $nextRun.ToString('yyyy-MM-dd HH:mm') -ForegroundColor Yellow
    
    Write-Host "`n🚀 Quick Actions:" -ForegroundColor Cyan
    Write-Host "  • Run now:        " -ForegroundColor Gray -NoNewline
    Write-Host "Start-BackupJob -Name '$($Job.Name)'" -ForegroundColor White
    
    Write-Host "  • Watch progress: " -ForegroundColor Gray -NoNewline
    Write-Host "Watch-BackupProgress -Name '$($Job.Name)'" -ForegroundColor White
    
    Write-Host "  • View schedule:  " -ForegroundColor Gray -NoNewline
    Write-Host "Get-BackupSchedule -Name '$($Job.Name)'" -ForegroundColor White
    
    Write-Host "  • Test backup:    " -ForegroundColor Gray -NoNewline
    Write-Host "Test-Backup -Name '$($Job.Name)'" -ForegroundColor White
    
    Write-Host "`n💡 Tip: " -ForegroundColor Magenta -NoNewline
    Write-Host "Your backup job is now active and will run automatically!" -ForegroundColor White
    
    # Offer to run now
    Write-Host "`nWould you like to run the backup now? (Y/N): " -ForegroundColor Cyan -NoNewline
    $runNow = Read-Host
    
    if ($runNow -match '^[Yy]') {
        Write-Host "`nStarting backup..." -ForegroundColor Green
        Start-BackupJob -Name $Job.Name
    }
}

# Initialize function
function Initialize-BackupService {
    # Create required directories
    @($script:BackupServiceConfig.JobsPath, 
      $script:BackupServiceConfig.HistoryPath,
      $script:BackupServiceConfig.TempPath) | ForEach-Object {
        if (-not (Test-Path $_)) {
            New-Item -Path $_ -ItemType Directory -Force | Out-Null
        }
    }
}

Export-ModuleMember -Function New-BackupJob -Alias backup-wizard