function Write-AutomationLog {
    <#
    .SYNOPSIS
        Writes user-friendly, color-coded log messages with optional persistence
    
    .DESCRIPTION
        Write-AutomationLog provides an enhanced logging experience that makes
        monitoring automation tasks delightful:
        
        - Color-coded output with intuitive symbols
        - Structured logging with metadata support
        - Multiple output targets (console, file, event log)
        - Real-time log streaming capability
        - Log filtering and search functionality
        - Automatic log rotation and cleanup
        - Context preservation across related messages
        
        The function emphasizes clarity and readability while maintaining
        professional logging capabilities.
    
    .PARAMETER Message
        The log message to write
    
    .PARAMETER Level
        Log level: Debug, Info, Warning, Error, Success, Progress
    
    .PARAMETER Context
        Contextual information about the operation (job name, function, etc.)
    
    .PARAMETER Metadata
        Additional structured data to include with the log entry
    
    .PARAMETER NoConsole
        Suppress console output (still writes to log file)
    
    .PARAMETER NoFile
        Suppress file output (console only)
    
    .PARAMETER PassThru
        Return the log entry object
    
    .PARAMETER Indent
        Indentation level for hierarchical logging
    
    .EXAMPLE
        Write-AutomationLog "Backup started" -Level Info
        Simple informational message
    
    .EXAMPLE
        Write-AutomationLog "Connection failed" -Level Error -Context "DatabaseBackup" -Metadata @{Server="SQL01"; Error=$_.Exception.Message}
        Error message with context and metadata
    
    .EXAMPLE
        Write-AutomationLog "Processing item 5 of 10" -Level Progress -Indent 1
        Progress message with indentation
    #>
    
    [CmdletBinding()]
    [Alias('autolog')]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Debug', 'Info', 'Warning', 'Error', 'Success', 'Progress')]
        [string]$Level = 'Info',
        
        [Parameter(Mandatory = $false)]
        [string]$Context = '',
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Metadata = @{},
        
        [Parameter(Mandatory = $false)]
        [switch]$NoConsole,
        
        [Parameter(Mandatory = $false)]
        [switch]$NoFile,
        
        [Parameter(Mandatory = $false)]
        [switch]$PassThru,
        
        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 5)]
        [int]$Indent = 0
    )
    
    begin {
        # Initialize logging if needed
        if (-not $script:LoggingInitialized) {
            Initialize-Logging
        }
    }
    
    process {
        # Create log entry
        $logEntry = [PSCustomObject]@{
            Timestamp = Get-Date
            Level = $Level
            Message = $Message
            Context = $Context
            Metadata = $Metadata
            UserName = $env:USERNAME
            ComputerName = $env:COMPUTERNAME
            ProcessId = $PID
            ThreadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
        }
        
        # Console output
        if (-not $NoConsole) {
            Write-ConsoleLog -Entry $logEntry -Indent $Indent
        }
        
        # File output
        if (-not $NoFile) {
            Write-FileLog -Entry $logEntry
        }
        
        # Event log output for errors
        if ($Level -eq 'Error' -and $script:AutomationConfig.LogToEventLog) {
            Write-EventLogEntry -Entry $logEntry
        }
        
        # Update log statistics
        Update-LogStatistics -Level $Level
        
        # Return log entry if requested
        if ($PassThru) {
            return $logEntry
        }
    }
}

# Initialize logging subsystem
function Initialize-Logging {
    # Ensure log directory exists
    $logPath = $script:AutomationConfig.LogPath
    if (-not (Test-Path $logPath)) {
        New-Item -Path $logPath -ItemType Directory -Force | Out-Null
    }
    
    # Initialize log file
    $script:CurrentLogFile = Join-Path $logPath "Automation-$(Get-Date -Format 'yyyy-MM-dd').log"
    
    # Create log file with header if it doesn't exist
    if (-not (Test-Path $script:CurrentLogFile)) {
        $header = @"
════════════════════════════════════════════════════════════════════════
PowerShell Automation Platform Log
Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
User: $env:USERNAME
Computer: $env:COMPUTERNAME
════════════════════════════════════════════════════════════════════════
"@
        Set-Content -Path $script:CurrentLogFile -Value $header -Encoding UTF8
    }
    
    # Initialize statistics
    $script:LogStatistics = @{
        Debug = 0
        Info = 0
        Warning = 0
        Error = 0
        Success = 0
        Progress = 0
        StartTime = Get-Date
    }
    
    # Check and rotate logs if needed
    Invoke-LogRotation
    
    $script:LoggingInitialized = $true
}

# Write formatted console output
function Write-ConsoleLog {
    param($Entry, [int]$Indent)
    
    # Get theme settings
    $theme = $script:AutomationTheme[$Entry.Level]
    if (-not $theme) {
        $theme = @{ Foreground = 'Gray'; Symbol = '?' }
    }
    
    # Build indentation
    $indentStr = "  " * $Indent
    
    # Format timestamp
    $timestamp = $Entry.Timestamp.ToString("HH:mm:ss")
    
    # Build console output
    $output = "$indentStr[$timestamp] "
    
    # Add symbol and level
    Write-Host $output -NoNewline -ForegroundColor DarkGray
    Write-Host "$($theme.Symbol) " -NoNewline -ForegroundColor $theme.Foreground
    
    # Add context if present
    if ($Entry.Context) {
        Write-Host "[$($Entry.Context)] " -NoNewline -ForegroundColor Cyan
    }
    
    # Write message
    Write-Host $Entry.Message -ForegroundColor $theme.Foreground
    
    # Add metadata if present and verbose
    if ($Entry.Metadata.Count -gt 0 -and $VerbosePreference -ne 'SilentlyContinue') {
        $metadataStr = ($Entry.Metadata.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; '
        Write-Host "$indentStr      └─ $metadataStr" -ForegroundColor DarkGray
    }
}

# Write to log file
function Write-FileLog {
    param($Entry)
    
    # Format log entry as JSON for structured logging
    $logLine = $Entry | ConvertTo-Json -Compress
    
    # Append to log file with lock to prevent conflicts
    $retries = 3
    while ($retries -gt 0) {
        try {
            [System.IO.File]::AppendAllText($script:CurrentLogFile, "$logLine`n", [System.Text.Encoding]::UTF8)
            break
        }
        catch {
            $retries--
            if ($retries -eq 0) {
                Write-Warning "Failed to write to log file: $_"
            }
            else {
                Start-Sleep -Milliseconds 100
            }
        }
    }
}

# Write to Windows Event Log
function Write-EventLogEntry {
    param($Entry)
    
    try {
        # Ensure event source exists
        $source = "PSAutomation"
        if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
            New-EventLog -LogName Application -Source $source -ErrorAction SilentlyContinue
        }
        
        # Map our levels to event log entry types
        $entryType = switch ($Entry.Level) {
            'Error' { 'Error' }
            'Warning' { 'Warning' }
            default { 'Information' }
        }
        
        # Create event message
        $eventMessage = @"
$($Entry.Message)

Context: $($Entry.Context)
User: $($Entry.UserName)
Computer: $($Entry.ComputerName)

Metadata:
$(($Entry.Metadata.GetEnumerator() | ForEach-Object { "  $($_.Key): $($_.Value)" }) -join "`n")
"@
        
        Write-EventLog -LogName Application -Source $source -EntryType $entryType -EventId 1000 -Message $eventMessage
    }
    catch {
        # Silently fail - event log writing is not critical
    }
}

# Update log statistics
function Update-LogStatistics {
    param([string]$Level)
    
    if ($script:LogStatistics.ContainsKey($Level)) {
        $script:LogStatistics[$Level]++
    }
}

# Perform log rotation
function Invoke-LogRotation {
    try {
        $logPath = $script:AutomationConfig.LogPath
        $maxSizeMB = $script:AutomationConfig.MaxLogSizeMB
        $retentionDays = $script:AutomationConfig.LogRetentionDays
        
        # Check current log size
        if (Test-Path $script:CurrentLogFile) {
            $currentSize = (Get-Item $script:CurrentLogFile).Length / 1MB
            
            if ($currentSize -gt $maxSizeMB) {
                # Rotate current log
                $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
                $archiveName = "Automation-$(Get-Date -Format 'yyyy-MM-dd')-$timestamp.log"
                $archivePath = Join-Path $logPath "Archive"
                
                if (-not (Test-Path $archivePath)) {
                    New-Item -Path $archivePath -ItemType Directory -Force | Out-Null
                }
                
                Move-Item -Path $script:CurrentLogFile -Destination (Join-Path $archivePath $archiveName) -Force
                
                # Create new log file
                Initialize-Logging
            }
        }
        
        # Clean up old logs
        $cutoffDate = (Get-Date).AddDays(-$retentionDays)
        Get-ChildItem -Path $logPath -Filter "*.log" -Recurse |
            Where-Object { $_.LastWriteTime -lt $cutoffDate } |
            Remove-Item -Force
    }
    catch {
        # Log rotation failure should not stop logging
        Write-Warning "Log rotation failed: $_"
    }
}

# Function to get recent log entries
function Get-AutomationLog {
    <#
    .SYNOPSIS
        Retrieves and displays automation log entries with filtering options
    
    .DESCRIPTION
        Provides an easy way to view, search, and analyze log entries with
        various filtering and display options.
    
    .PARAMETER Last
        Number of most recent entries to retrieve
    
    .PARAMETER Level
        Filter by log level
    
    .PARAMETER Context
        Filter by context
    
    .PARAMETER Since
        Show logs since specified datetime
    
    .PARAMETER Search
        Search for text in log messages
    
    .PARAMETER Live
        Show live log updates (tail -f style)
    
    .EXAMPLE
        Get-AutomationLog -Last 20
        Show last 20 log entries
    
    .EXAMPLE
        Get-AutomationLog -Level Error -Since (Get-Date).AddHours(-1)
        Show all errors from the last hour
    
    .EXAMPLE
        Get-AutomationLog -Live
        Show live log updates
    #>
    
    [CmdletBinding()]
    [Alias('autolog')]
    param(
        [Parameter(Mandatory = $false)]
        [int]$Last = 50,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Debug', 'Info', 'Warning', 'Error', 'Success', 'Progress', 'All')]
        [string]$Level = 'All',
        
        [Parameter(Mandatory = $false)]
        [string]$Context = '',
        
        [Parameter(Mandatory = $false)]
        [datetime]$Since,
        
        [Parameter(Mandatory = $false)]
        [string]$Search = '',
        
        [Parameter(Mandatory = $false)]
        [switch]$Live
    )
    
    if ($Live) {
        Show-LiveLog -Level $Level -Context $Context -Search $Search
    }
    else {
        Get-LogEntries -Last $Last -Level $Level -Context $Context -Since $Since -Search $Search |
            Format-LogDisplay
    }
}

# Function to show live log updates
function Show-LiveLog {
    param(
        [string]$Level,
        [string]$Context,
        [string]$Search
    )
    
    Write-Host "`n📡 Live Log Viewer (Press Ctrl+C to stop)" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════" -ForegroundColor Cyan
    
    $lastPosition = 0
    if (Test-Path $script:CurrentLogFile) {
        $lastPosition = (Get-Item $script:CurrentLogFile).Length
    }
    
    try {
        while ($true) {
            if (Test-Path $script:CurrentLogFile) {
                $currentPosition = (Get-Item $script:CurrentLogFile).Length
                
                if ($currentPosition -gt $lastPosition) {
                    # Read new content
                    $reader = [System.IO.StreamReader]::new($script:CurrentLogFile)
                    $reader.BaseStream.Seek($lastPosition, [System.IO.SeekOrigin]::Begin) | Out-Null
                    
                    while ($reader.Peek() -ge 0) {
                        $line = $reader.ReadLine()
                        try {
                            $entry = $line | ConvertFrom-Json
                            
                            # Apply filters
                            if (($Level -eq 'All' -or $entry.Level -eq $Level) -and
                                ($Context -eq '' -or $entry.Context -like "*$Context*") -and
                                ($Search -eq '' -or $entry.Message -like "*$Search*")) {
                                
                                Write-ConsoleLog -Entry $entry -Indent 0
                            }
                        }
                        catch {
                            # Skip malformed lines
                        }
                    }
                    
                    $reader.Close()
                    $lastPosition = $currentPosition
                }
            }
            
            Start-Sleep -Milliseconds 500
        }
    }
    catch {
        Write-Host "`nLive log viewing stopped." -ForegroundColor Yellow
    }
}

# Function to get log statistics
function Get-LogStatistics {
    <#
    .SYNOPSIS
        Shows log statistics and summary information
    #>
    
    [CmdletBinding()]
    param()
    
    Write-Host "`n📊 Log Statistics" -ForegroundColor Cyan
    Write-Host "════════════════" -ForegroundColor Cyan
    
    if ($script:LogStatistics) {
        $duration = (Get-Date) - $script:LogStatistics.StartTime
        
        Write-Host "`n  Session Duration: $($duration.ToString('hh\:mm\:ss'))" -ForegroundColor White
        Write-Host "`n  Message Counts:" -ForegroundColor White
        
        foreach ($level in @('Success', 'Info', 'Progress', 'Warning', 'Error', 'Debug')) {
            $count = $script:LogStatistics[$level]
            $color = switch ($level) {
                'Success' { 'Green' }
                'Info' { 'Cyan' }
                'Progress' { 'Blue' }
                'Warning' { 'Yellow' }
                'Error' { 'Red' }
                'Debug' { 'Gray' }
            }
            
            $bar = '█' * [Math]::Min($count, 50)
            Write-Host "    $level`: " -ForegroundColor $color -NoNewline
            Write-Host "$count " -ForegroundColor White -NoNewline
            Write-Host $bar -ForegroundColor $color
        }
        
        # Log file info
        if (Test-Path $script:CurrentLogFile) {
            $fileInfo = Get-Item $script:CurrentLogFile
            Write-Host "`n  Current Log File:" -ForegroundColor White
            Write-Host "    Path: $($fileInfo.FullName)" -ForegroundColor Gray
            Write-Host "    Size: $([Math]::Round($fileInfo.Length / 1KB, 2)) KB" -ForegroundColor Gray
        }
    }
}

# Export functions
Export-ModuleMember -Function Write-AutomationLog, Get-AutomationLog, Get-LogStatistics -Alias autolog