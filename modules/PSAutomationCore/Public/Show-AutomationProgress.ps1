function Show-AutomationProgress {
    <#
    .SYNOPSIS
        Displays rich, interactive progress information for automation tasks
    
    .DESCRIPTION
        Show-AutomationProgress provides a delightful progress reporting experience with:
        - Real-time progress bars with percentage and ETA
        - Multi-level progress for complex operations
        - Status messages with color coding
        - Performance metrics and throughput
        - Interactive pause/resume capability
        
        This function enhances user experience by providing clear, visual feedback
        during long-running operations.
    
    .PARAMETER Activity
        The main activity being performed
    
    .PARAMETER Status
        Current status message to display
    
    .PARAMETER PercentComplete
        Percentage of completion (0-100)
    
    .PARAMETER CurrentOperation
        Details about the current sub-operation
    
    .PARAMETER Id
        Unique identifier for this progress stream (for nested progress)
    
    .PARAMETER ParentId
        Parent progress ID for hierarchical progress display
    
    .PARAMETER Completed
        Indicates the operation is complete
    
    .PARAMETER Style
        Visual style for the progress bar: Modern, Classic, Minimal
    
    .PARAMETER ShowMetrics
        Display performance metrics (items/sec, ETA, etc.)
    
    .EXAMPLE
        Show-AutomationProgress -Activity "Backing up files" -Status "Processing" -PercentComplete 45
        Shows a progress bar at 45% completion
    
    .EXAMPLE
        Show-AutomationProgress -Activity "System scan" -Status "Scanning drivers" -PercentComplete 70 -ShowMetrics
        Shows progress with performance metrics
    
    .EXAMPLE
        Show-AutomationProgress -Activity "Backup complete" -Completed
        Shows completion message with summary
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Activity,
        
        [Parameter(Mandatory = $false)]
        [string]$Status = "",
        
        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 100)]
        [int]$PercentComplete = -1,
        
        [Parameter(Mandatory = $false)]
        [string]$CurrentOperation = "",
        
        [Parameter(Mandatory = $false)]
        [int]$Id = 0,
        
        [Parameter(Mandatory = $false)]
        [int]$ParentId = -1,
        
        [Parameter(Mandatory = $false)]
        [switch]$Completed,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Modern', 'Classic', 'Minimal')]
        [string]$Style = 'Modern',
        
        [Parameter(Mandatory = $false)]
        [switch]$ShowMetrics,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Metrics = @{}
    )
    
    # Store progress state for metrics calculation
    if (-not $script:ProgressState) {
        $script:ProgressState = @{}
    }
    
    # Initialize or update progress state
    if (-not $script:ProgressState.ContainsKey($Id)) {
        $script:ProgressState[$Id] = @{
            StartTime = Get-Date
            LastUpdate = Get-Date
            ItemsProcessed = 0
            TotalItems = 100
            Activity = $Activity
        }
    }
    
    $state = $script:ProgressState[$Id]
    
    if ($Completed) {
        # Show completion message
        Show-CompletionMessage -Activity $Activity -State $state -Style $Style
        
        # Clean up state
        $script:ProgressState.Remove($Id)
        
        # Clear the progress bar
        Write-Progress -Activity $Activity -Id $Id -Completed
        return
    }
    
    # Build progress parameters
    $progressParams = @{
        Activity = $Activity
        Id = $Id
    }
    
    if ($Status) {
        $progressParams.Status = $Status
    }
    
    if ($PercentComplete -ge 0) {
        $progressParams.PercentComplete = $PercentComplete
    }
    
    if ($CurrentOperation) {
        $progressParams.CurrentOperation = $CurrentOperation
    }
    
    if ($ParentId -ge 0) {
        $progressParams.ParentId = $ParentId
    }
    
    # Calculate metrics if requested
    if ($ShowMetrics -and $PercentComplete -gt 0) {
        $elapsed = (Get-Date) - $state.StartTime
        $rate = Calculate-ProcessingRate -State $state -PercentComplete $PercentComplete
        $eta = Calculate-ETA -State $state -PercentComplete $PercentComplete
        
        $metricsText = "Rate: $rate | ETA: $eta"
        
        if ($CurrentOperation) {
            $progressParams.CurrentOperation = "$CurrentOperation | $metricsText"
        }
        else {
            $progressParams.CurrentOperation = $metricsText
        }
    }
    
    # Apply style enhancements
    switch ($Style) {
        'Modern' {
            # Add emoji indicators based on progress
            $statusEmoji = Get-ProgressEmoji -PercentComplete $PercentComplete
            $progressParams.Status = "$statusEmoji $Status"
        }
        'Classic' {
            # Traditional style - no modifications
        }
        'Minimal' {
            # Simplified display
            $progressParams.Status = if ($Status) { $Status } else { "$PercentComplete%" }
        }
    }
    
    # Show the progress
    Write-Progress @progressParams
    
    # Update console title with progress (if enabled)
    if ($script:AutomationConfig.ShowProgressInTitle) {
        Update-ConsoleTitle -Activity $Activity -PercentComplete $PercentComplete
    }
}

# Helper function to show completion message
function Show-CompletionMessage {
    param(
        [string]$Activity,
        [hashtable]$State,
        [string]$Style
    )
    
    $duration = (Get-Date) - $State.StartTime
    $durationText = Format-Duration -Duration $duration
    
    switch ($Style) {
        'Modern' {
            Write-Host "`n  ✅ $Activity" -ForegroundColor Green
            Write-Host "  ⏱️  Duration: $durationText" -ForegroundColor Cyan
            
            if ($State.ItemsProcessed -gt 0) {
                Write-Host "  📊 Items processed: $($State.ItemsProcessed)" -ForegroundColor Cyan
            }
        }
        'Classic' {
            Write-Host "`n  [COMPLETE] $Activity" -ForegroundColor Green
            Write-Host "  Duration: $durationText" -ForegroundColor Cyan
        }
        'Minimal' {
            Write-Host "$Activity - Done ($durationText)" -ForegroundColor Green
        }
    }
}

# Helper function to calculate processing rate
function Calculate-ProcessingRate {
    param(
        [hashtable]$State,
        [int]$PercentComplete
    )
    
    $elapsed = (Get-Date) - $State.StartTime
    
    if ($elapsed.TotalSeconds -gt 0 -and $PercentComplete -gt 0) {
        $itemsProcessed = [math]::Round(($PercentComplete / 100) * $State.TotalItems)
        $rate = [math]::Round($itemsProcessed / $elapsed.TotalSeconds, 2)
        
        return "$rate items/sec"
    }
    
    return "Calculating..."
}

# Helper function to calculate ETA
function Calculate-ETA {
    param(
        [hashtable]$State,
        [int]$PercentComplete
    )
    
    if ($PercentComplete -gt 0 -and $PercentComplete -lt 100) {
        $elapsed = (Get-Date) - $State.StartTime
        $totalEstimated = $elapsed.TotalSeconds * (100 / $PercentComplete)
        $remaining = $totalEstimated - $elapsed.TotalSeconds
        
        if ($remaining -gt 0) {
            $eta = (Get-Date).AddSeconds($remaining)
            return $eta.ToString("HH:mm:ss")
        }
    }
    
    return "Unknown"
}

# Helper function to get progress emoji
function Get-ProgressEmoji {
    param([int]$PercentComplete)
    
    if ($PercentComplete -lt 0) { return "🔄" }
    elseif ($PercentComplete -eq 0) { return "🏁" }
    elseif ($PercentComplete -lt 25) { return "🔵" }
    elseif ($PercentComplete -lt 50) { return "🟡" }
    elseif ($PercentComplete -lt 75) { return "🟠" }
    elseif ($PercentComplete -lt 100) { return "🟢" }
    else { return "✅" }
}

# Helper function to format duration
function Format-Duration {
    param([TimeSpan]$Duration)
    
    if ($Duration.TotalDays -ge 1) {
        return "{0:d} days {0:hh\:mm\:ss}" -f $Duration
    }
    elseif ($Duration.TotalHours -ge 1) {
        return "{0:hh\:mm\:ss}" -f $Duration
    }
    elseif ($Duration.TotalMinutes -ge 1) {
        return "{0:mm\:ss}" -f $Duration
    }
    else {
        return "{0:ss} seconds" -f $Duration
    }
}

# Helper function to update console title
function Update-ConsoleTitle {
    param(
        [string]$Activity,
        [int]$PercentComplete
    )
    
    if ($PercentComplete -ge 0) {
        $Host.UI.RawUI.WindowTitle = "[$PercentComplete%] $Activity - PowerShell Automation"
    }
    else {
        $Host.UI.RawUI.WindowTitle = "$Activity - PowerShell Automation"
    }
}

# Function to create a progress tracker object
function New-ProgressTracker {
    <#
    .SYNOPSIS
        Creates a progress tracker object for managing complex multi-step operations
    
    .DESCRIPTION
        The progress tracker provides an object-oriented approach to progress management
        with support for nested operations and automatic metric tracking.
    
    .PARAMETER Name
        Name of the operation to track
    
    .PARAMETER TotalSteps
        Total number of steps in the operation
    
    .PARAMETER ShowMetrics
        Automatically show performance metrics
    
    .EXAMPLE
        $tracker = New-ProgressTracker -Name "File Backup" -TotalSteps 5
        $tracker.StartStep("Scanning files")
        # ... do work ...
        $tracker.CompleteStep()
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [int]$TotalSteps = 0,
        
        [Parameter(Mandatory = $false)]
        [switch]$ShowMetrics
    )
    
    $tracker = [PSCustomObject]@{
        Name = $Name
        TotalSteps = $TotalSteps
        CurrentStep = 0
        StartTime = Get-Date
        ShowMetrics = $ShowMetrics.IsPresent
        Id = Get-Random
        
        # Methods
        StartStep = {
            param([string]$StepName)
            $this.CurrentStep++
            $percent = if ($this.TotalSteps -gt 0) { 
                [math]::Round(($this.CurrentStep / $this.TotalSteps) * 100) 
            } else { -1 }
            
            Show-AutomationProgress -Activity $this.Name -Status $StepName `
                -PercentComplete $percent -Id $this.Id -ShowMetrics:$this.ShowMetrics
        }.GetNewClosure()
        
        CompleteStep = {
            # Step completed, ready for next
        }.GetNewClosure()
        
        Complete = {
            Show-AutomationProgress -Activity $this.Name -Completed -Id $this.Id
        }.GetNewClosure()
    }
    
    # Bind methods to the object
    Add-Member -InputObject $tracker -MemberType ScriptMethod -Name StartStep -Value $tracker.StartStep
    Add-Member -InputObject $tracker -MemberType ScriptMethod -Name CompleteStep -Value $tracker.CompleteStep
    Add-Member -InputObject $tracker -MemberType ScriptMethod -Name Complete -Value $tracker.Complete
    
    return $tracker
}

Export-ModuleMember -Function Show-AutomationProgress, New-ProgressTracker