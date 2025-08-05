<#
.SYNOPSIS
    Generates comprehensive backup health reports with monitoring dashboards and analytics.
.DESCRIPTION
    This script creates detailed backup health reports including backup job status, storage
    utilization, success rates, performance trends, and compliance metrics. Supports
    multiple report formats and automated dashboard generation for backup monitoring.
.PARAMETER BackupPath
    Path to backup repository or backup server to analyze.
.PARAMETER ReportType
    Type of report: Summary, Detailed, Trend, or Compliance.
.PARAMETER Days
    Number of days to analyze for trend reports (default: 30).
.PARAMETER OutputPath
    Directory to save generated reports and dashboards.
.PARAMETER Format
    Output format: JSON, HTML, CSV, or Dashboard.
.PARAMETER IncludeMetrics
    If specified, includes detailed performance metrics and analytics.
.PARAMETER ThresholdConfig
    Path to JSON file containing alert thresholds and compliance requirements.
.PARAMETER EmailReport
    If specified, emails the report to configured recipients.
.PARAMETER GenerateDashboard
    If specified, creates an interactive HTML dashboard.
.EXAMPLE
    .\Get-BackupHealthReport.ps1 -BackupPath "\\backup-server\backups" -ReportType "Summary" -Format "HTML"
.EXAMPLE
    .\Get-BackupHealthReport.ps1 -BackupPath "C:\Backups" -ReportType "Trend" -Days 90 -GenerateDashboard
.NOTES
    Author: System Administrator
    Requires: PSAdminCore module, backup repository access
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BackupPath,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Summary", "Detailed", "Trend", "Compliance")]
    [string]$ReportType = "Summary",
    
    [Parameter(Mandatory = $false)]
    [int]$Days = 30,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:TEMP\BackupReports",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("JSON", "HTML", "CSV", "Dashboard")]
    [string]$Format = "HTML",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeMetrics,
    
    [Parameter(Mandatory = $false)]
    [string]$ThresholdConfig,
    
    [Parameter(Mandatory = $false)]
    [switch]$EmailReport,
    
    [Parameter(Mandatory = $false)]
    [switch]$GenerateDashboard
)

# Import required modules

if (Test-Path $modulePath) {
    Import-Module $modulePath -Force
} else {
    # Fall back to installed module
    Import-Module PSAdminCore -Force -ErrorAction Stop
}

    Import-Module PSAdminCore -Force -ErrorAction Stop
}

Write-AdminLog -Message "Starting backup health report generation (Type: $ReportType)" -Level "Info"

# Function to analyze backup patterns
function Get-BackupPatterns {
    param([array]$BackupFiles)
    
    try {
        $patterns = @{
            DailyBackups = @{}
            WeeklyTrends = @{}
            SizePatterns = @{}
            TypeDistribution = @{}
        }
        
        foreach ($file in $BackupFiles) {
            $date = $file.LastWriteTime.Date
            $dayOfWeek = $file.LastWriteTime.DayOfWeek
            $hour = $file.LastWriteTime.Hour
            
            # Daily patterns
            $dateKey = $date.ToString("yyyy-MM-dd")
            if (-not $patterns.DailyBackups.ContainsKey($dateKey)) {
                $patterns.DailyBackups[$dateKey] = @{
                    Count = 0
                    TotalSizeMB = 0
                    Files = @()
                }
            }
            $patterns.DailyBackups[$dateKey].Count++
            $patterns.DailyBackups[$dateKey].TotalSizeMB += [math]::Round($file.Length / 1MB, 2)
            $patterns.DailyBackups[$dateKey].Files += $file.Name
            
            # Weekly trends
            if (-not $patterns.WeeklyTrends.ContainsKey($dayOfWeek)) {
                $patterns.WeeklyTrends[$dayOfWeek] = @{ Count = 0; AvgSizeMB = 0; TotalSizeMB = 0 }
            }
            $patterns.WeeklyTrends[$dayOfWeek].Count++
            $patterns.WeeklyTrends[$dayOfWeek].TotalSizeMB += [math]::Round($file.Length / 1MB, 2)
            
            # Size patterns
            $sizeCategory = switch ($file.Length) {
                { $_ -lt 100MB } { "Small (<100MB)" }
                { $_ -lt 1GB } { "Medium (100MB-1GB)" }
                { $_ -lt 10GB } { "Large (1GB-10GB)" }
                default { "VeryLarge (>10GB)" }
            }
            if (-not $patterns.SizePatterns.ContainsKey($sizeCategory)) {
                $patterns.SizePatterns[$sizeCategory] = 0
            }
            $patterns.SizePatterns[$sizeCategory]++
            
            # Type distribution
            $extension = $file.Extension.ToLower()
            if (-not $patterns.TypeDistribution.ContainsKey($extension)) {
                $patterns.TypeDistribution[$extension] = @{ Count = 0; TotalSizeMB = 0 }
            }
            $patterns.TypeDistribution[$extension].Count++
            $patterns.TypeDistribution[$extension].TotalSizeMB += [math]::Round($file.Length / 1MB, 2)
        }
        
        # Calculate averages
        foreach ($day in $patterns.WeeklyTrends.Keys) {
            if ($patterns.WeeklyTrends[$day].Count -gt 0) {
                $patterns.WeeklyTrends[$day].AvgSizeMB = [math]::Round($patterns.WeeklyTrends[$day].TotalSizeMB / $patterns.WeeklyTrends[$day].Count, 2)
            }
        }
        
        return $patterns
    } catch {
        Write-AdminLog -Message "Failed to analyze backup patterns: $($_.Exception.Message)" -Level "Error"
        return @{}
    }
}

# Function to calculate backup metrics
function Get-BackupMetrics {
    param([array]$BackupFiles, [int]$Days)
    
    try {
        $startDate = (Get-Date).AddDays(-$Days)
        $recentFiles = $BackupFiles | Where-Object { $_.LastWriteTime -gt $startDate }
        
        $metrics = @{
            TotalFiles = $BackupFiles.Count
            RecentFiles = $recentFiles.Count
            TotalSizeGB = [math]::Round(($BackupFiles | Measure-Object Length -Sum).Sum / 1GB, 2)
            RecentSizeGB = [math]::Round(($recentFiles | Measure-Object Length -Sum).Sum / 1GB, 2)
            AverageFileSizeMB = if ($BackupFiles.Count -gt 0) { 
                [math]::Round(($BackupFiles | Measure-Object Length -Average).Average / 1MB, 2) 
            } else { 0 }
            OldestBackup = if ($BackupFiles) { ($BackupFiles | Sort-Object LastWriteTime | Select-Object -First 1).LastWriteTime } else { $null }
            NewestBackup = if ($BackupFiles) { ($BackupFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime } else { $null }
            BackupFrequency = @{}
            GrowthRate = @{}
            HealthScore = 0
        }
        
        # Calculate backup frequency (backups per day)
        if ($recentFiles.Count -gt 0) {
            $dateGroups = $recentFiles | Group-Object { $_.LastWriteTime.Date.ToString("yyyy-MM-dd") }
            $metrics.BackupFrequency = @{
                AveragePerDay = [math]::Round($dateGroups.Count / $Days, 2)
                MaxPerDay = ($dateGroups | Measure-Object Count -Maximum).Maximum
                MinPerDay = ($dateGroups | Measure-Object Count -Minimum).Minimum
                DaysWithBackups = $dateGroups.Count
                DaysWithoutBackups = $Days - $dateGroups.Count
            }
        }
        
        # Calculate growth rate
        if ($BackupFiles.Count -gt 1) {
            $sortedFiles = $BackupFiles | Sort-Object LastWriteTime
            $oldestSize = $sortedFiles[0].Length
            $newestSize = $sortedFiles[-1].Length
            $timeSpan = $sortedFiles[-1].LastWriteTime - $sortedFiles[0].LastWriteTime
            
            if ($timeSpan.TotalDays -gt 0 -and $oldestSize -gt 0) {
                $dailyGrowthRate = (($newestSize - $oldestSize) / $oldestSize) / $timeSpan.TotalDays * 100
                $metrics.GrowthRate = @{
                    DailyPercentage = [math]::Round($dailyGrowthRate, 4)
                    MonthlyPercentage = [math]::Round($dailyGrowthRate * 30, 2)
                    ProjectedSizeGB30Days = [math]::Round($metrics.TotalSizeGB * (1 + ($dailyGrowthRate * 30 / 100)), 2)
                }
            }
        }
        
        # Calculate health score (0-100)
        $healthFactors = @{
            RecentActivity = if ($Days -gt 0) { [math]::Min(100, ($metrics.BackupFrequency.DaysWithBackups / $Days) * 100) } else { 0 }
            SizeConsistency = if ($metrics.AverageFileSizeMB -gt 0) { 
                $sizeVariance = ($BackupFiles | Measure-Object Length -StandardDeviation).StandardDeviation / ($BackupFiles | Measure-Object Length -Average).Average
                [math]::Max(0, 100 - ($sizeVariance * 100))
            } else { 0 }
            FrequencyConsistency = if ($metrics.BackupFrequency.AveragePerDay -gt 0) {
                $freqVariance = ($metrics.BackupFrequency.MaxPerDay - $metrics.BackupFrequency.MinPerDay) / $metrics.BackupFrequency.AveragePerDay
                [math]::Max(0, 100 - ($freqVariance * 50))
            } else { 0 }
        }
        
        $metrics.HealthScore = [math]::Round(($healthFactors.Values | Measure-Object -Average).Average, 2)
        
        return $metrics
    } catch {
        Write-AdminLog -Message "Failed to calculate backup metrics: $($_.Exception.Message)" -Level "Error"
        return @{}
    }
}

# Function to check compliance thresholds
function Test-BackupCompliance {
    param([hashtable]$Metrics, [string]$ThresholdConfigPath)
    
    try {
        $defaultThresholds = @{
            MinDailyBackups = 1
            MaxDaysWithoutBackup = 2
            MinHealthScore = 80
            MaxBackupAge = 24
            MinFreeDiskSpaceGB = 50
            MaxBackupSizeGB = 1000
        }
        
        $thresholds = $defaultThresholds
        
        if ($ThresholdConfigPath -and (Test-Path $ThresholdConfigPath)) {
            try {
                $customThresholds = Get-Content $ThresholdConfigPath | ConvertFrom-Json
                foreach ($key in $customThresholds.PSObject.Properties.Name) {
                    $thresholds[$key] = $customThresholds.$key
                }
                Write-AdminLog -Message "Loaded custom compliance thresholds" -Level "Info"
            } catch {
                Write-AdminLog -Message "Failed to load custom thresholds, using defaults" -Level "Warning"
            }
        }
        
        $compliance = @{
            OverallCompliant = $true
            Violations = @()
            Warnings = @()
            Score = 100
            Thresholds = $thresholds
        }
        
        # Check daily backup frequency
        if ($Metrics.BackupFrequency.AveragePerDay -lt $thresholds.MinDailyBackups) {
            $compliance.Violations += "Average daily backups ($($Metrics.BackupFrequency.AveragePerDay)) below threshold ($($thresholds.MinDailyBackups))"
            $compliance.OverallCompliant = $false
            $compliance.Score -= 20
        }
        
        # Check days without backup
        if ($Metrics.BackupFrequency.DaysWithoutBackups -gt $thresholds.MaxDaysWithoutBackup) {
            $compliance.Violations += "Days without backup ($($Metrics.BackupFrequency.DaysWithoutBackups)) exceeds threshold ($($thresholds.MaxDaysWithoutBackup))"
            $compliance.OverallCompliant = $false
            $compliance.Score -= 25
        }
        
        # Check health score
        if ($Metrics.HealthScore -lt $thresholds.MinHealthScore) {
            $compliance.Violations += "Health score ($($Metrics.HealthScore)) below threshold ($($thresholds.MinHealthScore))"
            $compliance.OverallCompliant = $false
            $compliance.Score -= 15
        }
        
        # Check backup age
        if ($Metrics.NewestBackup) {
            $hoursSinceLastBackup = ((Get-Date) - $Metrics.NewestBackup).TotalHours
            if ($hoursSinceLastBackup -gt $thresholds.MaxBackupAge) {
                $compliance.Violations += "Last backup age ($([math]::Round($hoursSinceLastBackup, 1)) hours) exceeds threshold ($($thresholds.MaxBackupAge) hours)"
                $compliance.OverallCompliant = $false
                $compliance.Score -= 30
            }
        }
        
        # Check storage size
        if ($Metrics.TotalSizeGB -gt $thresholds.MaxBackupSizeGB) {
            $compliance.Warnings += "Total backup size ($($Metrics.TotalSizeGB) GB) approaching threshold ($($thresholds.MaxBackupSizeGB) GB)"
            $compliance.Score -= 5
        }
        
        # Check disk space (if backup path is local)
        if ($BackupPath -match "^[A-Z]:" -or $BackupPath.StartsWith("\\localhost\")) {
            try {
                $drive = (Get-Item $BackupPath).PSDrive
                $freeSpaceGB = [math]::Round($drive.Free / 1GB, 2)
                if ($freeSpaceGB -lt $thresholds.MinFreeDiskSpaceGB) {
                    $compliance.Violations += "Free disk space ($freeSpaceGB GB) below threshold ($($thresholds.MinFreeDiskSpaceGB) GB)"
                    $compliance.OverallCompliant = $false
                    $compliance.Score -= 20
                }
            } catch {
                $compliance.Warnings += "Unable to check disk space: $($_.Exception.Message)"
            }
        }
        
        $compliance.Score = [math]::Max(0, $compliance.Score)
        return $compliance
    } catch {
        Write-AdminLog -Message "Failed to check compliance: $($_.Exception.Message)" -Level "Error"
        return @{ OverallCompliant = $false; Violations = @("Compliance check failed"); Score = 0 }
    }
}

# Function to generate HTML dashboard
function New-BackupDashboard {
    param([hashtable]$ReportData, [string]$OutputPath)
    
    try {
        $dashboardHtml = @"
<!DOCTYPE html>
<html>
<head>
    <title>Backup Health Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .card { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .card h3 { margin-top: 0; color: #333; border-bottom: 2px solid #007acc; padding-bottom: 10px; }
        .metric { display: flex; justify-content: space-between; align-items: center; margin: 10px 0; }
        .metric-value { font-size: 1.5em; font-weight: bold; }
        .status-good { color: #28a745; }
        .status-warning { color: #ffc107; }
        .status-danger { color: #dc3545; }
        .health-score { font-size: 2em; text-align: center; margin: 20px 0; }
        .compliance-item { padding: 5px 0; border-bottom: 1px solid #eee; }
        .chart-container { height: 300px; margin: 20px 0; }
        .summary-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; }
        .summary-item { text-align: center; padding: 15px; background: #f8f9fa; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>Backup Health Dashboard</h1>
    <p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | <strong>Report Type:</strong> $($ReportData.ReportType) | <strong>Period:</strong> $($ReportData.Days) days</p>
    
    <div class="dashboard">
        <div class="card">
            <h3>Overall Health</h3>
            <div class="health-score $(if ($ReportData.Metrics.HealthScore -ge 80) { 'status-good' } elseif ($ReportData.Metrics.HealthScore -ge 60) { 'status-warning' } else { 'status-danger' })">
                $($ReportData.Metrics.HealthScore)%
            </div>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="metric-value">$($ReportData.Metrics.TotalFiles)</div>
                    <div>Total Backups</div>
                </div>
                <div class="summary-item">
                    <div class="metric-value">$($ReportData.Metrics.TotalSizeGB)</div>
                    <div>Total Size (GB)</div>
                </div>
                <div class="summary-item">
                    <div class="metric-value">$($ReportData.Metrics.RecentFiles)</div>
                    <div>Recent Backups</div>
                </div>
                <div class="summary-item">
                    <div class="metric-value">$($ReportData.Metrics.BackupFrequency.AveragePerDay)</div>
                    <div>Avg Daily Backups</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h3>Compliance Status</h3>
            <div class="metric">
                <span>Overall Compliance:</span>
                <span class="metric-value $(if ($ReportData.Compliance.OverallCompliant) { 'status-good' } else { 'status-danger' })">
                    $(if ($ReportData.Compliance.OverallCompliant) { 'PASS' } else { 'FAIL' })
                </span>
            </div>
            <div class="metric">
                <span>Compliance Score:</span>
                <span class="metric-value">$($ReportData.Compliance.Score)%</span>
            </div>
            <div style="margin-top: 15px;">
                <strong>Violations:</strong>
                $(if ($ReportData.Compliance.Violations.Count -eq 0) { '<div class="status-good">None</div>' } else { 
                    $ReportData.Compliance.Violations | ForEach-Object { "<div class='compliance-item status-danger'>$_</div>" } | Out-String
                })
            </div>
            <div style="margin-top: 15px;">
                <strong>Warnings:</strong>
                $(if ($ReportData.Compliance.Warnings.Count -eq 0) { '<div class="status-good">None</div>' } else { 
                    $ReportData.Compliance.Warnings | ForEach-Object { "<div class='compliance-item status-warning'>$_</div>" } | Out-String
                })
            </div>
        </div>
        
        <div class="card">
            <h3>Backup Frequency</h3>
            <div class="chart-container">
                <canvas id="frequencyChart"></canvas>
            </div>
            <div class="metric">
                <span>Days with Backups:</span>
                <span class="metric-value">$($ReportData.Metrics.BackupFrequency.DaysWithBackups)</span>
            </div>
            <div class="metric">
                <span>Days without Backups:</span>
                <span class="metric-value">$($ReportData.Metrics.BackupFrequency.DaysWithoutBackups)</span>
            </div>
        </div>
        
        <div class="card">
            <h3>Storage Analysis</h3>
            <div class="chart-container">
                <canvas id="storageChart"></canvas>
            </div>
            <div class="metric">
                <span>Average File Size:</span>
                <span class="metric-value">$($ReportData.Metrics.AverageFileSizeMB) MB</span>
            </div>
            <div class="metric">
                <span>Growth Rate (Monthly):</span>
                <span class="metric-value">$($ReportData.Metrics.GrowthRate.MonthlyPercentage)%</span>
            </div>
        </div>
    </div>
    
    <script>
        // Frequency Chart
        const frequencyCtx = document.getElementById('frequencyChart').getContext('2d');
        new Chart(frequencyCtx, {
            type: 'line',
            data: {
                labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                datasets: [{
                    label: 'Backups per Day',
                    data: [
                        $($ReportData.Patterns.WeeklyTrends.Monday.Count),
                        $($ReportData.Patterns.WeeklyTrends.Tuesday.Count),
                        $($ReportData.Patterns.WeeklyTrends.Wednesday.Count),
                        $($ReportData.Patterns.WeeklyTrends.Thursday.Count),
                        $($ReportData.Patterns.WeeklyTrends.Friday.Count),
                        $($ReportData.Patterns.WeeklyTrends.Saturday.Count),
                        $($ReportData.Patterns.WeeklyTrends.Sunday.Count)
                    ],
                    borderColor: '#007acc',
                    backgroundColor: 'rgba(0, 122, 204, 0.1)',
                    tension: 0.4
                }]
            },
            options: { responsive: true, maintainAspectRatio: false }
        });
        
        // Storage Chart
        const storageCtx = document.getElementById('storageChart').getContext('2d');
        new Chart(storageCtx, {
            type: 'doughnut',
            data: {
                labels: [$(($ReportData.Patterns.SizePatterns.Keys | ForEach-Object { "'$_'" }) -join ',')],
                datasets: [{
                    data: [$(($ReportData.Patterns.SizePatterns.Values) -join ',')],
                    backgroundColor: ['#28a745', '#ffc107', '#fd7e14', '#dc3545']
                }]
            },
            options: { responsive: true, maintainAspectRatio: false }
        });
    </script>
</body>
</html>
"@
        
        $dashboardPath = Join-Path $OutputPath "BackupDashboard-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
        $dashboardHtml | Out-File -FilePath $dashboardPath -Encoding UTF8
        
        return $dashboardPath
    } catch {
        Write-AdminLog -Message "Failed to generate dashboard: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

try {
    # Validate backup path
    if (-not (Test-Path $BackupPath)) {
        throw "Backup path not found: $BackupPath"
    }
    
    # Create output directory
    if (-not (Test-Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }
    
    Write-AdminLog -Message "Analyzing backup repository: $BackupPath" -Level "Info"
    
    # Get backup files
    $backupFiles = Get-ChildItem $BackupPath -Recurse -File | Where-Object {
        $_.Extension -in @('.zip', '.bak', '.backup', '.gz', '.tar') -or 
        $_.Name -like "*backup*" -or 
        $_.Name -like "*.encrypted"
    }
    
    Write-AdminLog -Message "Found $($backupFiles.Count) backup files" -Level "Info"
    
    # Calculate date range for analysis
    $endDate = Get-Date
    $startDate = $endDate.AddDays(-$Days)
    $analysisFiles = $backupFiles | Where-Object { $_.LastWriteTime -gt $startDate }
    
    # Generate report data based on type
    $reportData = @{
        ReportType = $ReportType
        GeneratedDate = Get-Date
        BackupPath = $BackupPath
        Days = $Days
        AnalysisPeriod = "$($startDate.ToString('yyyy-MM-dd')) to $($endDate.ToString('yyyy-MM-dd'))"
        Metrics = @{}
        Patterns = @{}
        Compliance = @{}
        Recommendations = @()
    }
    
    switch ($ReportType) {
        "Summary" {
            Write-AdminLog -Message "Generating summary report..." -Level "Info"
            
            $reportData.Metrics = Get-BackupMetrics -BackupFiles $backupFiles -Days $Days
            $reportData.Compliance = Test-BackupCompliance -Metrics $reportData.Metrics -ThresholdConfigPath $ThresholdConfig
            
            # Generate basic recommendations
            if ($reportData.Metrics.BackupFrequency.DaysWithoutBackups -gt 1) {
                $reportData.Recommendations += "Consider increasing backup frequency - $($reportData.Metrics.BackupFrequency.DaysWithoutBackups) days without backups detected"
            }
            if ($reportData.Metrics.HealthScore -lt 80) {
                $reportData.Recommendations += "Backup health score is below optimal - review backup consistency and reliability"
            }
            if ($reportData.Metrics.GrowthRate.MonthlyPercentage -gt 50) {
                $reportData.Recommendations += "High storage growth rate detected - consider implementing compression or retention policies"
            }
        }
        
        "Detailed" {
            Write-AdminLog -Message "Generating detailed report..." -Level "Info"
            
            $reportData.Metrics = Get-BackupMetrics -BackupFiles $backupFiles -Days $Days
            $reportData.Patterns = Get-BackupPatterns -BackupFiles $analysisFiles
            $reportData.Compliance = Test-BackupCompliance -Metrics $reportData.Metrics -ThresholdConfigPath $ThresholdConfig
            
            # Detailed file analysis
            $reportData.FileAnalysis = $backupFiles | ForEach-Object {
                [PSCustomObject]@{
                    FileName = $_.Name
                    SizeMB = [math]::Round($_.Length / 1MB, 2)
                    Created = $_.CreationTime
                    Modified = $_.LastWriteTime
                    Age = [math]::Round(((Get-Date) - $_.LastWriteTime).TotalDays, 1)
                    Type = $_.Extension
                }
            } | Sort-Object Modified -Descending
        }
        
        "Trend" {
            Write-AdminLog -Message "Generating trend report..." -Level "Info"
            
            $reportData.Metrics = Get-BackupMetrics -BackupFiles $backupFiles -Days $Days
            $reportData.Patterns = Get-BackupPatterns -BackupFiles $analysisFiles
            
            # Additional trend analysis
            $dailyTrends = $analysisFiles | Group-Object { $_.LastWriteTime.Date.ToString("yyyy-MM-dd") } | 
                          Sort-Object Name | ForEach-Object {
                [PSCustomObject]@{
                    Date = $_.Name
                    Count = $_.Count
                    TotalSizeMB = [math]::Round(($_.Group | Measure-Object Length -Sum).Sum / 1MB, 2)
                    AverageSizeMB = [math]::Round(($_.Group | Measure-Object Length -Average).Average / 1MB, 2)
                }
            }
            
            $reportData.DailyTrends = $dailyTrends
        }
        
        "Compliance" {
            Write-AdminLog -Message "Generating compliance report..." -Level "Info"
            
            $reportData.Metrics = Get-BackupMetrics -BackupFiles $backupFiles -Days $Days
            $reportData.Compliance = Test-BackupCompliance -Metrics $reportData.Metrics -ThresholdConfigPath $ThresholdConfig
            
            # Detailed compliance analysis
            $reportData.ComplianceDetails = @{
                BackupRetention = @{
                    OldestBackupDays = if ($reportData.Metrics.OldestBackup) { 
                        [math]::Round(((Get-Date) - $reportData.Metrics.OldestBackup).TotalDays, 1) 
                    } else { 0 }
                    RetentionCompliance = "Not implemented in demo"
                }
                RPO_RTO = @{
                    RecoveryPointObjective = "To be configured"
                    RecoveryTimeObjective = "To be configured"
                    LastBackupAge = if ($reportData.Metrics.NewestBackup) { 
                        [math]::Round(((Get-Date) - $reportData.Metrics.NewestBackup).TotalHours, 1) 
                    } else { 0 }
                }
                SecurityCompliance = @{
                    EncryptedBackups = ($backupFiles | Where-Object { $_.Name -like "*.encrypted" }).Count
                    EncryptionPercentage = if ($backupFiles.Count -gt 0) { 
                        [math]::Round((($backupFiles | Where-Object { $_.Name -like "*.encrypted" }).Count / $backupFiles.Count) * 100, 2) 
                    } else { 0 }
                }
            }
        }
    }
    
    # Generate output files
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $baseFileName = "BackupHealth-$ReportType-$timestamp"
    $outputFiles = @()
    
    if ($Format -eq "JSON" -or $GenerateDashboard) {
        $jsonFile = Join-Path $OutputPath "$baseFileName.json"
        $reportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile -Encoding UTF8
        $outputFiles += $jsonFile
        Write-AdminLog -Message "JSON report saved: $jsonFile" -Level "Success"
    }
    
    if ($Format -eq "HTML" -or $GenerateDashboard) {
        $htmlFile = Join-Path $OutputPath "$baseFileName.html"
        
        $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Backup Health Report - $ReportType</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
        .header { background-color: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .section { margin: 20px 0; }
        .metric { display: flex; justify-content: space-between; padding: 5px 0; border-bottom: 1px solid #eee; }
        .status-good { color: green; font-weight: bold; }
        .status-warning { color: orange; font-weight: bold; }
        .status-danger { color: red; font-weight: bold; }
        table { border-collapse: collapse; width: 100%; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .health-score { font-size: 24px; text-align: center; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Backup Health Report - $ReportType</h1>
        <p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p><strong>Backup Path:</strong> $BackupPath</p>
        <p><strong>Analysis Period:</strong> $($reportData.AnalysisPeriod)</p>
    </div>
    
    <div class="section">
        <h2>Overall Health Score</h2>
        <div class="health-score $(if ($reportData.Metrics.HealthScore -ge 80) { 'status-good' } elseif ($reportData.Metrics.HealthScore -ge 60) { 'status-warning' } else { 'status-danger' })">
            $($reportData.Metrics.HealthScore)%
        </div>
    </div>
    
    <div class="section">
        <h2>Metrics Summary</h2>
        <div class="metric"><span>Total Backup Files:</span><span>$($reportData.Metrics.TotalFiles)</span></div>
        <div class="metric"><span>Total Size:</span><span>$($reportData.Metrics.TotalSizeGB) GB</span></div>
        <div class="metric"><span>Average Daily Backups:</span><span>$($reportData.Metrics.BackupFrequency.AveragePerDay)</span></div>
        <div class="metric"><span>Days Without Backups:</span><span>$($reportData.Metrics.BackupFrequency.DaysWithoutBackups)</span></div>
        <div class="metric"><span>Monthly Growth Rate:</span><span>$($reportData.Metrics.GrowthRate.MonthlyPercentage)%</span></div>
    </div>
    
    <div class="section">
        <h2>Compliance Status</h2>
        <div class="metric">
            <span>Overall Compliance:</span>
            <span class="$(if ($reportData.Compliance.OverallCompliant) { 'status-good' } else { 'status-danger' })">
                $(if ($reportData.Compliance.OverallCompliant) { 'COMPLIANT' } else { 'NON-COMPLIANT' })
            </span>
        </div>
        <div class="metric"><span>Compliance Score:</span><span>$($reportData.Compliance.Score)%</span></div>
        
        $(if ($reportData.Compliance.Violations.Count -gt 0) {
            "<h3>Violations:</h3><ul>" + 
            ($reportData.Compliance.Violations | ForEach-Object { "<li class='status-danger'>$_</li>" }) + 
            "</ul>"
        })
        
        $(if ($reportData.Compliance.Warnings.Count -gt 0) {
            "<h3>Warnings:</h3><ul>" + 
            ($reportData.Compliance.Warnings | ForEach-Object { "<li class='status-warning'>$_</li>" }) + 
            "</ul>"
        })
    </div>
    
    $(if ($reportData.Recommendations.Count -gt 0) {
        "<div class='section'><h2>Recommendations</h2><ul>" + 
        ($reportData.Recommendations | ForEach-Object { "<li>$_</li>" }) + 
        "</ul></div>"
    })
    
    <div class="section">
        <h2>Detailed Data</h2>
        <pre>$($reportData | ConvertTo-Json -Depth 3)</pre>
    </div>
</body>
</html>
"@
        
        $htmlContent | Out-File -FilePath $htmlFile -Encoding UTF8
        $outputFiles += $htmlFile
        Write-AdminLog -Message "HTML report saved: $htmlFile" -Level "Success"
    }
    
    if ($Format -eq "CSV") {
        $csvFile = Join-Path $OutputPath "$baseFileName.csv"
        
        if ($reportData.FileAnalysis) {
            $reportData.FileAnalysis | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
        } else {
            # Create summary CSV
            $summaryData = @()
            foreach ($key in $reportData.Metrics.Keys) {
                $value = $reportData.Metrics[$key]
                if ($value -is [hashtable]) {
                    foreach ($subKey in $value.Keys) {
                        $summaryData += [PSCustomObject]@{
                            Category = $key
                            Metric = $subKey
                            Value = $value[$subKey]
                        }
                    }
                } else {
                    $summaryData += [PSCustomObject]@{
                        Category = "General"
                        Metric = $key
                        Value = $value
                    }
                }
            }
            $summaryData | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
        }
        
        $outputFiles += $csvFile
        Write-AdminLog -Message "CSV report saved: $csvFile" -Level "Success"
    }
    
    # Generate interactive dashboard
    if ($GenerateDashboard) {
        Write-AdminLog -Message "Generating interactive dashboard..." -Level "Info"
        $dashboardPath = New-BackupDashboard -ReportData $reportData -OutputPath $OutputPath
        if ($dashboardPath) {
            $outputFiles += $dashboardPath
            Write-AdminLog -Message "Interactive dashboard saved: $dashboardPath" -Level "Success"
        }
    }
    
    # Email report if requested
    if ($EmailReport) {
        $subject = "Backup Health Report - $ReportType"
        $complianceStatus = if ($reportData.Compliance.OverallCompliant) { "COMPLIANT" } else { "NON-COMPLIANT" }
        
        $body = @"
Backup Health Report - $ReportType

Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Backup Path: $BackupPath
Analysis Period: $($reportData.AnalysisPeriod)

Summary:
- Health Score: $($reportData.Metrics.HealthScore)%
- Compliance Status: $complianceStatus ($($reportData.Compliance.Score)%)
- Total Backups: $($reportData.Metrics.TotalFiles)
- Total Size: $($reportData.Metrics.TotalSizeGB) GB
- Recent Activity: $($reportData.Metrics.RecentFiles) backups in last $Days days

$(if ($reportData.Compliance.Violations.Count -gt 0) {
    "VIOLATIONS:" + "`n" + ($reportData.Compliance.Violations | ForEach-Object { "- $_" }) -join "`n"
})

Report files: $($outputFiles -join ', ')

Please review the detailed reports for more information.
"@
        
        try {
            Send-AdminNotification -Subject $subject -Body $body
            Write-AdminLog -Message "Report emailed successfully" -Level "Success"
        } catch {
            Write-AdminLog -Message "Failed to email report: $($_.Exception.Message)" -Level "Warning"
        }
    }
    
    # Generate final summary report
    $finalReport = New-AdminReport -ReportTitle "Backup Health Report Generation" -Data $reportData -Description "Backup health monitoring and analysis results" -Metadata @{
        ReportType = $ReportType
        Days = $Days
        Format = $Format
        OutputFiles = $outputFiles
        BackupFileCount = $backupFiles.Count
        HealthScore = $reportData.Metrics.HealthScore
        ComplianceStatus = $reportData.Compliance.OverallCompliant
    }
    
    Write-Output $finalReport
    Write-AdminLog -Message "Backup health report generation completed successfully" -Level "Success"
    
} catch {
    Write-AdminLog -Message "Backup health report generation failed: $($_.Exception.Message)" -Level "Error"
    throw
}
