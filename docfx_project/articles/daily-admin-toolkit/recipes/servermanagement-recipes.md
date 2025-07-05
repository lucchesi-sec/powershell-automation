# ServerManagement Recipes

## Overview

The ServerManagement module provides comprehensive tools for monitoring server health, testing connectivity, and managing remote systems. These recipes cover essential daily server administration tasks with real-world scenarios.

## Prerequisites

- **PowerShell Remoting** enabled on target servers
- **Administrative privileges** on target systems
- **Network connectivity** to managed servers
- **WinRM service** running on target machines
- **Firewall exceptions** for PowerShell remoting (typically port 5985/5986)

```powershell
# Verify prerequisites
Test-WSMan -ComputerName 'SERVER01'

# Import the ServerManagement module
Import-Module ProjectName.ServerManagement

# Test module availability
Get-Command -Module ProjectName.ServerManagement
```

## Recipe 1: Server Health Checks

### Scenario
You need to perform morning health checks across your server infrastructure to identify issues before users report problems.

### Solution

```powershell
# Basic health check for a single server
Get-ServerHealth -ComputerName 'SERVER01'

# Health check multiple servers
$servers = @('WEB01', 'WEB02', 'DB01', 'FILE01')
Get-ServerHealth -ComputerName $servers | Format-Table -AutoSize

# Detailed health report
Get-ServerHealth -ComputerName 'SERVER01' -Detailed | Format-List

# Filter for unhealthy servers only
Get-ServerHealth -ComputerName $servers | 
    Where-Object { $_.OverallStatus -ne 'Healthy' } |
    Sort-Object ComputerName
```

### Advanced Usage

```powershell
# Comprehensive morning health check routine
function Start-MorningHealthCheck {
    param(
        [Parameter(Mandatory)]
        [string[]]$ServerList,
        
        [string]$ReportPath = "C:\Admin\HealthReports",
        
        [switch]$EmailReport
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = Join-Path $ReportPath "HealthCheck_$timestamp.html"
    
    # Ensure report directory exists
    if (-not (Test-Path $ReportPath)) {
        New-Item -Path $ReportPath -ItemType Directory -Force
    }
    
    Write-Host "🔍 Starting health check for $($ServerList.Count) servers..." -ForegroundColor Cyan
    
    $healthResults = @()
    $failedServers = @()
    
    foreach ($server in $ServerList) {
        Write-Progress -Activity "Health Check" -Status "Checking $server" -PercentComplete (($healthResults.Count / $ServerList.Count) * 100)
        
        try {
            $health = Get-ServerHealth -ComputerName $server -Detailed
            $healthResults += $health
            
            if ($health.OverallStatus -ne 'Healthy') {
                $failedServers += $server
                Write-Warning "⚠️  Issues found on $server"
            } else {
                Write-Host "✅ $server is healthy" -ForegroundColor Green
            }
        } catch {
            $healthResults += [PSCustomObject]@{
                ComputerName = $server
                OverallStatus = 'Error'
                ErrorMessage = $_.Exception.Message
                Timestamp = Get-Date
            }
            $failedServers += $server
            Write-Error "❌ Failed to check $server`: $($_.Exception.Message)"
        }
    }
    
    # Generate HTML report
    $htmlReport = $healthResults | ConvertTo-Html -Title "Server Health Report - $(Get-Date)" -PreContent "<h1>Daily Health Check Report</h1><p>Generated: $(Get-Date)</p>"
    $htmlReport | Out-File -FilePath $reportFile -Encoding UTF8
    
    # Summary
    $summary = @{
        TotalServers = $ServerList.Count
        HealthyServers = ($healthResults | Where-Object { $_.OverallStatus -eq 'Healthy' }).Count
        UnhealthyServers = $failedServers.Count
        ReportPath = $reportFile
        Timestamp = Get-Date
    }
    
    Write-Host "`n📊 Health Check Summary:" -ForegroundColor Yellow
    Write-Host "   Total Servers: $($summary.TotalServers)" -ForegroundColor White
    Write-Host "   Healthy: $($summary.HealthyServers)" -ForegroundColor Green
    Write-Host "   Issues: $($summary.UnhealthyServers)" -ForegroundColor Red
    Write-Host "   Report: $($summary.ReportPath)" -ForegroundColor Cyan
    
    if ($EmailReport -and $failedServers.Count -gt 0) {
        Send-HealthAlertEmail -FailedServers $failedServers -ReportPath $reportFile
    }
    
    return $summary
}

# Usage
$serverList = Get-Content "C:\Admin\ProductionServers.txt"
$report = Start-MorningHealthCheck -ServerList $serverList -EmailReport
```

### Custom Health Checks

```powershell
# Define custom health check criteria
function Get-CustomServerHealth {
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [hashtable]$Thresholds = @{
            CPUThreshold = 80
            MemoryThreshold = 85
            DiskThreshold = 90
        }
    )
    
    $healthData = @{
        ComputerName = $ComputerName
        Timestamp = Get-Date
        Checks = @()
    }
    
    try {
        # CPU Usage Check
        $cpu = Get-Counter "\\$ComputerName\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples 3
        $avgCPU = ($cpu.CounterSamples | Measure-Object CookedValue -Average).Average
        
        $healthData.Checks += @{
            Check = "CPU Usage"
            Value = [math]::Round($avgCPU, 2)
            Threshold = $Thresholds.CPUThreshold
            Status = if ($avgCPU -gt $Thresholds.CPUThreshold) { "Warning" } else { "OK" }
        }
        
        # Memory Usage Check
        $memory = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName
        $memoryPercent = [math]::Round((($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory) / $memory.TotalVisibleMemorySize) * 100, 2)
        
        $healthData.Checks += @{
            Check = "Memory Usage"
            Value = $memoryPercent
            Threshold = $Thresholds.MemoryThreshold
            Status = if ($memoryPercent -gt $Thresholds.MemoryThreshold) { "Warning" } else { "OK" }
        }
        
        # Disk Space Check
        $disks = Get-WmiObject -Class Win32_LogicalDisk -ComputerName $ComputerName | Where-Object { $_.DriveType -eq 3 }
        foreach ($disk in $disks) {
            $diskPercent = [math]::Round((($disk.Size - $disk.FreeSpace) / $disk.Size) * 100, 2)
            
            $healthData.Checks += @{
                Check = "Disk Space ($($disk.DeviceID))"
                Value = $diskPercent
                Threshold = $Thresholds.DiskThreshold
                Status = if ($diskPercent -gt $Thresholds.DiskThreshold) { "Critical" } else { "OK" }
            }
        }
        
        # Overall Status
        $criticalCount = ($healthData.Checks | Where-Object { $_.Status -eq "Critical" }).Count
        $warningCount = ($healthData.Checks | Where-Object { $_.Status -eq "Warning" }).Count
        
        $healthData.OverallStatus = if ($criticalCount -gt 0) { "Critical" } 
                                  elseif ($warningCount -gt 0) { "Warning" } 
                                  else { "Healthy" }
        
    } catch {
        $healthData.OverallStatus = "Error"
        $healthData.Error = $_.Exception.Message
    }
    
    return [PSCustomObject]$healthData
}
```

## Recipe 2: Test Server Connectivity

### Scenario
Before deploying updates or performing maintenance, you need to verify that servers are accessible and responsive.

### Solution

```powershell
# Basic connectivity test
Test-ServerConnectivity -ComputerName 'SERVER01'

# Test multiple servers
$servers = @('WEB01', 'WEB02', 'DB01')
Test-ServerConnectivity -ComputerName $servers | Format-Table -AutoSize

# Comprehensive connectivity test
Test-ServerConnectivity -ComputerName 'SERVER01' -IncludePorts @(80, 443, 3389, 5985)

# Test with custom timeout
Test-ServerConnectivity -ComputerName $servers -TimeoutSeconds 10
```

### Advanced Usage

```powershell
# Pre-deployment connectivity validation
function Test-DeploymentReadiness {
    param(
        [Parameter(Mandatory)]
        [string[]]$ServerList,
        
        [hashtable]$RequiredPorts = @{
            'PowerShell Remoting' = 5985
            'PowerShell Remoting SSL' = 5986
            'RDP' = 3389
        },
        
        [int]$TimeoutSeconds = 30
    )
    
    $results = @()
    
    foreach ($server in $ServerList) {
        Write-Progress -Activity "Testing Connectivity" -Status $server -PercentComplete (($results.Count / $ServerList.Count) * 100)
        
        $serverResult = @{
            ComputerName = $server
            Timestamp = Get-Date
            Tests = @()
        }
        
        # Basic ping test
        try {
            $ping = Test-Connection -ComputerName $server -Count 2 -Quiet -ErrorAction Stop
            $serverResult.Tests += @{
                Test = "Ping"
                Status = if ($ping) { "✅ Success" } else { "❌ Failed" }
                Details = if ($ping) { "Responsive" } else { "No response" }
            }
        } catch {
            $serverResult.Tests += @{
                Test = "Ping"
                Status = "❌ Error"
                Details = $_.Exception.Message
            }
        }
        
        # DNS resolution test
        try {
            $dns = Resolve-DnsName -Name $server -ErrorAction Stop
            $serverResult.Tests += @{
                Test = "DNS Resolution"
                Status = "✅ Success"
                Details = "Resolved to $($dns.IPAddress -join ', ')"
            }
        } catch {
            $serverResult.Tests += @{
                Test = "DNS Resolution"
                Status = "❌ Failed"
                Details = $_.Exception.Message
            }
        }
        
        # Port connectivity tests
        foreach ($portName in $RequiredPorts.Keys) {
            $port = $RequiredPorts[$portName]
            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.ReceiveTimeout = $TimeoutSeconds * 1000
                $tcpClient.SendTimeout = $TimeoutSeconds * 1000
                
                $asyncResult = $tcpClient.BeginConnect($server, $port, $null, $null)
                $waitHandle = $asyncResult.AsyncWaitHandle
                
                if ($waitHandle.WaitOne($TimeoutSeconds * 1000, $false)) {
                    $tcpClient.EndConnect($asyncResult)
                    $serverResult.Tests += @{
                        Test = "$portName (Port $port)"
                        Status = "✅ Open"
                        Details = "Connection successful"
                    }
                } else {
                    $serverResult.Tests += @{
                        Test = "$portName (Port $port)"
                        Status = "❌ Closed/Filtered"
                        Details = "Connection timeout"
                    }
                }
                $tcpClient.Close()
            } catch {
                $serverResult.Tests += @{
                    Test = "$portName (Port $port)"
                    Status = "❌ Failed"
                    Details = $_.Exception.Message
                }
            }
        }
        
        # WinRM specific test
        try {
            Test-WSMan -ComputerName $server -ErrorAction Stop | Out-Null
            $serverResult.Tests += @{
                Test = "WinRM/PowerShell Remoting"
                Status = "✅ Available"
                Details = "WinRM service responding"
            }
        } catch {
            $serverResult.Tests += @{
                Test = "WinRM/PowerShell Remoting"
                Status = "❌ Unavailable"
                Details = "WinRM not responding"
            }
        }
        
        # Overall readiness assessment
        $failedTests = ($serverResult.Tests | Where-Object { $_.Status -like "*❌*" }).Count
        $serverResult.OverallReadiness = if ($failedTests -eq 0) { "✅ Ready" } 
                                       elseif ($failedTests -le 2) { "⚠️ Partially Ready" } 
                                       else { "❌ Not Ready" }
        
        $results += [PSCustomObject]$serverResult
    }
    
    return $results
}

# Usage
$deploymentServers = @('WEB01', 'WEB02', 'API01', 'DB01')
$readinessReport = Test-DeploymentReadiness -ServerList $deploymentServers

# Display summary
$readinessReport | ForEach-Object {
    Write-Host "`n🖥️  $($_.ComputerName) - $($_.OverallReadiness)" -ForegroundColor $(
        switch ($_.OverallReadiness) {
            { $_ -like "*✅*" } { "Green" }
            { $_ -like "*⚠️*" } { "Yellow" }
            { $_ -like "*❌*" } { "Red" }
            default { "White" }
        }
    )
    $_.Tests | ForEach-Object { Write-Host "   $($_.Test): $($_.Status)" }
}
```## Recipe 3: Service Status Monitoring

### Scenario
You need to monitor critical services across multiple servers to ensure business applications are running properly.

### Solution

```powershell
# Check specific services on a server
Get-ServiceStatus -ComputerName 'WEB01' -ServiceName @('IIS', 'W3SVC')

# Monitor services across multiple servers
$webServers = @('WEB01', 'WEB02', 'WEB03')
$criticalServices = @('IIS', 'W3SVC', 'WAS')
Get-ServiceStatus -ComputerName $webServers -ServiceName $criticalServices | Format-Table -AutoSize

# Get detailed service information
Get-ServiceStatus -ComputerName 'WEB01' -ServiceName 'IIS' -IncludeDetails

# Filter for stopped services only
Get-ServiceStatus -ComputerName $webServers -ServiceName $criticalServices | 
    Where-Object { $_.Status -ne 'Running' }
```

### Advanced Usage

```powershell
# Comprehensive service monitoring dashboard
function Start-ServiceMonitoringDashboard {
    param(
        [Parameter(Mandatory)]
        [hashtable]$ServiceGroups,  # @{ 'Web Servers' = @{ Servers = @('WEB01','WEB02'); Services = @('IIS','W3SVC') } }
        
        [int]$RefreshIntervalSeconds = 30,
        
        [switch]$ContinuousMode
    )
    
    do {
        Clear-Host
        Write-Host "🖥️  Service Monitoring Dashboard - $(Get-Date)" -ForegroundColor Cyan
        Write-Host "=" * 80 -ForegroundColor Gray
        
        $allResults = @()
        $totalIssues = 0
        
        foreach ($groupName in $ServiceGroups.Keys) {
            $group = $ServiceGroups[$groupName]
            Write-Host "`n📊 $groupName" -ForegroundColor Yellow
            Write-Host "-" * 40 -ForegroundColor Gray
            
            try {
                $groupResults = Get-ServiceStatus -ComputerName $group.Servers -ServiceName $group.Services
                $allResults += $groupResults
                
                # Group by server for display
                $groupResults | Group-Object ComputerName | ForEach-Object {
                    $serverName = $_.Name
                    $serverServices = $_.Group
                    
                    $stoppedServices = ($serverServices | Where-Object { $_.Status -ne 'Running' }).Count
                    $totalServices = $serverServices.Count
                    
                    $serverStatus = if ($stoppedServices -eq 0) { "✅" } else { "❌" }
                    $statusColor = if ($stoppedServices -eq 0) { "Green" } else { "Red" }
                    
                    Write-Host "  $serverStatus $serverName`: $($totalServices - $stoppedServices)/$totalServices running" -ForegroundColor $statusColor
                    
                    # Show stopped services
                    $serverServices | Where-Object { $_.Status -ne 'Running' } | ForEach-Object {
                        Write-Host "    ⚠️  $($_.ServiceName): $($_.Status)" -ForegroundColor Red
                        $totalIssues++
                    }
                }
            } catch {
                Write-Host "  ❌ Error monitoring $groupName`: $($_.Exception.Message)" -ForegroundColor Red
                $totalIssues++
            }
        }
        
        # Summary
        Write-Host "`n📈 Summary" -ForegroundColor Yellow
        Write-Host "-" * 40 -ForegroundColor Gray
        $totalServers = ($ServiceGroups.Values | ForEach-Object { $_.Servers }).Count
        $summaryColor = if ($totalIssues -eq 0) { "Green" } else { "Red" }
        Write-Host "  Servers Monitored: $totalServers" -ForegroundColor White
        Write-Host "  Total Issues: $totalIssues" -ForegroundColor $summaryColor
        Write-Host "  Last Update: $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Gray
        
        if ($ContinuousMode) {
            Write-Host "`nPress 'Q' to quit, any other key to refresh immediately..." -ForegroundColor Cyan
            
            # Wait for refresh interval or user input
            $timeout = New-TimeSpan -Seconds $RefreshIntervalSeconds
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            
            while ($stopwatch.Elapsed -lt $timeout) {
                if ([Console]::KeyAvailable) {
                    $key = [Console]::ReadKey($true)
                    if ($key.Key -eq 'Q') {
                        return $allResults
                    } else {
                        break
                    }
                }
                Start-Sleep -Milliseconds 100
            }
        }
        
    } while ($ContinuousMode)
    
    return $allResults
}

# Define service monitoring configuration
$serviceConfig = @{
    'Web Servers' = @{
        Servers = @('WEB01', 'WEB02', 'WEB03')
        Services = @('IIS', 'W3SVC', 'WAS')
    }
    'Database Servers' = @{
        Servers = @('DB01', 'DB02')
        Services = @('MSSQLSERVER', 'SQLSERVERAGENT')
    }
    'File Servers' = @{
        Servers = @('FILE01', 'FILE02')
        Services = @('Server', 'LanmanServer', 'DFS Replication')
    }
}

# Start monitoring dashboard
Start-ServiceMonitoringDashboard -ServiceGroups $serviceConfig -ContinuousMode
```

### Automated Service Recovery

```powershell
# Smart service restart with dependency checking
function Start-ServiceWithDependencies {
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [Parameter(Mandatory)]
        [string]$ServiceName,
        
        [int]$MaxRetries = 3,
        
        [int]$RetryDelaySeconds = 30,
        
        [switch]$RestartDependents
    )
    
    $results = @{
        ComputerName = $ComputerName
        ServiceName = $ServiceName
        Actions = @()
        Success = $false
    }
    
    try {
        # Get service and its dependencies
        $service = Get-Service -Name $ServiceName -ComputerName $ComputerName
        $dependencies = $service.ServicesDependedOn
        
        $results.Actions += "Found service '$ServiceName' with $($dependencies.Count) dependencies"
        
        # Check and start dependencies first
        foreach ($dependency in $dependencies) {
            if ($dependency.Status -ne 'Running') {
                $results.Actions += "Starting dependency: $($dependency.Name)"
                Start-Service -Name $dependency.Name -ErrorAction Stop
                Start-Sleep -Seconds 5
            }
        }
        
        # Attempt to start the main service with retries
        $attempt = 1
        while ($attempt -le $MaxRetries) {
            try {
                $results.Actions += "Attempt $attempt to start $ServiceName"
                
                if ($service.Status -eq 'Running') {
                    # Restart if already running
                    Restart-Service -Name $ServiceName -Force -ErrorAction Stop
                    $results.Actions += "Service restarted successfully"
                } else {
                    # Start if stopped
                    Start-Service -Name $ServiceName -ErrorAction Stop
                    $results.Actions += "Service started successfully"
                }
                
                # Verify service is running
                Start-Sleep -Seconds 10
                $service.Refresh()
                
                if ($service.Status -eq 'Running') {
                    $results.Success = $true
                    $results.Actions += "✅ Service is now running"
                    break
                } else {
                    $results.Actions += "⚠️ Service status: $($service.Status)"
                }
                
            } catch {
                $results.Actions += "❌ Attempt $attempt failed: $($_.Exception.Message)"
                
                if ($attempt -lt $MaxRetries) {
                    $results.Actions += "Waiting $RetryDelaySeconds seconds before retry..."
                    Start-Sleep -Seconds $RetryDelaySeconds
                }
            }
            
            $attempt++
        }
        
        # Restart dependent services if requested and main service is running
        if ($RestartDependents -and $results.Success) {
            $dependents = Get-Service -ComputerName $ComputerName | Where-Object { 
                $_.ServicesDependedOn.Name -contains $ServiceName 
            }
            
            foreach ($dependent in $dependents) {
                if ($dependent.Status -eq 'Running') {
                    try {
                        $results.Actions += "Restarting dependent service: $($dependent.Name)"
                        Restart-Service -Name $dependent.Name -Force
                    } catch {
                        $results.Actions += "⚠️ Failed to restart dependent service $($dependent.Name): $($_.Exception.Message)"
                    }
                }
            }
        }
        
    } catch {
        $results.Actions += "❌ Critical error: $($_.Exception.Message)"
        $results.Success = $false
    }
    
    return [PSCustomObject]$results
}

# Usage example
$serviceResult = Start-ServiceWithDependencies -ComputerName 'WEB01' -ServiceName 'W3SVC' -RestartDependents
$serviceResult.Actions | ForEach-Object { Write-Host $_ }
```

## Recipe 4: Performance Monitoring

### Scenario
You need to monitor server performance metrics to identify bottlenecks and capacity issues.

### Solution

```powershell
# Get performance counters for a server
Get-ServerPerformance -ComputerName 'SERVER01'

# Monitor performance across multiple servers
$servers = @('WEB01', 'WEB02', 'DB01')
Get-ServerPerformance -ComputerName $servers | Format-Table -AutoSize

# Get detailed performance metrics
Get-ServerPerformance -ComputerName 'SERVER01' -IncludeNetwork -IncludeDisk

# Monitor performance over time
1..5 | ForEach-Object {
    Get-ServerPerformance -ComputerName 'SERVER01'
    Start-Sleep -Seconds 60
}
```

### Advanced Performance Monitoring

```powershell
# Comprehensive performance baseline collection
function New-PerformanceBaseline {
    param(
        [Parameter(Mandatory)]
        [string[]]$ComputerNames,
        
        [int]$SampleIntervalSeconds = 30,
        
        [int]$SampleCount = 10,
        
        [string]$BaselineName = "Baseline_$(Get-Date -Format 'yyyyMMdd')"
    )
    
    $baselineData = @()
    
    Write-Host "📊 Collecting performance baseline: $BaselineName" -ForegroundColor Cyan
    Write-Host "   Computers: $($ComputerNames -join ', ')" -ForegroundColor Gray
    Write-Host "   Samples: $SampleCount every $SampleIntervalSeconds seconds" -ForegroundColor Gray
    
    for ($sample = 1; $sample -le $SampleCount; $sample++) {
        Write-Progress -Activity "Collecting Baseline" -Status "Sample $sample of $SampleCount" -PercentComplete (($sample / $SampleCount) * 100)
        
        foreach ($computer in $ComputerNames) {
            try {
                # CPU Usage
                $cpu = Get-Counter "\\$computer\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples 1
                
                # Memory Usage
                $memory = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $computer
                $memoryPercent = [math]::Round((($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory) / $memory.TotalVisibleMemorySize) * 100, 2)
                
                # Disk Usage
                $diskCounters = Get-Counter "\\$computer\PhysicalDisk(_Total)\% Disk Time" -SampleInterval 1 -MaxSamples 1
                
                # Network Usage
                $networkAdapters = Get-WmiObject -Class Win32_PerfRawData_Tcpip_NetworkInterface -ComputerName $computer | 
                    Where-Object { $_.Name -notlike "*Loopback*" -and $_.Name -notlike "*Teredo*" }
                
                $baselineData += [PSCustomObject]@{
                    BaselineName = $BaselineName
                    ComputerName = $computer
                    SampleNumber = $sample
                    Timestamp = Get-Date
                    CPUPercent = [math]::Round($cpu.CounterSamples[0].CookedValue, 2)
                    MemoryPercent = $memoryPercent
                    DiskPercent = [math]::Round($diskCounters.CounterSamples[0].CookedValue, 2)
                    NetworkAdapters = $networkAdapters.Count
                    TotalMemoryGB = [math]::Round($memory.TotalVisibleMemorySize / 1024 / 1024, 2)
                }
                
            } catch {
                Write-Warning "Failed to collect data from $computer`: $($_.Exception.Message)"
            }
        }
        
        if ($sample -lt $SampleCount) {
            Start-Sleep -Seconds $SampleIntervalSeconds
        }
    }
    
    # Calculate statistics
    $statistics = $baselineData | Group-Object ComputerName | ForEach-Object {
        $computerData = $_.Group
        [PSCustomObject]@{
            ComputerName = $_.Name
            CPUAverage = [math]::Round(($computerData | Measure-Object CPUPercent -Average).Average, 2)
            CPUMax = [math]::Round(($computerData | Measure-Object CPUPercent -Maximum).Maximum, 2)
            MemoryAverage = [math]::Round(($computerData | Measure-Object MemoryPercent -Average).Average, 2)
            MemoryMax = [math]::Round(($computerData | Measure-Object MemoryPercent -Maximum).Maximum, 2)
            DiskAverage = [math]::Round(($computerData | Measure-Object DiskPercent -Average).Average, 2)
            DiskMax = [math]::Round(($computerData | Measure-Object DiskPercent -Maximum).Maximum, 2)
            SampleCount = $computerData.Count
        }
    }
    
    # Export baseline data
    $exportPath = "C:\Admin\Baselines"
    if (-not (Test-Path $exportPath)) {
        New-Item -Path $exportPath -ItemType Directory -Force
    }
    
    $baselineFile = Join-Path $exportPath "$BaselineName.csv"
    $statsFile = Join-Path $exportPath "${BaselineName}_Statistics.csv"
    
    $baselineData | Export-Csv $baselineFile -NoTypeInformation
    $statistics | Export-Csv $statsFile -NoTypeInformation
    
    Write-Host "`n✅ Baseline collection complete!" -ForegroundColor Green
    Write-Host "   Baseline data: $baselineFile" -ForegroundColor Cyan
    Write-Host "   Statistics: $statsFile" -ForegroundColor Cyan
    
    return @{
        BaselineData = $baselineData
        Statistics = $statistics
        BaselineFile = $baselineFile
        StatisticsFile = $statsFile
    }
}

# Create performance baseline
$webServers = @('WEB01', 'WEB02', 'WEB03')
$baseline = New-PerformanceBaseline -ComputerNames $webServers -SampleCount 5 -SampleIntervalSeconds 30

# Display baseline statistics
$baseline.Statistics | Format-Table -AutoSize
```

## Troubleshooting and Error Handling

### Common Issues and Solutions

```powershell
# Comprehensive server diagnostics
function Test-ServerDiagnostics {
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )
    
    $diagnostics = @{
        ComputerName = $ComputerName
        Timestamp = Get-Date
        Tests = @()
    }
    
    # Test 1: Basic connectivity
    try {
        $ping = Test-Connection -ComputerName $ComputerName -Count 2 -Quiet
        $diagnostics.Tests += @{
            Test = "Network Connectivity"
            Status = if ($ping) { "✅ Pass" } else { "❌ Fail" }
            Details = if ($ping) { "Server responds to ping" } else { "No ping response" }
        }
    } catch {
        $diagnostics.Tests += @{ Test = "Network Connectivity"; Status = "❌ Error"; Details = $_.Exception.Message }
    }
    
    # Test 2: WinRM connectivity
    try {
        Test-WSMan -ComputerName $ComputerName -ErrorAction Stop | Out-Null
        $diagnostics.Tests += @{
            Test = "PowerShell Remoting"
            Status = "✅ Pass"
            Details = "WinRM service accessible"
        }
    } catch {
        $diagnostics.Tests += @{
            Test = "PowerShell Remoting"
            Status = "❌ Fail"
            Details = "WinRM not accessible: $($_.Exception.Message)"
        }
    }
    
    # Test 3: Service accessibility
    try {
        $services = Get-Service -ComputerName $ComputerName | Select-Object -First 1
        $diagnostics.Tests += @{
            Test = "Service Query"
            Status = "✅ Pass"
            Details = "Can query services remotely"
        }
    } catch {
        $diagnostics.Tests += @{
            Test = "Service Query"
            Status = "❌ Fail"
            Details = "Cannot query services: $($_.Exception.Message)"
        }
    }
    
    # Test 4: Performance counter access
    try {
        Get-Counter "\\$ComputerName\Processor(_Total)\% Processor Time" -MaxSamples 1 -ErrorAction Stop | Out-Null
        $diagnostics.Tests += @{
            Test = "Performance Counters"
            Status = "✅ Pass"
            Details = "Performance counters accessible"
        }
    } catch {
        $diagnostics.Tests += @{
            Test = "Performance Counters"
            Status = "❌ Fail"
            Details = "Cannot access counters: $($_.Exception.Message)"
        }
    }
    
    # Test 5: WMI connectivity
    try {
        Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop | Out-Null
        $diagnostics.Tests += @{
            Test = "WMI Connectivity"
            Status = "✅ Pass"
            Details = "WMI queries successful"
        }
    } catch {
        $diagnostics.Tests += @{
            Test = "WMI Connectivity"
            Status = "❌ Fail"
            Details = "WMI error: $($_.Exception.Message)"
        }
    }
    
    # Overall assessment
    $failedTests = ($diagnostics.Tests | Where-Object { $_.Status -like "*❌*" }).Count
    $diagnostics.OverallStatus = switch ($failedTests) {
        0 { "✅ All tests passed" }
        { $_ -le 2 } { "⚠️ Some issues detected" }
        default { "❌ Multiple failures" }
    }
    
    return [PSCustomObject]$diagnostics
}

# Run diagnostics
$diagResult = Test-ServerDiagnostics -ComputerName 'SERVER01'
Write-Host "`n🔍 Diagnostics for $($diagResult.ComputerName)" -ForegroundColor Cyan
Write-Host "Overall Status: $($diagResult.OverallStatus)" -ForegroundColor Yellow
$diagResult.Tests | ForEach-Object { 
    Write-Host "  $($_.Test): $($_.Status)" 
    if ($_.Details) { Write-Host "    $($_.Details)" -ForegroundColor Gray }
}
```

## Best Practices Summary

1. **Use `-WhatIf` parameters** for testing commands before execution
2. **Implement proper error handling** with try-catch blocks
3. **Monitor network timeouts** when dealing with remote servers
4. **Use progress indicators** for long-running operations
5. **Log all monitoring activities** for audit trails
6. **Set appropriate thresholds** based on baseline measurements
7. **Test connectivity first** before attempting complex operations
8. **Use parallel processing** for multiple server operations when possible

---

> **Next Steps**: Explore [ServiceManagement Recipes](servicemanagement-recipes.md) for advanced service and process management tasks.