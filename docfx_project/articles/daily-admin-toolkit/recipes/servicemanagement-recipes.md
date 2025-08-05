# ServiceManagement Recipes

## Overview

The ServiceManagement module provides powerful tools for managing Windows services and processes remotely. These recipes cover essential service management tasks with safety controls and production-grade error handling.

## Prerequisites

- **PowerShell Remoting** enabled on target servers
- **Administrative privileges** on target systems
- **Service Control Manager** access permissions
- **Network connectivity** to managed servers
- **Appropriate firewall exceptions** for remote management

```powershell
# Verify prerequisites
Test-WSMan -ComputerName 'SERVER01'

# Import the ServiceManagement module
Import-Module ProjectName.ServiceManagement

# Verify service management permissions
Get-Service -ComputerName 'SERVER01' | Select-Object -First 1
```

## Recipe 1: Remote Service Restart

### Scenario
A critical service has stopped responding on a production server and needs to be restarted safely with proper dependency handling and verification.

### Solution

```powershell
# Basic service restart
Restart-RemoteService -ComputerName 'WEB01' -ServiceName 'W3SVC'

# Restart with safety checks
Restart-RemoteService -ComputerName 'WEB01' -ServiceName 'W3SVC' -WaitForStart -Timeout 300

# Restart multiple services on multiple servers
$servers = @('WEB01', 'WEB02', 'WEB03')
$services = @('W3SVC', 'WAS')
Restart-RemoteService -ComputerName $servers -ServiceName $services -Parallel

# Restart with dependency verification
Restart-RemoteService -ComputerName 'WEB01' -ServiceName 'W3SVC' -CheckDependencies -RestartDependents
```

### Advanced Usage

```powershell
# Safe service restart with comprehensive checks
function Restart-ServiceSafely {
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [Parameter(Mandatory)]
        [string]$ServiceName,
        
        [int]$TimeoutSeconds = 300,
        
        [switch]$CheckApplicationHealth,
        
        [string]$HealthCheckUrl = $null,
        
        [switch]$CreateBackup,
        
        [switch]$NotifyUsers
    )
    
    $operation = @{
        ComputerName = $ComputerName
        ServiceName = $ServiceName
        StartTime = Get-Date
        Steps = @()
        Success = $false
    }
    
    try {
        # Step 1: Pre-restart checks
        $operation.Steps += "🔍 Starting pre-restart checks..."
        
        # Verify service exists
        $service = Get-Service -Name $ServiceName -ComputerName $ComputerName -ErrorAction Stop
        $operation.Steps += "✅ Service '$ServiceName' found on $ComputerName"
        
        # Check current status
        $operation.Steps += "📊 Current service status: $($service.Status)"
        
        # Check dependencies
        $dependencies = $service.ServicesDependedOn
        $dependents = Get-Service -ComputerName $ComputerName | Where-Object { 
            $_.ServicesDependedOn.Name -contains $ServiceName 
        }
        
        $operation.Steps += "🔗 Dependencies: $($dependencies.Count), Dependents: $($dependents.Count)"
        
        # Step 2: Pre-restart application health check
        if ($CheckApplicationHealth -and $HealthCheckUrl) {
            $operation.Steps += "🏥 Checking application health..."
            try {
                $response = Invoke-WebRequest -Uri $HealthCheckUrl -TimeoutSec 30 -UseBasicParsing
                $operation.Steps += "✅ Application health check passed (Status: $($response.StatusCode))"
            } catch {
                $operation.Steps += "⚠️ Application health check failed: $($_.Exception.Message)"
            }
        }
        
        # Step 3: Create service configuration backup
        if ($CreateBackup) {
            $operation.Steps += "💾 Creating service configuration backup..."
            $serviceConfig = Get-WmiObject -Class Win32_Service -ComputerName $ComputerName -Filter "Name='$ServiceName'"
            $backupData = @{
                ServiceName = $serviceConfig.Name
                StartMode = $serviceConfig.StartMode
                ServiceAccount = $serviceConfig.StartName
                BinaryPath = $serviceConfig.PathName
                BackupTime = Get-Date
            }
            
            $backupPath = "C:\Admin\ServiceBackups\${ComputerName}_${ServiceName}_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
            $backupData | ConvertTo-Json | Out-File -FilePath $backupPath -Encoding UTF8
            $operation.Steps += "✅ Backup created: $backupPath"
        }
        
        # Step 4: Notify users if requested
        if ($NotifyUsers) {
            $operation.Steps += "📢 Notifying users of maintenance..."
            # Implementation depends on your notification system
            # Send-MaintenanceNotification -Service $ServiceName -Computer $ComputerName -Action "Restart"
        }
        
        # Step 5: Stop dependent services first
        if ($dependents.Count -gt 0) {
            $operation.Steps += "⏹️ Stopping dependent services..."
            foreach ($dependent in $dependents | Where-Object { $_.Status -eq 'Running' }) {
                try {
                    Stop-Service -Name $dependent.Name -Force -ErrorAction Stop
                    $operation.Steps += "✅ Stopped dependent service: $($dependent.Name)"
                } catch {
                    $operation.Steps += "⚠️ Failed to stop dependent service $($dependent.Name): $($_.Exception.Message)"
                }
            }
        }
        
        # Step 6: Restart the main service
        $operation.Steps += "🔄 Restarting service '$ServiceName'..."
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        
        if ($service.Status -eq 'Running') {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            $operation.Steps += "⏹️ Service stopped"
        }
        
        # Wait for service to fully stop
        do {
            Start-Sleep -Seconds 2
            $service.Refresh()
        } while ($service.Status -ne 'Stopped' -and $stopwatch.ElapsedMilliseconds -lt ($TimeoutSeconds * 1000))
        
        if ($service.Status -ne 'Stopped') {
            throw "Service failed to stop within timeout period"
        }
        
        # Start the service
        Start-Service -Name $ServiceName -ErrorAction Stop
        $operation.Steps += "▶️ Service start command issued"
        
        # Wait for service to start
        do {
            Start-Sleep -Seconds 2
            $service.Refresh()
        } while ($service.Status -ne 'Running' -and $stopwatch.ElapsedMilliseconds -lt ($TimeoutSeconds * 1000))
        
        if ($service.Status -eq 'Running') {
            $operation.Steps += "✅ Service started successfully"
        } else {
            throw "Service failed to start within timeout period. Status: $($service.Status)"
        }
        
        # Step 7: Restart dependent services
        if ($dependents.Count -gt 0) {
            $operation.Steps += "▶️ Restarting dependent services..."
            Start-Sleep -Seconds 5  # Allow main service to stabilize
            
            foreach ($dependent in $dependents) {
                try {
                    Start-Service -Name $dependent.Name -ErrorAction Stop
                    $operation.Steps += "✅ Started dependent service: $($dependent.Name)"
                } catch {
                    $operation.Steps += "⚠️ Failed to start dependent service $($dependent.Name): $($_.Exception.Message)"
                }
            }
        }
        
        # Step 8: Post-restart health check
        if ($CheckApplicationHealth -and $HealthCheckUrl) {
            $operation.Steps += "🏥 Post-restart health check..."
            Start-Sleep -Seconds 10  # Allow service to initialize
            
            try {
                $response = Invoke-WebRequest -Uri $HealthCheckUrl -TimeoutSec 30 -UseBasicParsing
                $operation.Steps += "✅ Post-restart health check passed (Status: $($response.StatusCode))"
            } catch {
                $operation.Steps += "❌ Post-restart health check failed: $($_.Exception.Message)"
                throw "Service restarted but application health check failed"
            }
        }
        
        $operation.Success = $true
        $operation.Steps += "🎉 Service restart completed successfully"
        
    } catch {
        $operation.Steps += "❌ Error during restart: $($_.Exception.Message)"
        $operation.Success = $false
    } finally {
        $operation.EndTime = Get-Date
        $operation.Duration = New-TimeSpan -Start $operation.StartTime -End $operation.EndTime
        
        # Cleanup notification
        if ($NotifyUsers) {
            $status = if ($operation.Success) { "Completed" } else { "Failed" }
            # Send-MaintenanceNotification -Service $ServiceName -Computer $ComputerName -Action "Restart $status"
        }
    }
    
    return [PSCustomObject]$operation
}

# Usage examples
$restartResult = Restart-ServiceSafely -ComputerName 'WEB01' -ServiceName 'W3SVC' -CheckApplicationHealth -HealthCheckUrl 'http://WEB01/health' -CreateBackup

# Display operation results
Write-Host "`n🔄 Service Restart Operation: $($restartResult.ServiceName) on $($restartResult.ComputerName)" -ForegroundColor Cyan
Write-Host "Success: $($restartResult.Success)" -ForegroundColor $(if ($restartResult.Success) { "Green" } else { "Red" })
Write-Host "Duration: $($restartResult.Duration.ToString('mm\:ss'))" -ForegroundColor Yellow
Write-Host "`nOperation Steps:" -ForegroundColor Yellow
$restartResult.Steps | ForEach-Object { Write-Host "  $_" }
```

## Recipe 2: Process Management

### Scenario
You need to identify and manage processes across multiple servers, potentially stopping unresponsive applications or resource-intensive processes.

### Solution

```powershell
# Find processes by name
Get-ProcessByName -ComputerName 'SERVER01' -ProcessName 'notepad'

# Find processes across multiple servers
$servers = @('WEB01', 'WEB02', 'WEB03')
Get-ProcessByName -ComputerName $servers -ProcessName 'w3wp' | Format-Table -AutoSize

# Get detailed process information
Get-ProcessByName -ComputerName 'SERVER01' -ProcessName 'sqlservr' -IncludeDetails

# Find processes by CPU or memory usage
Get-ProcessByName -ComputerName 'SERVER01' -MinCPUPercent 80
Get-ProcessByName -ComputerName 'SERVER01' -MinMemoryMB 1000
```

### Advanced Usage

```powershell
# Comprehensive process monitoring and management
function Get-ProcessInsights {
    param(
        [Parameter(Mandatory)]
        [string[]]$ComputerNames,
        
        [string[]]$ProcessNames = @(),
        
        [int]$TopProcessCount = 10,
        
        [switch]$IncludeSystemProcesses,
        
        [double]$CPUThreshold = 80.0,
        
        [int]$MemoryThresholdMB = 1000
    )
    
    $insights = @{
        Timestamp = Get-Date
        ComputerCount = $ComputerNames.Count
        Results = @()
    }
    
    foreach ($computer in $ComputerNames) {
        Write-Progress -Activity "Analyzing Processes" -Status $computer -PercentComplete (($insights.Results.Count / $ComputerNames.Count) * 100)
        
        try {
            $computerResult = @{
                ComputerName = $computer
                ProcessAnalysis = @{}
                TopProcesses = @()
                Alerts = @()
                Success = $true
            }
            
            # Get all processes for analysis
            $processes = Get-Process -ComputerName $computer -ErrorAction Stop
            
            if (-not $IncludeSystemProcesses) {
                $processes = $processes | Where-Object { 
                    $_.ProcessName -notmatch '^(System|Idle|csrss|winlogon|services|lsass|svchost)$' 
                }
            }
            
            # Filter by specific process names if provided
            if ($ProcessNames.Count -gt 0) {
                $processes = $processes | Where-Object { $_.ProcessName -in $ProcessNames }
            }
            
            # Analyze process statistics
            $computerResult.ProcessAnalysis = @{
                TotalProcesses = $processes.Count
                TotalCPU = ($processes | Measure-Object CPU -Sum).Sum
                TotalMemoryMB = [math]::Round(($processes | Measure-Object WorkingSet -Sum).Sum / 1MB, 2)
                UniqueProcessNames = ($processes | Group-Object ProcessName).Count
            }
            
            # Identify top resource consumers
            $computerResult.TopProcesses += @{
                Category = "CPU Usage"
                Processes = $processes | Sort-Object CPU -Descending | Select-Object -First $TopProcessCount | 
                    Select-Object ProcessName, Id, CPU, @{Name="MemoryMB";Expression={[math]::Round($_.WorkingSet/1MB,2)}}
            }
            
            $computerResult.TopProcesses += @{
                Category = "Memory Usage"
                Processes = $processes | Sort-Object WorkingSet -Descending | Select-Object -First $TopProcessCount |
                    Select-Object ProcessName, Id, @{Name="MemoryMB";Expression={[math]::Round($_.WorkingSet/1MB,2)}}, CPU
            }
            
            # Generate alerts for threshold violations
            $highCPUProcesses = $processes | Where-Object { $_.CPU -gt $CPUThreshold }
            if ($highCPUProcesses) {
                $computerResult.Alerts += "⚠️ High CPU processes: $($highCPUProcesses.Count) processes using >$CPUThreshold% CPU"
            }
            
            $highMemoryProcesses = $processes | Where-Object { ($_.WorkingSet / 1MB) -gt $MemoryThresholdMB }
            if ($highMemoryProcesses) {
                $computerResult.Alerts += "⚠️ High memory processes: $($highMemoryProcesses.Count) processes using >$MemoryThresholdMB MB"
            }
            
            # Check for duplicate processes that might indicate issues
            $duplicateProcesses = $processes | Group-Object ProcessName | Where-Object { $_.Count -gt 5 }
            if ($duplicateProcesses) {
                foreach ($duplicate in $duplicateProcesses) {
                    $computerResult.Alerts += "🔄 Multiple instances: $($duplicate.Name) has $($duplicate.Count) running instances"
                }
            }
            
        } catch {
            $computerResult = @{
                ComputerName = $computer
                Success = $false
                Error = $_.Exception.Message
            }
        }
        
        $insights.Results += [PSCustomObject]$computerResult
    }
    
    return [PSCustomObject]$insights
}

# Usage
$processInsights = Get-ProcessInsights -ComputerNames @('WEB01', 'WEB02') -TopProcessCount 5 -CPUThreshold 70

# Display insights
foreach ($result in $processInsights.Results) {
    if ($result.Success) {
        Write-Host "`n🖥️  $($result.ComputerName)" -ForegroundColor Cyan
        Write-Host "   Total Processes: $($result.ProcessAnalysis.TotalProcesses)" -ForegroundColor White
        Write-Host "   Total Memory: $($result.ProcessAnalysis.TotalMemoryMB) MB" -ForegroundColor White
        
        if ($result.Alerts.Count -gt 0) {
            Write-Host "   Alerts:" -ForegroundColor Yellow
            $result.Alerts | ForEach-Object { Write-Host "     $_" -ForegroundColor Yellow }
        }
    } else {
        Write-Host "`n❌ $($result.ComputerName): $($result.Error)" -ForegroundColor Red
    }
}
```## Recipe 3: Safe Process Termination

### Scenario
You need to stop unresponsive or problematic processes remotely while ensuring data integrity and following proper shutdown procedures.

### Solution

```powershell
# Stop process by name with confirmation
Stop-ProcessRemotely -ComputerName 'SERVER01' -ProcessName 'notepad' -Confirm

# Force stop unresponsive process
Stop-ProcessRemotely -ComputerName 'SERVER01' -ProcessId 1234 -Force

# Stop processes across multiple servers
$servers = @('WEB01', 'WEB02', 'WEB03')
Stop-ProcessRemotely -ComputerName $servers -ProcessName 'badapp' -WhatIf

# Graceful shutdown with timeout
Stop-ProcessRemotely -ComputerName 'SERVER01' -ProcessName 'myapp' -GracefulShutdown -TimeoutSeconds 30
```

### Advanced Usage

```powershell
# Intelligent process termination with safety checks
function Stop-ProcessIntelligently {
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [Parameter(Mandatory, ParameterSetName="ByName")]
        [string]$ProcessName,
        
        [Parameter(Mandatory, ParameterSetName="ById")]
        [int]$ProcessId,
        
        [int]$GracefulTimeoutSeconds = 30,
        
        [switch]$BackupData,
        
        [string[]]$ProtectedProcesses = @('winlogon', 'csrss', 'smss', 'services', 'lsass'),
        
        [switch]$NotifyUsers,
        
        [switch]$Force
    )
    
    $operation = @{
        ComputerName = $ComputerName
        TargetProcess = if ($ProcessName) { $ProcessName } else { $ProcessId }
        StartTime = Get-Date
        Steps = @()
        Success = $false
        ProcessesTerminated = @()
    }
    
    try {
        # Step 1: Identify target processes
        $operation.Steps += "🔍 Identifying target processes..."
        
        if ($ProcessName) {
            $targetProcesses = Get-Process -Name $ProcessName -ComputerName $ComputerName -ErrorAction Stop
        } else {
            $targetProcesses = Get-Process -Id $ProcessId -ComputerName $ComputerName -ErrorAction Stop
        }
        
        if ($targetProcesses.Count -eq 0) {
            throw "No matching processes found"
        }
        
        $operation.Steps += "✅ Found $($targetProcesses.Count) matching process(es)"
        
        # Step 2: Safety checks
        $operation.Steps += "🛡️ Performing safety checks..."
        
        foreach ($process in $targetProcesses) {
            # Check if process is in protected list
            if ($process.ProcessName -in $ProtectedProcesses -and -not $Force) {
                throw "Process '$($process.ProcessName)' is protected and cannot be terminated without -Force parameter"
            }
            
            # Check if process is critical system process
            if ($process.PriorityClass -eq 'RealTime' -and -not $Force) {
                $operation.Steps += "⚠️ Warning: Process '$($process.ProcessName)' has RealTime priority"
            }
            
            # Check process uptime
            $processAge = (Get-Date) - $process.StartTime
            if ($processAge.TotalMinutes -lt 5 -and -not $Force) {
                $operation.Steps += "⚠️ Warning: Process '$($process.ProcessName)' started recently ($([math]::Round($processAge.TotalMinutes, 1)) minutes ago)"
            }
        }
        
        # Step 3: User notification
        if ($NotifyUsers) {
            $operation.Steps += "📢 Notifying users of process termination..."
            # Implementation depends on your notification system
            foreach ($process in $targetProcesses) {
                # Send-ProcessTerminationNotification -ProcessName $process.ProcessName -ComputerName $ComputerName
            }
        }
        
        # Step 4: Data backup if requested
        if ($BackupData) {
            $operation.Steps += "💾 Initiating data backup procedures..."
            foreach ($process in $targetProcesses) {
                try {
                    # Get process executable path for backup context
                    $processPath = $process.Path
                    if ($processPath) {
                        $operation.Steps += "📁 Process location: $processPath"
                        # Implement application-specific backup logic here
                        # Backup-ApplicationData -ProcessPath $processPath -BackupLocation "C:\Backups\ProcessData"
                    }
                } catch {
                    $operation.Steps += "⚠️ Could not determine process path for backup"
                }
            }
        }
        
        # Step 5: Graceful shutdown attempt
        $operation.Steps += "🤝 Attempting graceful shutdown..."
        
        foreach ($process in $targetProcesses) {
            try {
                # Try to close main window first (for GUI applications)
                if ($process.MainWindowHandle -ne [System.IntPtr]::Zero) {
                    $operation.Steps += "🪟 Closing main window for process ID $($process.Id)"
                    $process.CloseMainWindow() | Out-Null
                } else {
                    $operation.Steps += "📝 Process ID $($process.Id) has no main window, skipping graceful close"
                }
            } catch {
                $operation.Steps += "⚠️ Could not close main window for process ID $($process.Id)"
            }
        }
        
        # Step 6: Wait for graceful shutdown
        if ($GracefulTimeoutSeconds -gt 0) {
            $operation.Steps += "⏳ Waiting up to $GracefulTimeoutSeconds seconds for graceful shutdown..."
            
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $remainingProcesses = @($targetProcesses)
            
            while ($remainingProcesses.Count -gt 0 -and $stopwatch.ElapsedMilliseconds -lt ($GracefulTimeoutSeconds * 1000)) {
                Start-Sleep -Seconds 2
                
                # Check which processes are still running
                $stillRunning = @()
                foreach ($process in $remainingProcesses) {
                    try {
                        $checkProcess = Get-Process -Id $process.Id -ComputerName $ComputerName -ErrorAction Stop
                        $stillRunning += $checkProcess
                    } catch {
                        # Process has exited
                        $operation.Steps += "✅ Process ID $($process.Id) exited gracefully"
                        $operation.ProcessesTerminated += @{
                            ProcessId = $process.Id
                            ProcessName = $process.ProcessName
                            TerminationMethod = "Graceful"
                            Timestamp = Get-Date
                        }
                    }
                }
                
                $remainingProcesses = $stillRunning
            }
            
            if ($remainingProcesses.Count -eq 0) {
                $operation.Steps += "🎉 All processes exited gracefully"
                $operation.Success = $true
                return [PSCustomObject]$operation
            } else {
                $operation.Steps += "⚠️ $($remainingProcesses.Count) process(es) did not exit gracefully"
            }
        }
        
        # Step 7: Force termination if necessary
        if ($remainingProcesses.Count -gt 0 -or $GracefulTimeoutSeconds -eq 0) {
            $operation.Steps += "⚡ Force terminating remaining processes..."
            
            $processesToKill = if ($remainingProcesses) { $remainingProcesses } else { $targetProcesses }
            
            foreach ($process in $processesToKill) {
                try {
                    $operation.Steps += "🔨 Force killing process ID $($process.Id) ($($process.ProcessName))"
                    Stop-Process -Id $process.Id -Force -ErrorAction Stop
                    
                    $operation.ProcessesTerminated += @{
                        ProcessId = $process.Id
                        ProcessName = $process.ProcessName
                        TerminationMethod = "Force"
                        Timestamp = Get-Date
                    }
                    
                } catch {
                    $operation.Steps += "❌ Failed to terminate process ID $($process.Id): $($_.Exception.Message)"
                }
            }
            
            # Verify termination
            Start-Sleep -Seconds 3
            $stillAlive = @()
            foreach ($process in $processesToKill) {
                try {
                    Get-Process -Id $process.Id -ComputerName $ComputerName -ErrorAction Stop | Out-Null
                    $stillAlive += $process
                } catch {
                    # Process successfully terminated
                }
            }
            
            if ($stillAlive.Count -eq 0) {
                $operation.Steps += "✅ All processes successfully terminated"
                $operation.Success = $true
            } else {
                $operation.Steps += "❌ $($stillAlive.Count) process(es) could not be terminated"
                $operation.Success = $false
            }
        }
        
    } catch {
        $operation.Steps += "❌ Error during process termination: $($_.Exception.Message)"
        $operation.Success = $false
    } finally {
        $operation.EndTime = Get-Date
        $operation.Duration = New-TimeSpan -Start $operation.StartTime -End $operation.EndTime
        
        # Final notification
        if ($NotifyUsers) {
            $status = if ($operation.Success) { "Completed" } else { "Failed" }
            # Send-ProcessTerminationNotification -Status $status -ProcessCount $operation.ProcessesTerminated.Count
        }
    }
    
    return [PSCustomObject]$operation
}

# Usage examples
$terminationResult = Stop-ProcessIntelligently -ComputerName 'WEB01' -ProcessName 'badapp' -GracefulTimeoutSeconds 30 -BackupData

# Display results
Write-Host "`n🔨 Process Termination Operation" -ForegroundColor Cyan
Write-Host "Target: $($terminationResult.TargetProcess) on $($terminationResult.ComputerName)" -ForegroundColor White
Write-Host "Success: $($terminationResult.Success)" -ForegroundColor $(if ($terminationResult.Success) { "Green" } else { "Red" })
Write-Host "Duration: $($terminationResult.Duration.ToString('mm\:ss'))" -ForegroundColor Yellow
Write-Host "Processes Terminated: $($terminationResult.ProcessesTerminated.Count)" -ForegroundColor Yellow

Write-Host "`nOperation Steps:" -ForegroundColor Yellow
$terminationResult.Steps | ForEach-Object { Write-Host "  $_" }

if ($terminationResult.ProcessesTerminated.Count -gt 0) {
    Write-Host "`nTerminated Processes:" -ForegroundColor Yellow
    $terminationResult.ProcessesTerminated | ForEach-Object {
        Write-Host "  ID: $($_.ProcessId), Name: $($_.ProcessName), Method: $($_.TerminationMethod)" -ForegroundColor Gray
    }
}
```

## Recipe 4: Service Dependency Management

### Scenario
You need to understand and manage complex service dependencies when planning maintenance or troubleshooting service issues.

### Solution

```powershell
# Analyze service dependencies
Get-ServiceDependencies -ComputerName 'SERVER01' -ServiceName 'W3SVC'

# Get full dependency tree
Get-ServiceDependencies -ComputerName 'SERVER01' -ServiceName 'W3SVC' -Recursive

# Map dependencies for multiple services
$criticalServices = @('W3SVC', 'MSSQLSERVER', 'Spooler')
Get-ServiceDependencies -ComputerName 'SERVER01' -ServiceName $criticalServices -IncludeDependents
```

### Advanced Usage

```powershell
# Comprehensive service dependency analysis
function Get-ServiceDependencyMap {
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [string[]]$ServiceNames = @(),
        
        [switch]$IncludeAll,
        
        [switch]$ExportDiagram,
        
        [string]$ExportPath = "C:\Admin\ServiceMaps"
    )
    
    $dependencyMap = @{
        ComputerName = $ComputerName
        Timestamp = Get-Date
        Services = @{}
        DependencyChains = @()
    }
    
    try {
        # Get all services or specific ones
        if ($IncludeAll) {
            $services = Get-Service -ComputerName $ComputerName
        } elseif ($ServiceNames.Count -gt 0) {
            $services = Get-Service -ComputerName $ComputerName -Name $ServiceNames
        } else {
            # Get only non-trivial services (those with dependencies)
            $allServices = Get-Service -ComputerName $ComputerName
            $services = $allServices | Where-Object { 
                $_.ServicesDependedOn.Count -gt 0 -or 
                ($allServices | Where-Object { $_.ServicesDependedOn.Name -contains $_.Name }).Count -gt 0
            }
        }
        
        Write-Host "🔍 Analyzing $($services.Count) services for dependencies..." -ForegroundColor Cyan
        
        # Build dependency map
        foreach ($service in $services) {
            $serviceInfo = @{
                Name = $service.Name
                DisplayName = $service.DisplayName
                Status = $service.Status
                StartType = $service.StartType
                Dependencies = @()
                Dependents = @()
                DependencyLevel = 0
            }
            
            # Get services this service depends on
            if ($service.ServicesDependedOn.Count -gt 0) {
                $serviceInfo.Dependencies = $service.ServicesDependedOn | ForEach-Object {
                    @{
                        Name = $_.Name
                        DisplayName = $_.DisplayName
                        Status = $_.Status
                    }
                }
            }
            
            # Get services that depend on this service
            $dependentServices = $services | Where-Object { 
                $_.ServicesDependedOn.Name -contains $service.Name 
            }
            
            if ($dependentServices) {
                $serviceInfo.Dependents = $dependentServices | ForEach-Object {
                    @{
                        Name = $_.Name
                        DisplayName = $_.DisplayName
                        Status = $_.Status
                    }
                }
            }
            
            $dependencyMap.Services[$service.Name] = $serviceInfo
        }
        
        # Calculate dependency levels (how deep in the dependency chain)
        function Get-DependencyLevel($serviceName, $visited = @()) {
            if ($serviceName -in $visited) {
                return 0  # Circular dependency detection
            }
            
            $service = $dependencyMap.Services[$serviceName]
            if (-not $service -or $service.Dependencies.Count -eq 0) {
                return 0
            }
            
            $maxLevel = 0
            foreach ($dependency in $service.Dependencies) {
                $level = Get-DependencyLevel $dependency.Name ($visited + $serviceName)
                if ($level -gt $maxLevel) {
                    $maxLevel = $level
                }
            }
            
            return $maxLevel + 1
        }
        
        # Calculate levels for all services
        foreach ($serviceName in $dependencyMap.Services.Keys) {
            $dependencyMap.Services[$serviceName].DependencyLevel = Get-DependencyLevel $serviceName
        }
        
        # Identify dependency chains
        $chainId = 1
        foreach ($serviceName in $dependencyMap.Services.Keys) {
            $service = $dependencyMap.Services[$serviceName]
            
            if ($service.Dependencies.Count -gt 0) {
                $chain = @{
                    Id = $chainId++
                    RootService = $serviceName
                    Chain = @()
                    TotalServices = 0
                    MaxDepth = 0
                }
                
                # Build the chain recursively
                function Build-Chain($currentService, $depth = 0, $visited = @()) {
                    if ($currentService -in $visited -or $depth -gt 10) {
                        return  # Prevent infinite loops
                    }
                    
                    $chain.Chain += @{
                        ServiceName = $currentService
                        Depth = $depth
                        Status = $dependencyMap.Services[$currentService].Status
                    }
                    
                    $chain.TotalServices++
                    if ($depth -gt $chain.MaxDepth) {
                        $chain.MaxDepth = $depth
                    }
                    
                    $serviceInfo = $dependencyMap.Services[$currentService]
                    if ($serviceInfo -and $serviceInfo.Dependencies.Count -gt 0) {
                        foreach ($dependency in $serviceInfo.Dependencies) {
                            Build-Chain $dependency.Name ($depth + 1) ($visited + $currentService)
                        }
                    }
                }
                
                Build-Chain $serviceName
                $dependencyMap.DependencyChains += $chain
            }
        }
        
        # Generate summary statistics
        $dependencyMap.Statistics = @{
            TotalServices = $dependencyMap.Services.Count
            ServicesWithDependencies = ($dependencyMap.Services.Values | Where-Object { $_.Dependencies.Count -gt 0 }).Count
            ServicesWithDependents = ($dependencyMap.Services.Values | Where-Object { $_.Dependents.Count -gt 0 }).Count
            MaxDependencyLevel = ($dependencyMap.Services.Values | Measure-Object DependencyLevel -Maximum).Maximum
            DependencyChains = $dependencyMap.DependencyChains.Count
            LongestChain = if ($dependencyMap.DependencyChains.Count -gt 0) { 
                ($dependencyMap.DependencyChains | Measure-Object MaxDepth -Maximum).Maximum 
            } else { 0 }
        }
        
        # Export diagram if requested
        if ($ExportDiagram) {
            if (-not (Test-Path $ExportPath)) {
                New-Item -Path $ExportPath -ItemType Directory -Force
            }
            
            $diagramFile = Join-Path $ExportPath "ServiceDependencies_${ComputerName}_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
            
            $diagramContent = @()
            $diagramContent += "Service Dependency Map for $ComputerName"
            $diagramContent += "Generated: $(Get-Date)"
            $diagramContent += "=" * 60
            $diagramContent += ""
            
            # Sort services by dependency level
            $sortedServices = $dependencyMap.Services.Values | Sort-Object DependencyLevel, Name
            
            foreach ($service in $sortedServices) {
                $indent = "  " * $service.DependencyLevel
                $status = switch ($service.Status) {
                    'Running' { '✅' }
                    'Stopped' { '❌' }
                    default { '⚠️' }
                }
                
                $diagramContent += "$indent$status $($service.Name) ($($service.Status))"
                
                if ($service.Dependencies.Count -gt 0) {
                    foreach ($dep in $service.Dependencies) {
                        $depStatus = switch ($dep.Status) {
                            'Running' { '✅' }
                            'Stopped' { '❌' }
                            default { '⚠️' }
                        }
                        $diagramContent += "$indent  └─ Depends on: $depStatus $($dep.Name)"
                    }
                }
            }
            
            $diagramContent | Out-File -FilePath $diagramFile -Encoding UTF8
            Write-Host "📊 Dependency diagram exported to: $diagramFile" -ForegroundColor Green
        }
        
    } catch {
        Write-Error "Failed to analyze service dependencies: $($_.Exception.Message)"
        return $null
    }
    
    return [PSCustomObject]$dependencyMap
}

# Usage
$serviceMap = Get-ServiceDependencyMap -ComputerName 'SERVER01' -IncludeAll -ExportDiagram

# Display summary
Write-Host "`n📊 Service Dependency Analysis for $($serviceMap.ComputerName)" -ForegroundColor Cyan
Write-Host "Total Services: $($serviceMap.Statistics.TotalServices)" -ForegroundColor White
Write-Host "Services with Dependencies: $($serviceMap.Statistics.ServicesWithDependencies)" -ForegroundColor White
Write-Host "Services with Dependents: $($serviceMap.Statistics.ServicesWithDependents)" -ForegroundColor White
Write-Host "Max Dependency Level: $($serviceMap.Statistics.MaxDependencyLevel)" -ForegroundColor White
Write-Host "Dependency Chains: $($serviceMap.Statistics.DependencyChains)" -ForegroundColor White
Write-Host "Longest Chain: $($serviceMap.Statistics.LongestChain)" -ForegroundColor White

# Show top dependency chains
if ($serviceMap.DependencyChains.Count -gt 0) {
    Write-Host "`n🔗 Top Dependency Chains:" -ForegroundColor Yellow
    $serviceMap.DependencyChains | Sort-Object MaxDepth -Descending | Select-Object -First 5 | ForEach-Object {
        Write-Host "  $($_.RootService): $($_.TotalServices) services, depth $($_.MaxDepth)" -ForegroundColor Gray
    }
}
```

## Best Practices and Safety Guidelines

### Safety Checklist

```powershell
# Pre-operation safety checklist
function Test-ServiceOperationSafety {
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [Parameter(Mandatory)]
        [string]$ServiceName,
        
        [string]$Operation  # 'Restart', 'Stop', 'Start'
    )
    
    $safetyCheck = @{
        ComputerName = $ComputerName
        ServiceName = $ServiceName
        Operation = $Operation
        Checks = @()
        OverallSafety = "Unknown"
        Recommendations = @()
    }
    
    try {
        # Check 1: Service exists and is accessible
        $service = Get-Service -Name $ServiceName -ComputerName $ComputerName -ErrorAction Stop
        $safetyCheck.Checks += @{
            Check = "Service Accessibility"
            Status = "✅ Pass"
            Details = "Service found and accessible"
        }
        
        # Check 2: Current service status
        $safetyCheck.Checks += @{
            Check = "Current Status"
            Status = "ℹ️ Info"
            Details = "Service is currently $($service.Status)"
        }
        
        # Check 3: Service criticality assessment
        $criticalServices = @('Dhcp', 'Dns', 'W32Time', 'Netlogon', 'NTDS', 'kdc')
        if ($service.Name -in $criticalServices) {
            $safetyCheck.Checks += @{
                Check = "Service Criticality"
                Status = "⚠️ Warning"
                Details = "This is a critical system service"
            }
            $safetyCheck.Recommendations += "Consider maintenance window for critical service operations"
        } else {
            $safetyCheck.Checks += @{
                Check = "Service Criticality"
                Status = "✅ Pass"
                Details = "Non-critical service"
            }
        }
        
        # Check 4: Dependent services impact
        $dependents = Get-Service -ComputerName $ComputerName | Where-Object { 
            $_.ServicesDependedOn.Name -contains $ServiceName 
        }
        
        if ($dependents.Count -gt 0) {
            $runningDependents = $dependents | Where-Object { $_.Status -eq 'Running' }
            $safetyCheck.Checks += @{
                Check = "Dependent Services"
                Status = "⚠️ Warning"
                Details = "$($dependents.Count) dependent services found ($($runningDependents.Count) running)"
            }
            $safetyCheck.Recommendations += "Review impact on dependent services: $($dependents.Name -join ', ')"
        } else {
            $safetyCheck.Checks += @{
                Check = "Dependent Services"
                Status = "✅ Pass"
                Details = "No dependent services"
            }
        }
        
        # Check 5: Business hours assessment
        $currentHour = (Get-Date).Hour
        $isBusinessHours = $currentHour -ge 8 -and $currentHour -le 17
        
        if ($isBusinessHours -and $dependents.Count -gt 0) {
            $safetyCheck.Checks += @{
                Check = "Timing"
                Status = "⚠️ Warning"
                Details = "Operation during business hours with dependent services"
            }
            $safetyCheck.Recommendations += "Consider performing operation outside business hours"
        } else {
            $safetyCheck.Checks += @{
                Check = "Timing"
                Status = "✅ Pass"
                Details = if ($isBusinessHours) { "Business hours but no dependents" } else { "Outside business hours" }
            }
        }
        
        # Check 6: Recent changes
        try {
            $serviceWMI = Get-WmiObject -Class Win32_Service -ComputerName $ComputerName -Filter "Name='$ServiceName'"
            $processId = $serviceWMI.ProcessId
            
            if ($processId -and $processId -gt 0) {
                $process = Get-Process -Id $processId -ComputerName $ComputerName -ErrorAction SilentlyContinue
                if ($process) {
                    $processAge = (Get-Date) - $process.StartTime
                    if ($processAge.TotalMinutes -lt 30) {
                        $safetyCheck.Checks += @{
                            Check = "Recent Restart"
                            Status = "⚠️ Warning"
                            Details = "Service was restarted $([math]::Round($processAge.TotalMinutes, 1)) minutes ago"
                        }
                        $safetyCheck.Recommendations += "Service was recently restarted - verify stability before additional operations"
                    } else {
                        $safetyCheck.Checks += @{
                            Check = "Service Stability"
                            Status = "✅ Pass"
                            Details = "Service has been running for $([math]::Round($processAge.TotalHours, 1)) hours"
                        }
                    }
                }
            }
        } catch {
            $safetyCheck.Checks += @{
                Check = "Process Information"
                Status = "ℹ️ Info"
                Details = "Could not determine process information"
            }
        }
        
        # Overall safety assessment
        $warningCount = ($safetyCheck.Checks | Where-Object { $_.Status -like "*⚠️*" }).Count
        $failCount = ($safetyCheck.Checks | Where-Object { $_.Status -like "*❌*" }).Count
        
        $safetyCheck.OverallSafety = if ($failCount -gt 0) { "❌ High Risk" }
                                   elseif ($warningCount -gt 2) { "⚠️ Medium Risk" }
                                   elseif ($warningCount -gt 0) { "⚠️ Low Risk" }
                                   else { "✅ Safe" }
        
    } catch {
        $safetyCheck.Checks += @{
            Check = "Initial Assessment"
            Status = "❌ Fail"
            Details = "Error: $($_.Exception.Message)"
        }
        $safetyCheck.OverallSafety = "❌ Cannot Assess"
    }
    
    return [PSCustomObject]$safetyCheck
}

# Usage
$safetyResult = Test-ServiceOperationSafety -ComputerName 'WEB01' -ServiceName 'W3SVC' -Operation 'Restart'

Write-Host "`n🛡️ Safety Assessment: $($safetyResult.ServiceName) on $($safetyResult.ComputerName)" -ForegroundColor Cyan
Write-Host "Overall Safety: $($safetyResult.OverallSafety)" -ForegroundColor Yellow

Write-Host "`nSafety Checks:" -ForegroundColor Yellow
$safetyResult.Checks | ForEach-Object {
    Write-Host "  $($_.Check): $($_.Status)" -ForegroundColor White
    if ($_.Details) { Write-Host "    $($_.Details)" -ForegroundColor Gray }
}

if ($safetyResult.Recommendations.Count -gt 0) {
    Write-Host "`nRecommendations:" -ForegroundColor Yellow
    $safetyResult.Recommendations | ForEach-Object { Write-Host "  • $_" -ForegroundColor Cyan }
}
```

## Integration and Automation

### Scheduled Maintenance Integration

```powershell
# Automated maintenance window execution
function Start-ScheduledMaintenance {
    param(
        [Parameter(Mandatory)]
        [hashtable]$MaintenancePlan,
        
        [string]$LogPath = "C:\Admin\MaintenanceLogs",
        
        [switch]$WhatIf
    )
    
    # Implementation for scheduled service maintenance
    # Integrates with task scheduler and monitoring systems
    # Includes rollback procedures and health verification
}
```

### Monitoring System Integration

```powershell
# SCOM/Nagios integration examples
function Send-ServiceAlert {
    param($ComputerName, $ServiceName, $Status, $Message)
    # Integration with monitoring systems
}

# Enhanced service operations with monitoring
Restart-RemoteService -ComputerName 'WEB01' -ServiceName 'W3SVC'
Send-ServiceAlert -ComputerName 'WEB01' -ServiceName 'W3SVC' -Status 'Restarted' -Message 'Service restarted successfully'
```

## Summary

The ServiceManagement module provides production-grade tools for:

1. **Safe Service Restart** - Graceful shutdown with dependency handling
2. **Intelligent Process Management** - Resource monitoring and safe termination
3. **Dependency Analysis** - Comprehensive service relationship mapping
4. **Safety Validation** - Pre-operation risk assessment
5. **Automation Integration** - Monitoring and scheduling system connectivity

### Key Safety Principles

- Always use `-WhatIf` when testing new operations
- Implement proper error handling and rollback procedures
- Consider business impact and timing
- Validate dependencies before service operations
- Monitor and log all maintenance activities
- Test operations in non-production environments first

---

> **Next Steps**: Explore the [Quick Reference Guide](../quick-reference/command-reference.md) for fast lookup of all Daily Admin Toolkit commands.