#!/usr/bin/env pwsh
#Requires -Version 7.0

<#
.SYNOPSIS
    Local PowerShell code analysis script for finding all PSScriptAnalyzer issues
.DESCRIPTION
    This script runs PSScriptAnalyzer locally to find all code issues before pushing to CI/CD
.EXAMPLE
    ./analyze-local.ps1
    ./analyze-local.ps1 -Severity Error
    ./analyze-local.ps1 -OutputFormat Detailed -ExportPath ./analysis-results.json
#>

[CmdletBinding()]
param(
    [ValidateSet('Error', 'Warning', 'Information', 'All')]
    [string]$Severity = 'All',
    
    [ValidateSet('Summary', 'Detailed', 'GitHub')]
    [string]$OutputFormat = 'Detailed',
    
    [string]$ExportPath = '',
    
    [switch]$InstallIfMissing,
    
    [string[]]$ExcludePaths = @('.github', 'test', 'tests', 'docfx_project')
)

# Colors for output
$colors = @{
    Error = 'Red'
    Warning = 'Yellow'
    Information = 'Cyan'
    Success = 'Green'
    Header = 'Magenta'
}

Write-Host "`n=== PowerShell Code Analysis ===" -ForegroundColor $colors.Header
Write-Host "Starting local analysis of PowerShell scripts`n" -ForegroundColor Gray

# Check if PSScriptAnalyzer is installed
$analyzer = Get-Module -ListAvailable -Name PSScriptAnalyzer | Select-Object -First 1

if (-not $analyzer) {
    if ($InstallIfMissing) {
        Write-Host "PSScriptAnalyzer not found. Installing..." -ForegroundColor $colors.Warning
        try {
            Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force -SkipPublisherCheck
            Import-Module PSScriptAnalyzer
            Write-Host "✓ PSScriptAnalyzer installed successfully" -ForegroundColor $colors.Success
        }
        catch {
            Write-Host "✗ Failed to install PSScriptAnalyzer: $_" -ForegroundColor $colors.Error
            Write-Host "`nTo install manually, run:" -ForegroundColor $colors.Information
            Write-Host "  Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force" -ForegroundColor White
            exit 1
        }
    }
    else {
        Write-Host "✗ PSScriptAnalyzer is not installed" -ForegroundColor $colors.Error
        Write-Host "`nInstall it using one of these methods:" -ForegroundColor $colors.Information
        Write-Host "  1. Run this script with -InstallIfMissing flag" -ForegroundColor White
        Write-Host "  2. Run: Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force" -ForegroundColor White
        Write-Host "  3. Use the project script: ./scripts/pipeline/Install-PSScriptAnalyzer.ps1" -ForegroundColor White
        exit 1
    }
}
else {
    Import-Module PSScriptAnalyzer
    Write-Host "✓ PSScriptAnalyzer $($analyzer.Version) is available" -ForegroundColor $colors.Success
}

# Discover all PowerShell files
Write-Host "`nDiscovering PowerShell files..." -ForegroundColor $colors.Header

$excludePattern = ($ExcludePaths | ForEach-Object { [regex]::Escape($_) }) -join '|'
$files = Get-ChildItem -Path . -Include *.ps1, *.psm1, *.psd1 -Recurse -File | 
    Where-Object { $_.FullName -notmatch "[\\/]($excludePattern)[\\/]" }

Write-Host "Found $($files.Count) PowerShell file(s) to analyze" -ForegroundColor $colors.Information

if ($files.Count -eq 0) {
    Write-Host "No PowerShell files found to analyze" -ForegroundColor $colors.Warning
    exit 0
}

# Run analysis
Write-Host "`nRunning PSScriptAnalyzer..." -ForegroundColor $colors.Header

$allResults = @()
$statistics = @{
    Error = 0
    Warning = 0
    Information = 0
    Total = 0
}

foreach ($file in $files) {
    $relativePath = $file.FullName.Replace($PWD.Path, '.').Replace('\', '/')
    
    try {
        $results = Invoke-ScriptAnalyzer -Path $file.FullName -ReportSummary
        
        if ($results) {
            $allResults += $results | ForEach-Object {
                $_ | Add-Member -NotePropertyName RelativePath -NotePropertyValue $relativePath -PassThru
            }
            
            # Update statistics
            $results | Group-Object Severity | ForEach-Object {
                $statistics[$_.Name] += $_.Count
                $statistics.Total += $_.Count
            }
        }
    }
    catch {
        Write-Host "✗ Failed to analyze $relativePath`: $_" -ForegroundColor $colors.Error
    }
}

# Filter by severity if requested
if ($Severity -ne 'All') {
    $allResults = $allResults | Where-Object { $_.Severity -eq $Severity }
}

# Output results based on format
Write-Host "`n=== Analysis Results ===" -ForegroundColor $colors.Header

switch ($OutputFormat) {
    'Summary' {
        Write-Host "`nSummary:" -ForegroundColor $colors.Header
        Write-Host "  Total Issues: $($statistics.Total)"
        Write-Host "  ❌ Errors: $($statistics.Error)" -ForegroundColor $colors.Error
        Write-Host "  ⚠️  Warnings: $($statistics.Warning)" -ForegroundColor $colors.Warning
        Write-Host "  ℹ️  Information: $($statistics.Information)" -ForegroundColor $colors.Information
        
        if ($statistics.Error -gt 0) {
            Write-Host "`n❌ ERRORS FOUND - These must be fixed:" -ForegroundColor $colors.Error
            $allResults | Where-Object { $_.Severity -eq 'Error' } | ForEach-Object {
                Write-Host "`n  File: $($_.RelativePath):$($_.Line)" -ForegroundColor White
                Write-Host "  Rule: $($_.RuleName)" -ForegroundColor $colors.Error
                Write-Host "  Message: $($_.Message)" -ForegroundColor Gray
            }
        }
    }
    
    'Detailed' {
        # Group by file
        $fileGroups = $allResults | Group-Object RelativePath
        
        foreach ($fileGroup in $fileGroups) {
            Write-Host "`n📄 $($fileGroup.Name)" -ForegroundColor $colors.Header
            Write-Host ("=" * 60) -ForegroundColor Gray
            
            foreach ($issue in $fileGroup.Group | Sort-Object Line) {
                $color = $colors[$issue.Severity]
                Write-Host "`n  [$($issue.Severity)] Line $($issue.Line), Column $($issue.Column)" -ForegroundColor $color
                Write-Host "  Rule: $($issue.RuleName)" -ForegroundColor $color
                Write-Host "  Message: $($issue.Message)" -ForegroundColor Gray
                
                if ($issue.SuggestedCorrections) {
                    Write-Host "  Suggestion: $($issue.SuggestedCorrections[0].Description)" -ForegroundColor $colors.Information
                }
            }
        }
        
        # Summary at the end
        Write-Host "`n=== Summary ===" -ForegroundColor $colors.Header
        Write-Host "Total Issues: $($statistics.Total)"
        Write-Host "❌ Errors: $($statistics.Error)" -ForegroundColor $colors.Error
        Write-Host "⚠️  Warnings: $($statistics.Warning)" -ForegroundColor $colors.Warning
        Write-Host "ℹ️  Information: $($statistics.Information)" -ForegroundColor $colors.Information
    }
    
    'GitHub' {
        # GitHub Actions annotation format
        foreach ($issue in $allResults) {
            $annotationType = switch ($issue.Severity) {
                'Error' { 'error' }
                'Warning' { 'warning' }
                'Information' { 'notice' }
            }
            
            Write-Host "::$annotationType file=$($issue.RelativePath),line=$($issue.Line),col=$($issue.Column)::[$($issue.RuleName)] $($issue.Message)"
        }
    }
}

# Export results if requested
if ($ExportPath) {
    try {
        $exportData = @{
            Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            Statistics = $statistics
            Results = $allResults | Select-Object @{N='File';E={$_.RelativePath}}, Line, Column, Severity, RuleName, Message, SuggestedCorrections
        }
        
        $exportData | ConvertTo-Json -Depth 5 | Out-File -FilePath $ExportPath -Encoding UTF8
        Write-Host "`n✓ Results exported to: $ExportPath" -ForegroundColor $colors.Success
    }
    catch {
        Write-Host "`n✗ Failed to export results: $_" -ForegroundColor $colors.Error
    }
}

# Exit with appropriate code
if ($statistics.Error -gt 0) {
    Write-Host "`n❌ Analysis failed - $($statistics.Error) error(s) found" -ForegroundColor $colors.Error
    Write-Host "Fix the errors and run this script again" -ForegroundColor $colors.Warning
    exit 1
}
elseif ($statistics.Warning -gt 0) {
    Write-Host "`n⚠️  Analysis completed with warnings" -ForegroundColor $colors.Warning
    exit 0
}
else {
    Write-Host "`n✅ Analysis passed - no issues found!" -ForegroundColor $colors.Success
    exit 0
}