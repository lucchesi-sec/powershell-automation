#Requires -Version 7.0
<#
.SYNOPSIS
    Local test script for PowerShell CI pipeline validation.

.DESCRIPTION
    This script simulates the GitHub Actions workflow locally to help developers
    test their code before pushing. It runs the same PSScriptAnalyzer checks
    that will be executed in the CI pipeline.

.PARAMETER SkipInstall
    Skip PSScriptAnalyzer installation if already installed.

.PARAMETER ShowOnlyErrors
    Only display error-level issues, hiding warnings and information.

.EXAMPLE
    ./.github/workflows/test-local.ps1
    Run full local validation

.EXAMPLE
    ./.github/workflows/test-local.ps1 -SkipInstall -ShowOnlyErrors
    Run validation showing only errors, skip module installation
#>

[CmdletBinding()]
param(
    [switch]$SkipInstall,
    [switch]$ShowOnlyErrors
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host "=== PowerShell CI Pipeline - Local Test ===" -ForegroundColor Cyan
Write-Host "Running the same checks as GitHub Actions..." -ForegroundColor Gray
Write-Host ""

# Step 1: Check PowerShell version
Write-Host "📋 PowerShell Environment:" -ForegroundColor Yellow
Write-Host "  Version: $($PSVersionTable.PSVersion)"
Write-Host "  Platform: $($PSVersionTable.Platform)"
Write-Host ""

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host "❌ ERROR: PowerShell 7.0 or higher is required" -ForegroundColor Red
    Write-Host "  Current version: $($PSVersionTable.PSVersion)" -ForegroundColor Red
    Write-Host "  Download from: https://github.com/PowerShell/PowerShell/releases" -ForegroundColor Gray
    exit 1
}

# Step 2: Install/Import PSScriptAnalyzer
if (-not $SkipInstall) {
    Write-Host "📦 Installing PSScriptAnalyzer..." -ForegroundColor Yellow
    try {
        $installScript = Join-Path $PSScriptRoot "../../scripts/pipeline/Install-PSScriptAnalyzer.ps1"
        if (Test-Path $installScript) {
            & $installScript -SkipPublisherCheck
        } else {
            Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force -SkipPublisherCheck
        }
    }
    catch {
        Write-Host "❌ Failed to install PSScriptAnalyzer: $_" -ForegroundColor Red
        exit 1
    }
}

Import-Module PSScriptAnalyzer -ErrorAction Stop
$analyzerVersion = (Get-Module PSScriptAnalyzer).Version
Write-Host "✅ PSScriptAnalyzer $analyzerVersion loaded" -ForegroundColor Green
Write-Host ""

# Step 3: Discover modules
Write-Host "🔍 Discovering PowerShell modules..." -ForegroundColor Yellow
$repoRoot = Join-Path $PSScriptRoot "../.."
$modules = Get-ChildItem -Path $repoRoot -Include *.psm1 -Recurse -File | 
    Where-Object { $_.FullName -notmatch '[\\/](test|tests|\.github)[\\/]' }

if ($modules.Count -eq 0) {
    Write-Host "⚠️  No PowerShell module files (.psm1) found" -ForegroundColor Yellow
    exit 0
}

Write-Host "Found $($modules.Count) module(s):" -ForegroundColor Gray
$modules | ForEach-Object { 
    Write-Host "  • $($_.FullName.Replace($repoRoot, '').TrimStart('/', '\'))" -ForegroundColor Gray
}
Write-Host ""

# Step 4: Run analysis
Write-Host "🔬 Running code analysis..." -ForegroundColor Yellow
Write-Host "=" * 60 -ForegroundColor DarkGray

$totalIssues = 0
$errorCount = 0
$warningCount = 0
$infoCount = 0
$hasErrors = $false

foreach ($module in $modules) {
    $relativePath = $module.FullName.Replace($repoRoot, '').TrimStart('/', '\')
    Write-Host "`n📄 Analyzing: $relativePath" -ForegroundColor Cyan
    Write-Host "-" * 60 -ForegroundColor DarkGray
    
    try {
        $results = Invoke-ScriptAnalyzer -Path $module.FullName -Recurse
        
        if ($results) {
            foreach ($result in $results) {
                $totalIssues++
                
                # Format output based on severity
                $icon = switch ($result.Severity) {
                    'Error'       { '❌'; $errorCount++; $hasErrors = $true; 'Red' }
                    'Warning'     { '⚠️ '; $warningCount++; 'Yellow' }
                    'Information' { 'ℹ️ '; $infoCount++; 'Cyan' }
                    default       { '❓'; 'Gray' }
                }
                
                # Skip non-errors if requested
                if ($ShowOnlyErrors -and $result.Severity -ne 'Error') {
                    continue
                }
                
                $color = switch ($result.Severity) {
                    'Error'       { 'Red' }
                    'Warning'     { 'Yellow' }
                    'Information' { 'Cyan' }
                    default       { 'Gray' }
                }
                
                Write-Host "$icon $($result.Severity): Line $($result.Line), Column $($result.Column)" -ForegroundColor $color
                Write-Host "   Rule: $($result.RuleName)" -ForegroundColor $color
                Write-Host "   $($result.Message)" -ForegroundColor $color
                if ($result.SuggestedCorrections) {
                    Write-Host "   Suggestion: $($result.SuggestedCorrections[0].Description)" -ForegroundColor Gray
                }
            }
        } else {
            Write-Host "✅ No issues found" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "❌ Analysis failed: $_" -ForegroundColor Red
        $hasErrors = $true
        $errorCount++
    }
}

# Step 5: Summary
Write-Host "`n" + "=" * 60 -ForegroundColor DarkGray
Write-Host "📊 Analysis Summary:" -ForegroundColor Yellow
Write-Host "  Total Issues: $totalIssues"
Write-Host "  ❌ Errors: $errorCount" -ForegroundColor $(if ($errorCount -gt 0) { 'Red' } else { 'Gray' })
Write-Host "  ⚠️  Warnings: $warningCount" -ForegroundColor $(if ($warningCount -gt 0) { 'Yellow' } else { 'Gray' })
Write-Host "  ℹ️  Information: $infoCount" -ForegroundColor Gray
Write-Host "=" * 60 -ForegroundColor DarkGray

# Step 6: Result
if ($hasErrors) {
    Write-Host "`n❌ FAILED: $errorCount error(s) found" -ForegroundColor Red
    Write-Host "Fix these issues before pushing to avoid CI pipeline failures" -ForegroundColor Yellow
    exit 1
} else {
    Write-Host "`n✅ PASSED: No errors found" -ForegroundColor Green
    if ($warningCount -gt 0) {
        Write-Host "Consider addressing $warningCount warning(s) to improve code quality" -ForegroundColor Yellow
    }
    exit 0
}