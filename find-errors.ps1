#!/usr/bin/env pwsh
#Requires -Version 7.0

<#
.SYNOPSIS
    Quick script to find all PSScriptAnalyzer errors in the codebase
.DESCRIPTION
    Focuses only on errors (not warnings or information) to quickly identify what needs to be fixed
#>

param(
    [switch]$ShowContext,
    [switch]$GroupByRule
)

Write-Host "`n🔍 Finding PSScriptAnalyzer Errors..." -ForegroundColor Magenta

# Check if analyzer is available
if (-not (Get-Module -ListAvailable PSScriptAnalyzer)) {
    Write-Host "❌ PSScriptAnalyzer not installed. Run: Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force" -ForegroundColor Red
    exit 1
}

Import-Module PSScriptAnalyzer

# Find all PS files
$files = Get-ChildItem -Path . -Include *.ps1, *.psm1, *.psd1 -Recurse | 
    Where-Object { $_.FullName -notmatch '[\\/](\.github|test|tests|docfx_project)[\\/]' }

Write-Host "Analyzing $($files.Count) files...`n" -ForegroundColor Gray

$errors = @()

foreach ($file in $files) {
    $results = Invoke-ScriptAnalyzer -Path $file.FullName -Severity Error
    if ($results) {
        $errors += $results | ForEach-Object {
            [PSCustomObject]@{
                File = $file.FullName.Replace($PWD.Path, '.').Replace('\', '/')
                Line = $_.Line
                Column = $_.Column
                Rule = $_.RuleName
                Message = $_.Message
                Extent = $_.Extent
            }
        }
    }
}

if ($errors.Count -eq 0) {
    Write-Host "✅ No errors found!" -ForegroundColor Green
    exit 0
}

Write-Host "❌ Found $($errors.Count) error(s):" -ForegroundColor Red

if ($GroupByRule) {
    # Group by rule
    $errorGroups = $errors | Group-Object Rule
    
    foreach ($group in $errorGroups | Sort-Object Count -Descending) {
        Write-Host "`n📌 Rule: $($group.Name) ($($group.Count) occurrence(s))" -ForegroundColor Yellow
        
        foreach ($err in $group.Group) {
            Write-Host "  - $($err.File):$($err.Line):$($err.Column)" -ForegroundColor White
            if ($ShowContext) {
                Write-Host "    $($err.Message)" -ForegroundColor Gray
                Write-Host "    Code: $($err.Extent)" -ForegroundColor DarkGray
            }
        }
    }
}
else {
    # Group by file
    $fileGroups = $errors | Group-Object File
    
    foreach ($group in $fileGroups) {
        Write-Host "`n📄 $($group.Name) ($($group.Count) error(s))" -ForegroundColor Yellow
        
        foreach ($err in $group.Group | Sort-Object Line) {
            Write-Host "  Line $($err.Line): [$($err.Rule)]" -ForegroundColor Red
            Write-Host "    $($err.Message)" -ForegroundColor Gray
            if ($ShowContext) {
                Write-Host "    Code: $($err.Extent)" -ForegroundColor DarkGray
            }
        }
    }
}

Write-Host "`n💡 To see more details, run:" -ForegroundColor Cyan
Write-Host "  ./find-errors.ps1 -ShowContext" -ForegroundColor White
Write-Host "  ./find-errors.ps1 -GroupByRule" -ForegroundColor White
Write-Host "  ./analyze-local.ps1 -Severity Error" -ForegroundColor White

exit 1