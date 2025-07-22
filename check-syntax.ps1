#!/usr/bin/env pwsh
#Requires -Version 7.0

<#
.SYNOPSIS
    Checks all PowerShell files for syntax errors
#>

Write-Host "`n🔍 Checking PowerShell Syntax..." -ForegroundColor Magenta

$files = Get-ChildItem -Path . -Include *.ps1, *.psm1, *.psd1 -Recurse | 
    Where-Object { $_.FullName -notmatch '[\\/](\.github|test|tests|docfx_project)[\\/]' }

$syntaxErrors = @()

foreach ($file in $files) {
    $relativePath = $file.FullName.Replace($PWD.Path, '.').Replace('\', '/')
    Write-Host "Checking: $relativePath" -ForegroundColor Gray
    
    $errors = $null
    $tokens = $null
    
    try {
        $null = [System.Management.Automation.Language.Parser]::ParseFile(
            $file.FullName, 
            [ref]$tokens, 
            [ref]$errors
        )
        
        if ($errors.Count -gt 0) {
            foreach ($parseError in $errors) {
                $syntaxErrors += [PSCustomObject]@{
                    File = $relativePath
                    Line = $parseError.Extent.StartLineNumber
                    Column = $parseError.Extent.StartColumnNumber
                    Message = $parseError.Message
                    ErrorId = $parseError.ErrorId
                }
                
                Write-Host "  ❌ SYNTAX ERROR at line $($parseError.Extent.StartLineNumber): $($parseError.Message)" -ForegroundColor Red
            }
        }
    }
    catch {
        Write-Host "  ❌ FAILED TO PARSE: $_" -ForegroundColor Red
        $syntaxErrors += [PSCustomObject]@{
            File = $relativePath
            Line = 0
            Column = 0
            Message = $_.Exception.Message
            ErrorId = "ParseException"
        }
    }
}

if ($syntaxErrors.Count -eq 0) {
    Write-Host "`n✅ No syntax errors found!" -ForegroundColor Green
} else {
    Write-Host "`n❌ Found $($syntaxErrors.Count) syntax error(s):" -ForegroundColor Red
    $syntaxErrors | Format-Table -AutoSize
}

Write-Host "`n📊 Summary:" -ForegroundColor Cyan
Write-Host "  Files checked: $($files.Count)" -ForegroundColor White
Write-Host "  Syntax errors: $($syntaxErrors.Count)" -ForegroundColor $(if ($syntaxErrors.Count -eq 0) { 'Green' } else { 'Red' })

exit $(if ($syntaxErrors.Count -eq 0) { 0 } else { 1 })