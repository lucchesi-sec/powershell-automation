#Requires -Version 7.0
<#
.SYNOPSIS
    Performs static code analysis on PowerShell module files using PSScriptAnalyzer.

.DESCRIPTION
    This script recursively scans for .psm1 files and analyzes them using PSScriptAnalyzer
    with comprehensive error handling and reporting capabilities. It handles scenarios
    where modules may be missing (like PSAdminCore) and provides detailed feedback.

.PARAMETER Path
    The root path to scan for PowerShell module files. Defaults to current directory.

.PARAMETER Recurse
    Recursively search for .psm1 files in subdirectories.

.PARAMETER ExcludePath
    Array of paths to exclude from analysis.

.PARAMETER Severity
    Minimum severity level to report (Error, Warning, Information).

.PARAMETER ExcludeRule
    Array of rule names to exclude from analysis.

.PARAMETER OutputFormat
    Output format for results (Console, Json, Xml, GitHub).

.PARAMETER FailOnError
    Exit with non-zero code if any errors are found.

.PARAMETER FailOnWarning
    Exit with non-zero code if any warnings are found.

.EXAMPLE
    .\Invoke-CodeAnalysis.ps1 -Path ".\modules" -Recurse
    Analyzes all .psm1 files in the modules directory recursively.

.EXAMPLE
    .\Invoke-CodeAnalysis.ps1 -Severity Error -FailOnError -OutputFormat GitHub
    Analyzes with GitHub Actions output format and fails on errors.

.NOTES
    Exit Codes:
    0 - Success, no issues found
    1 - Analysis completed with errors found
    2 - Analysis completed with warnings found
    3 - PSScriptAnalyzer not installed
    4 - No module files found to analyze
    5 - Analysis failed due to exception
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateScript({ Test-Path $_ -PathType Container })]
    [string]$Path = $PWD,
    
    [Parameter()]
    [switch]$Recurse,
    
    [Parameter()]
    [string[]]$ExcludePath = @(),
    
    [Parameter()]
    [ValidateSet('Error', 'Warning', 'Information')]
    [string]$Severity = 'Information',
    
    [Parameter()]
    [string[]]$ExcludeRule = @(),
    
    [Parameter()]
    [ValidateSet('Console', 'Json', 'Xml', 'GitHub')]
    [string]$OutputFormat = 'Console',
    
    [Parameter()]
    [switch]$FailOnError,
    
    [Parameter()]
    [switch]$FailOnWarning
)

# Set strict mode for better error detection
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Initialize counters
$script:errorCount = 0
$script:warningCount = 0
$script:informationCount = 0
$script:fileCount = 0
$script:exitCode = 0

# Function to write GitHub Actions compatible output
function Write-GitHubOutput {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Error', 'Warning', 'Notice', 'Debug')]
        [string]$Level,
        
        [Parameter(Mandatory)]
        [string]$Message,
        
        [Parameter()]
        [string]$File,
        
        [Parameter()]
        [int]$Line,
        
        [Parameter()]
        [int]$Column
    )
    
    $annotation = "::$($Level.ToLower())"
    
    if ($File) {
        # Convert to relative path for GitHub Actions
        $relativePath = Resolve-Path -Path $File -Relative -ErrorAction SilentlyContinue
        if ($relativePath) {
            $File = $relativePath
        }
        
        $annotation += " file=$File"
        if ($Line -gt 0) {
            $annotation += ",line=$Line"
            if ($Column -gt 0) {
                $annotation += ",col=$Column"
            }
        }
    }
    
    $annotation += "::$Message"
    Write-Host $annotation
}

# Function to check if PSScriptAnalyzer is available
function Test-PSScriptAnalyzer {
    try {
        $module = Get-Module -ListAvailable -Name PSScriptAnalyzer -ErrorAction Stop
        if ($module) {
            Import-Module PSScriptAnalyzer -ErrorAction Stop
            Write-Host "✓ PSScriptAnalyzer $($module.Version) loaded successfully"
            return $true
        }
    }
    catch {
        Write-GitHubOutput -Level Error -Message "PSScriptAnalyzer module not found or could not be loaded: $_"
    }
    return $false
}

# Function to find module files
function Find-ModuleFiles {
    param(
        [string]$SearchPath,
        [bool]$RecurseSearch,
        [string[]]$ExcludePaths
    )
    
    $moduleFiles = @()
    
    try {
        Write-Host "Searching for .psm1 files in: $SearchPath"
        
        $searchParams = @{
            Path = $SearchPath
            Filter = '*.psm1'
            File = $true
            ErrorAction = 'SilentlyContinue'
        }
        
        if ($RecurseSearch) {
            $searchParams['Recurse'] = $true
        }
        
        $files = Get-ChildItem @searchParams
        
        foreach ($file in $files) {
            $excluded = $false
            foreach ($excludePath in $ExcludePaths) {
                if ($file.FullName -like "*$excludePath*") {
                    $excluded = $true
                    Write-Host "  Excluding: $($file.FullName)"
                    break
                }
            }
            
            if (-not $excluded) {
                $moduleFiles += $file
            }
        }
        
        Write-Host "Found $($moduleFiles.Count) module file(s) to analyze"
    }
    catch {
        Write-GitHubOutput -Level Error -Message "Error searching for module files: $_"
    }
    
    return $moduleFiles
}

# Function to analyze a single file
function Invoke-FileAnalysis {
    param(
        [System.IO.FileInfo]$File,
        [string]$MinSeverity,
        [string[]]$ExcludedRules
    )
    
    Write-Host "`nAnalyzing: $($File.FullName)"
    
    $analysisParams = @{
        Path = $File.FullName
        Severity = $MinSeverity
        ErrorAction = 'SilentlyContinue'
    }
    
    if ($ExcludedRules.Count -gt 0) {
        $analysisParams['ExcludeRule'] = $ExcludedRules
    }
    
    try {
        # Check if file exists and is readable
        if (-not (Test-Path $File.FullName -PathType Leaf)) {
            Write-GitHubOutput -Level Warning -Message "File not found: $($File.FullName)"
            return @()
        }
        
        # Check if file is empty
        if ((Get-Item $File.FullName).Length -eq 0) {
            Write-GitHubOutput -Level Warning -Message "File is empty: $($File.FullName)"
            return @()
        }
        
        # Perform analysis
        $results = Invoke-ScriptAnalyzer @analysisParams
        
        if ($results) {
            Write-Host "  Found $($results.Count) issue(s)"
        }
        else {
            Write-Host "  ✓ No issues found"
        }
        
        return $results
    }
    catch {
        Write-GitHubOutput -Level Error -Message "Failed to analyze $($File.FullName): $_" -File $File.FullName
        return @()
    }
}

# Function to format and output results
function Format-AnalysisResults {
    param(
        [array]$Results,
        [string]$Format
    )
    
    switch ($Format) {
        'Console' {
            foreach ($result in $Results) {
                $severity = $result.Severity.ToString()
                $message = "$severity`: $($result.RuleName) - $($result.Message)"
                
                Write-Host ""
                Write-Host "File: $($result.ScriptPath)" -ForegroundColor Cyan
                Write-Host "Line $($result.Line), Column $($result.Column)" -ForegroundColor Gray
                
                switch ($result.Severity) {
                    'Error' { 
                        Write-Host $message -ForegroundColor Red
                        $script:errorCount++
                    }
                    'Warning' { 
                        Write-Host $message -ForegroundColor Yellow
                        $script:warningCount++
                    }
                    'Information' { 
                        Write-Host $message -ForegroundColor Green
                        $script:informationCount++
                    }
                }
                
                if ($result.SuggestedCorrections) {
                    Write-Host "Suggestion: $($result.SuggestedCorrections[0].Description)" -ForegroundColor Blue
                }
            }
        }
        
        'GitHub' {
            foreach ($result in $Results) {
                $level = switch ($result.Severity) {
                    'Error' { 'Error' }
                    'Warning' { 'Warning' }
                    'Information' { 'Notice' }
                }
                
                $message = "$($result.RuleName): $($result.Message)"
                Write-GitHubOutput -Level $level -Message $message -File $result.ScriptPath -Line $result.Line -Column $result.Column
                
                # Update counters
                switch ($result.Severity) {
                    'Error' { $script:errorCount++ }
                    'Warning' { $script:warningCount++ }
                    'Information' { $script:informationCount++ }
                }
            }
        }
        
        'Json' {
            $Results | ConvertTo-Json -Depth 10
        }
        
        'Xml' {
            $Results | ConvertTo-Xml -Depth 10 -As String
        }
    }
}

# Main execution
try {
    Write-Host "=== PowerShell Code Analysis ===" -ForegroundColor Cyan
    Write-Host "Path: $Path"
    Write-Host "Recurse: $Recurse"
    Write-Host "Severity: $Severity"
    Write-Host "Output Format: $OutputFormat"
    Write-Host ""
    
    # Check if PSScriptAnalyzer is available
    if (-not (Test-PSScriptAnalyzer)) {
        Write-Host "PSScriptAnalyzer is not installed. Run Install-PSScriptAnalyzer.ps1 first." -ForegroundColor Red
        exit 3
    }
    
    # Find module files
    $moduleFiles = Find-ModuleFiles -SearchPath $Path -RecurseSearch $Recurse -ExcludePaths $ExcludePath
    
    if ($moduleFiles.Count -eq 0) {
        Write-GitHubOutput -Level Warning -Message "No .psm1 files found to analyze in $Path"
        
        # Special handling for missing PSAdminCore module
        $coreModulePath = Join-Path $Path "modules\PSAdminCore\PSAdminCore.psm1"
        if (-not (Test-Path $coreModulePath)) {
            Write-GitHubOutput -Level Notice -Message "PSAdminCore module not found at expected location. This is a known issue in the repository."
        }
        
        exit 4
    }
    
    # Analyze each file
    $allResults = @()
    foreach ($file in $moduleFiles) {
        $script:fileCount++
        $fileResults = Invoke-FileAnalysis -File $file -MinSeverity $Severity -ExcludedRules $ExcludeRule
        if ($fileResults) {
            $allResults += $fileResults
        }
    }
    
    # Output results
    if ($allResults.Count -gt 0) {
        Write-Host "`n=== Analysis Results ===" -ForegroundColor Cyan
        Format-AnalysisResults -Results $allResults -Format $OutputFormat
    }
    
    # Summary
    Write-Host "`n=== Summary ===" -ForegroundColor Cyan
    Write-Host "Files Analyzed: $script:fileCount"
    Write-Host "Errors: $script:errorCount" -ForegroundColor $(if ($script:errorCount -gt 0) { 'Red' } else { 'Green' })
    Write-Host "Warnings: $script:warningCount" -ForegroundColor $(if ($script:warningCount -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "Information: $script:informationCount" -ForegroundColor Green
    
    # Determine exit code
    if ($FailOnError -and $script:errorCount -gt 0) {
        $script:exitCode = 1
        Write-GitHubOutput -Level Error -Message "Analysis failed: $script:errorCount error(s) found"
    }
    elseif ($FailOnWarning -and $script:warningCount -gt 0) {
        $script:exitCode = 2
        Write-GitHubOutput -Level Warning -Message "Analysis completed with warnings: $script:warningCount warning(s) found"
    }
    else {
        Write-Host "`n✓ Analysis completed successfully" -ForegroundColor Green
    }
}
catch {
    $script:exitCode = 5
    Write-GitHubOutput -Level Error -Message "Analysis failed with exception: $_"
    Write-Error "Code analysis failed: $_" -ErrorAction Continue
}

exit $script:exitCode