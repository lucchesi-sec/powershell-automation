#Requires -Version 7.0
<#
.SYNOPSIS
    Formats PSScriptAnalyzer output for GitHub Actions annotations and reporting.

.DESCRIPTION
    This script takes PSScriptAnalyzer results and formats them for optimal display
    in GitHub Actions, including inline annotations, summary reports, and artifact
    generation for failed runs.

.PARAMETER AnalysisResults
    Array of PSScriptAnalyzer result objects to format.

.PARAMETER OutputPath
    Path where to save the formatted report file.

.PARAMETER Format
    Output format: GitHub, HTML, Markdown, or JSON.

.PARAMETER IncludeSummary
    Include a summary section in the report.

.PARAMETER GroupByFile
    Group results by file rather than by severity.

.PARAMETER GenerateArtifact
    Generate an artifact file for GitHub Actions upload.

.EXAMPLE
    $results = Invoke-ScriptAnalyzer -Path . -Recurse
    .\Format-AnalysisReport.ps1 -AnalysisResults $results -Format GitHub

.EXAMPLE
    .\Format-AnalysisReport.ps1 -AnalysisResults $results -OutputPath "analysis-report.html" -Format HTML

.NOTES
    This script is designed to work with the GitHub Actions workflow and provide
    rich feedback about code quality issues.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory, ValueFromPipeline)]
    [object[]]$AnalysisResults,
    
    [Parameter()]
    [string]$OutputPath,
    
    [Parameter()]
    [ValidateSet('GitHub', 'HTML', 'Markdown', 'JSON')]
    [string]$Format = 'GitHub',
    
    [Parameter()]
    [switch]$IncludeSummary = $true,
    
    [Parameter()]
    [switch]$GroupByFile,
    
    [Parameter()]
    [switch]$GenerateArtifact
)

# Import required modules

if (Test-Path $modulePath) {
    Import-Module $modulePath -Force
} else {
    # Fall back to installed module
    Import-Module PSAdminCore -Force -ErrorAction Stop
}

begin {
    # Initialize collections
    $allResults = @()
    $script:errorCount = 0
    $script:warningCount = 0
    $script:informationCount = 0
    $script:fileCount = @{}.GetEnumerator() | Select-Object -First 0
    
    # Helper function to escape HTML
    function ConvertTo-HtmlEncoded {
        param([string]$Text)
}
        [System.Web.HttpUtility]::HtmlEncode($Text)
    }
    
    # Helper function to create GitHub annotation
    function New-GitHubAnnotation {
        param(
            [string]$Level,
            [string]$Message,
            [string]$File,
            [int]$Line,
            [int]$Column,
            [string]$Title
        )

}
        $annotation = "::$($Level.ToLower())"
        
        if ($File) {
            # Convert to relative path for GitHub
            $relativePath = $File
            if (Test-Path $File) {
                $relativePath = Resolve-Path -Path $File -Relative -ErrorAction SilentlyContinue
                if (-not $relativePath) { $relativePath = $File }
            }
            
            $annotation += " file=$relativePath"
            if ($Line -gt 0) {
                $annotation += ",line=$Line"
                if ($Column -gt 0) {
                    $annotation += ",col=$Column"
}
            if ($Title) {
                $annotation += ",title=$Title"
}
        $annotation += "::$Message"
        return $annotation
    }
    
    # Helper function to generate summary statistics
    function Get-AnalysisSummary {
        param([object[]]$Results)

}
        $summary = @{
            TotalIssues = $Results.Count
            Errors = ($Results | Where-Object { $_.Severity -eq 'Error' }).Count
            Warnings = ($Results | Where-Object { $_.Severity -eq 'Warning' }).Count
            Information = ($Results | Where-Object { $_.Severity -eq 'Information' }).Count
            FilesAnalyzed = ($Results | Select-Object -ExpandProperty ScriptPath -Unique).Count
            RulesViolated = ($Results | Select-Object -ExpandProperty RuleName -Unique).Count
            TopViolatedRules = $Results | Group-Object RuleName | 
                Sort-Object Count -Descending | 
                Select-Object -First 5 @{Name='Rule';Expression={$_.Name}}, Count
        }
        
        return $summary
}
process {
    # Collect all results
    $allResults += $AnalysisResults
}

end {
    if ($allResults.Count -eq 0) {
        Write-Host "No analysis results to format." -ForegroundColor Green
        return
    }
    
    # Count issues by severity
    foreach ($result in $allResults) {
        switch ($result.Severity) {
            'Error' { $script:errorCount++ }
            'Warning' { $script:warningCount++ }
            'Information' { $script:informationCount++ }
        }
        
        # Track unique files
        if ($result.ScriptPath -and -not $script:fileCount.ContainsKey($result.ScriptPath)) {
            $script:fileCount[$result.ScriptPath] = $true
}
    # Format based on selected output type
    switch ($Format) {
        'GitHub' {
            # Output GitHub Actions annotations
            foreach ($result in $allResults) {
                $level = switch ($result.Severity) {
                    'Error' { 'error' }
                    'Warning' { 'warning' }
                    'Information' { 'notice' }
                }
                
                $annotation = New-GitHubAnnotation `
                    -Level $level `
                    -Message $result.Message `
                    -File $result.ScriptPath `
                    -Line $result.Line `
                    -Column $result.Column `
                    -Title $result.RuleName
                
                Write-Host $annotation
            }
            
            # Output summary as GitHub Actions summary
            if ($IncludeSummary) {
                $summary = Get-AnalysisSummary -Results $allResults
                
                $summaryMd = @"
## PSScriptAnalyzer Results Summary

| Metric | Value |
|--------|-------|
| Total Issues | $($summary.TotalIssues) |
| 🔴 Errors | $($summary.Errors) |
| 🟡 Warnings | $($summary.Warnings) |
| 🔵 Information | $($summary.Information) |
| Files Analyzed | $($summary.FilesAnalyzed) |
| Rules Violated | $($summary.RulesViolated) |

### Top Violated Rules
| Rule | Count |
|------|-------|
"@
                
                foreach ($rule in $summary.TopViolatedRules) {
                    $summaryMd += "`n| $($rule.Rule) | $($rule.Count) |"
                }
                
                # Write to GitHub Actions summary if available
                if ($env:GITHUB_STEP_SUMMARY) {
                    $summaryMd | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append
                }
                else {
                    Write-Host "`n$summaryMd"
}
        }
        
        'HTML' {
            $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>PSScriptAnalyzer Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .summary { background: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .error { color: #d32f2f; }
        .warning { color: #f57c00; }
        .information { color: #388e3c; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .rule-name { font-weight: bold; }
        .file-path { font-size: 0.9em; color: #666; }
        .location { font-size: 0.9em; }
        pre { background: #f5f5f5; padding: 10px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>PSScriptAnalyzer Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        <p>
            <span class="error">Errors: $script:errorCount</span> | 
            <span class="warning">Warnings: $script:warningCount</span> | 
            <span class="information">Information: $script:informationCount</span>
        </p>
        <p>Files Analyzed: $($script:fileCount.Count)</p>
    </div>
"@
            
            if ($GroupByFile) {
                $groupedResults = $allResults | Group-Object ScriptPath
                foreach ($group in $groupedResults) {
                    $html += "<h2>$($group.Name)</h2><table>"
                    $html += "<tr><th>Line</th><th>Severity</th><th>Rule</th><th>Message</th></tr>"
                    
                    foreach ($result in $group.Group | Sort-Object Line) {
                        $severityClass = $result.Severity.ToString().ToLower()
                        $html += "<tr>"
                        $html += "<td class='location'>$($result.Line):$($result.Column)</td>"
                        $html += "<td class='$severityClass'>$($result.Severity)</td>"
                        $html += "<td class='rule-name'>$($result.RuleName)</td>"
                        $html += "<td>$(ConvertTo-HtmlEncoded $result.Message)</td>"
                        $html += "</tr>"
                    }
                    $html += "</table>"
}
            else {
                $html += "<table>"
                $html += "<tr><th>Severity</th><th>File</th><th>Location</th><th>Rule</th><th>Message</th></tr>"
                
                foreach ($result in $allResults | Sort-Object Severity, ScriptPath, Line) {
                    $severityClass = $result.Severity.ToString().ToLower()
                    $html += "<tr>"
                    $html += "<td class='$severityClass'>$($result.Severity)</td>"
                    $html += "<td class='file-path'>$($result.ScriptPath)</td>"
                    $html += "<td class='location'>$($result.Line):$($result.Column)</td>"
                    $html += "<td class='rule-name'>$($result.RuleName)</td>"
                    $html += "<td>$(ConvertTo-HtmlEncoded $result.Message)</td>"
                    $html += "</tr>"
                }
                $html += "</table>"
            }
            
            $html += "</body></html>"
            
            if ($OutputPath) {
                $html | Out-File -FilePath $OutputPath -Encoding utf8
                Write-Host "HTML report saved to: $OutputPath" -ForegroundColor Green
            }
            else {
                Write-Output $html
}
        'Markdown' {
            $markdown = @"
# PSScriptAnalyzer Report

Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

## Summary

- **Errors**: $script:errorCount
- **Warnings**: $script:warningCount  
- **Information**: $script:informationCount
- **Files Analyzed**: $($script:fileCount.Count)

## Issues

"@
            
            if ($GroupByFile) {
                $groupedResults = $allResults | Group-Object ScriptPath
                foreach ($group in $groupedResults) {
                    $markdown += "`n### $($group.Name)`n`n"
                    $markdown += "| Line | Severity | Rule | Message |`n"
                    $markdown += "|------|----------|------|---------|`n"
                    
                    foreach ($result in $group.Group | Sort-Object Line) {
                        $markdown += "| $($result.Line):$($result.Column) | $($result.Severity) | $($result.RuleName) | $($result.Message) |`n"
}
            }
            else {
                $markdown += "| Severity | File | Location | Rule | Message |`n"
                $markdown += "|----------|------|----------|------|---------|`n"
                
                foreach ($result in $allResults | Sort-Object Severity, ScriptPath, Line) {
                    $markdown += "| $($result.Severity) | $($result.ScriptPath) | $($result.Line):$($result.Column) | $($result.RuleName) | $($result.Message) |`n"
}
            if ($OutputPath) {
                $markdown | Out-File -FilePath $OutputPath -Encoding utf8
                Write-Host "Markdown report saved to: $OutputPath" -ForegroundColor Green
            }
            else {
                Write-Output $markdown
}
        'JSON' {
            $jsonReport = @{
                metadata = @{
                    generatedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    totalIssues = $allResults.Count
                    errorCount = $script:errorCount
                    warningCount = $script:warningCount
                    informationCount = $script:informationCount
                    filesAnalyzed = $script:fileCount.Count
                }
                results = $allResults | Select-Object @{Name='file';Expression={$_.ScriptPath}},
                    @{Name='line';Expression={$_.Line}},
                    @{Name='column';Expression={$_.Column}},
                    @{Name='severity';Expression={$_.Severity.ToString()}},
                    @{Name='rule';Expression={$_.RuleName}},
                    @{Name='message';Expression={$_.Message}}
            }
            
            $json = $jsonReport | ConvertTo-Json -Depth 10
            
            if ($OutputPath) {
                $json | Out-File -FilePath $OutputPath -Encoding utf8
                Write-Host "JSON report saved to: $OutputPath" -ForegroundColor Green
            }
            else {
                Write-Output $json
}
    }
    
    # Generate artifact file for GitHub Actions
    if ($GenerateArtifact -and $allResults.Count -gt 0) {
        $artifactPath = "psscriptanalyzer-results.json"
        $artifactData = @{
            summary = Get-AnalysisSummary -Results $allResults
            results = $allResults | Select-Object ScriptPath, Line, Column, Severity, RuleName, Message, SuggestedCorrections
            metadata = @{
                generatedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                psVersion = $PSVersionTable.PSVersion.ToString()
                platform = $PSVersionTable.Platform
}
        $artifactData | ConvertTo-Json -Depth 10 | Out-File -FilePath $artifactPath -Encoding utf8
        Write-Host "Artifact file created: $artifactPath" -ForegroundColor Green
        
        # Output artifact path for GitHub Actions
        if ($env:GITHUB_OUTPUT) {
            "artifact-path=$artifactPath" | Out-File -FilePath $env:GITHUB_OUTPUT -Append
}
    # Return exit code based on results
    if ($script:errorCount -gt 0) {
        exit 1
    }
    elseif ($script:warningCount -gt 0 -and $env:FAIL_ON_WARNING -eq 'true') {
        exit 2
    }
    else {
        exit 0
}
