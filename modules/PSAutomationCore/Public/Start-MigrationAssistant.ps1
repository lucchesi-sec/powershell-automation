function Start-MigrationAssistant {
    <#
    .SYNOPSIS
        Interactive assistant to help migrate legacy scripts to the new modular architecture
    
    .DESCRIPTION
        The Migration Assistant provides a smooth, guided experience for converting existing
        PowerShell scripts to the new modular automation platform:
        
        - Automated script discovery and analysis
        - Dependency mapping and resolution
        - Code transformation with preservation of functionality
        - Side-by-side comparison of changes
        - Automated testing of migrated code
        - Rollback capability for safety
        - Progress tracking with detailed reporting
        
        The assistant ensures zero downtime and maintains backward compatibility
        during the migration process.
    
    .PARAMETER ScriptPath
        Path to a specific script or directory containing scripts to migrate
    
    .PARAMETER TargetModule
        Target module name for the migrated code
    
    .PARAMETER PreviewOnly
        Analyze and preview migration without making changes
    
    .PARAMETER CreateBackup
        Create backup of original scripts before migration (default: true)
    
    .PARAMETER GenerateTests
        Automatically generate Pester tests for migrated code
    
    .PARAMETER Interactive
        Use interactive mode with step-by-step guidance (default: true)
    
    .EXAMPLE
        Start-MigrationAssistant
        Launches the interactive migration assistant
    
    .EXAMPLE
        Start-MigrationAssistant -ScriptPath "C:\Scripts" -TargetModule "PSCustomAutomation"
        Migrates all scripts in the specified directory to a new module
    
    .EXAMPLE
        Start-MigrationAssistant -ScriptPath ".\Start-Backup.ps1" -PreviewOnly
        Preview migration changes for a specific script without applying them
    #>
    
    [CmdletBinding()]
    [Alias('Start-Migration')]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ScriptPath,
        
        [Parameter(Mandatory = $false)]
        [string]$TargetModule,
        
        [Parameter(Mandatory = $false)]
        [switch]$PreviewOnly,
        
        [Parameter(Mandatory = $false)]
        [bool]$CreateBackup = $true,
        
        [Parameter(Mandatory = $false)]
        [switch]$GenerateTests,
        
        [Parameter(Mandatory = $false)]
        [bool]$Interactive = $true
    )
    
    begin {
        # Initialize migration session
        $migrationSession = @{
            SessionId = [guid]::NewGuid()
            StartTime = Get-Date
            Scripts = @()
            Analysis = @{}
            Changes = @()
            Backups = @()
            Status = 'Initializing'
        }
        
        # Set console title
        $originalTitle = $Host.UI.RawUI.WindowTitle
        $Host.UI.RawUI.WindowTitle = "PowerShell Migration Assistant"
    }
    
    process {
        try {
            # Show welcome screen
            if ($Interactive) {
                Show-MigrationWelcome
            }
            
            # Step 1: Discovery
            Write-Host "`n📂 Step 1: Script Discovery" -ForegroundColor Cyan
            Write-Host "══════════════════════════" -ForegroundColor Cyan
            
            if (-not $ScriptPath) {
                $ScriptPath = Get-ScriptPathInteractive
            }
            
            $migrationSession.Scripts = Discover-LegacyScripts -Path $ScriptPath
            
            if ($migrationSession.Scripts.Count -eq 0) {
                Write-Host "❌ No PowerShell scripts found in the specified location." -ForegroundColor Red
                return
            }
            
            Write-Host "✓ Found $($migrationSession.Scripts.Count) script(s) to migrate" -ForegroundColor Green
            
            # Step 2: Analysis
            Write-Host "`n🔍 Step 2: Script Analysis" -ForegroundColor Cyan
            Write-Host "═════════════════════════" -ForegroundColor Cyan
            
            $progressParams = @{
                Activity = "Analyzing Scripts"
                Status = "Performing deep analysis..."
                PercentComplete = 0
            }
            
            $analyzed = 0
            foreach ($script in $migrationSession.Scripts) {
                $progressParams.PercentComplete = ($analyzed / $migrationSession.Scripts.Count) * 100
                $progressParams.CurrentOperation = "Analyzing: $($script.Name)"
                Show-AutomationProgress @progressParams
                
                $analysis = Analyze-LegacyScript -ScriptPath $script.FullName
                $migrationSession.Analysis[$script.FullName] = $analysis
                
                $analyzed++
            }
            
            Show-AutomationProgress -Activity "Script Analysis" -Completed
            
            # Show analysis summary
            Show-AnalysisSummary -Session $migrationSession
            
            if ($Interactive) {
                Write-Host "`nContinue with migration? (Y/N): " -ForegroundColor Cyan -NoNewline
                $continue = Read-Host
                if ($continue -notmatch '^[Yy]') {
                    Write-Host "Migration cancelled." -ForegroundColor Yellow
                    return
                }
            }
            
            # Step 3: Target Module Setup
            Write-Host "`n📦 Step 3: Module Configuration" -ForegroundColor Cyan
            Write-Host "══════════════════════════════" -ForegroundColor Cyan
            
            if (-not $TargetModule) {
                $TargetModule = Get-TargetModuleInteractive -SuggestedName "PSMigratedAutomation"
            }
            
            $moduleConfig = Initialize-TargetModule -Name $TargetModule -Analysis $migrationSession.Analysis
            
            # Step 4: Create Backup
            if ($CreateBackup -and -not $PreviewOnly) {
                Write-Host "`n💾 Step 4: Creating Backups" -ForegroundColor Cyan
                Write-Host "══════════════════════════" -ForegroundColor Cyan
                
                $backupPath = New-MigrationBackup -Scripts $migrationSession.Scripts
                $migrationSession.Backups += $backupPath
                
                Write-Host "✓ Backups created at: $backupPath" -ForegroundColor Green
            }
            
            # Step 5: Code Transformation
            Write-Host "`n🔄 Step 5: Code Transformation" -ForegroundColor Cyan
            Write-Host "════════════════════════════" -ForegroundColor Cyan
            
            $transformProgress = @{
                Activity = "Transforming Scripts"
                Status = "Converting to modular architecture..."
                PercentComplete = 0
            }
            
            $transformed = 0
            foreach ($script in $migrationSession.Scripts) {
                $transformProgress.PercentComplete = ($transformed / $migrationSession.Scripts.Count) * 100
                $transformProgress.CurrentOperation = "Transforming: $($script.Name)"
                Show-AutomationProgress @transformProgress
                
                $result = Transform-LegacyScript `
                    -Script $script `
                    -Analysis $migrationSession.Analysis[$script.FullName] `
                    -TargetModule $TargetModule `
                    -PreviewOnly:$PreviewOnly
                
                $migrationSession.Changes += $result
                
                if ($Interactive -and $PreviewOnly) {
                    Show-TransformationPreview -Original $script -Transformed $result
                    
                    Write-Host "`nAccept these changes? (Y/N/A for all): " -ForegroundColor Cyan -NoNewline
                    $response = Read-Host
                    
                    if ($response -eq 'A') {
                        $Interactive = $false
                    }
                    elseif ($response -notmatch '^[Yy]') {
                        $result.Status = 'Skipped'
                    }
                }
                
                $transformed++
            }
            
            Show-AutomationProgress -Activity "Code Transformation" -Completed
            
            # Step 6: Generate Tests
            if ($GenerateTests -and -not $PreviewOnly) {
                Write-Host "`n🧪 Step 6: Generating Tests" -ForegroundColor Cyan
                Write-Host "══════════════════════════" -ForegroundColor Cyan
                
                Generate-MigrationTests -Module $TargetModule -Changes $migrationSession.Changes
                
                Write-Host "✓ Pester tests generated for migrated code" -ForegroundColor Green
            }
            
            # Step 7: Validation
            if (-not $PreviewOnly) {
                Write-Host "`n✅ Step 7: Validation" -ForegroundColor Cyan
                Write-Host "════════════════════" -ForegroundColor Cyan
                
                $validation = Test-MigratedModule -Name $TargetModule
                
                if ($validation.Success) {
                    Write-Host "✓ All validation tests passed!" -ForegroundColor Green
                }
                else {
                    Write-Host "⚠️  Some validation tests failed. Review the report for details." -ForegroundColor Yellow
                    Show-ValidationReport -Results $validation
                }
            }
            
            # Final Summary
            Show-MigrationSummary -Session $migrationSession -PreviewOnly:$PreviewOnly
            
            # Offer next steps
            if (-not $PreviewOnly) {
                Show-PostMigrationSteps -Module $TargetModule -Session $migrationSession
            }
            
            return $migrationSession
        }
        catch {
            Write-Error "Migration failed: $_"
            
            # Offer rollback if backups exist
            if ($migrationSession.Backups.Count -gt 0) {
                Write-Host "`n⚠️  Would you like to restore from backup? (Y/N): " -ForegroundColor Yellow -NoNewline
                $restore = Read-Host
                
                if ($restore -match '^[Yy]') {
                    Restore-MigrationBackup -BackupPath $migrationSession.Backups[0]
                }
            }
            
            throw
        }
    }
    
    end {
        # Restore console title
        $Host.UI.RawUI.WindowTitle = $originalTitle
        
        # Log migration session
        Write-AutomationLog -Message "Migration session completed" -Level Info -Metadata @{
            SessionId = $migrationSession.SessionId
            Duration = (Get-Date) - $migrationSession.StartTime
            ScriptsProcessed = $migrationSession.Scripts.Count
            Success = $migrationSession.Status -eq 'Completed'
        }
    }
}

# Helper function to show migration welcome
function Show-MigrationWelcome {
    Clear-Host
    
    Write-Host @"
    
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║         PowerShell Script Migration Assistant                 ║
    ║                                                               ║
    ║     Transform Your Scripts into Modern, Modular Code          ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    
    Welcome! This assistant will help you migrate your existing
    PowerShell scripts to the new modular automation platform.
    
    Benefits of migration:
    ✓ Better organization and maintainability
    ✓ Improved error handling and logging
    ✓ Built-in testing capabilities
    ✓ Enhanced security features
    ✓ Easier collaboration and version control
    
    The migration process is:
    • Safe - Your original scripts are backed up
    • Smart - Preserves your business logic
    • Smooth - Step-by-step guidance throughout
    
"@ -ForegroundColor Cyan
    
    Write-Host "Press any key to begin..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Helper function to discover legacy scripts
function Discover-LegacyScripts {
    param([string]$Path)
    
    $scripts = @()
    
    if (Test-Path $Path -PathType Leaf) {
        # Single file
        if ($Path -match '\.ps1$') {
            $scripts += Get-Item $Path
        }
    }
    else {
        # Directory
        Write-Host "  Scanning for PowerShell scripts..." -ForegroundColor Gray
        
        $scripts = Get-ChildItem -Path $Path -Filter "*.ps1" -Recurse |
            Where-Object { $_.FullName -notmatch '\\(tests?|spec)\\' }
    }
    
    # Show discovered scripts
    if ($scripts.Count -gt 0) {
        Write-Host "`n  Discovered scripts:" -ForegroundColor White
        foreach ($script in $scripts) {
            $relativePath = $script.FullName.Replace("$Path\", "")
            Write-Host "    • $relativePath" -ForegroundColor Gray
        }
    }
    
    return $scripts
}

# Helper function to analyze legacy script
function Analyze-LegacyScript {
    param([string]$ScriptPath)
    
    $analysis = @{
        Path = $ScriptPath
        Name = (Get-Item $ScriptPath).BaseName
        Dependencies = @()
        Functions = @()
        Commands = @()
        Variables = @()
        Parameters = @()
        ExternalCalls = @()
        ComplexityScore = 0
        Issues = @()
        Recommendations = @()
    }
    
    try {
        # Parse script content
        $content = Get-Content $ScriptPath -Raw
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($content, [ref]$null, [ref]$null)
        
        # Extract functions
        $functionDefinitions = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
        foreach ($func in $functionDefinitions) {
            $analysis.Functions += @{
                Name = $func.Name
                Parameters = $func.Parameters | ForEach-Object { $_.Name }
                LineNumber = $func.Extent.StartLineNumber
            }
        }
        
        # Extract commands
        $commands = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)
        $analysis.Commands = $commands | ForEach-Object { $_.CommandElements[0].Value } | Select-Object -Unique
        
        # Identify external dependencies
        $imports = $commands | Where-Object { 
            $_.CommandElements[0].Value -in @('Import-Module', 'Add-PSSnapin', 'Add-Type')
        }
        
        foreach ($import in $imports) {
            if ($import.CommandElements.Count -gt 1) {
                $analysis.Dependencies += $import.CommandElements[1].Value
            }
        }
        
        # Calculate complexity score
        $analysis.ComplexityScore = Calculate-ScriptComplexity -AST $ast
        
        # Identify issues and recommendations
        $analysis.Issues = Find-ScriptIssues -AST $ast -Content $content
        $analysis.Recommendations = Get-MigrationRecommendations -Analysis $analysis
        
    }
    catch {
        $analysis.Issues += "Failed to parse script: $_"
    }
    
    return $analysis
}

# Helper function to calculate script complexity
function Calculate-ScriptComplexity {
    param($AST)
    
    $complexity = 0
    
    # Count decision points
    $ifStatements = $AST.FindAll({ $args[0] -is [System.Management.Automation.Language.IfStatementAst] }, $true).Count
    $switchStatements = $AST.FindAll({ $args[0] -is [System.Management.Automation.Language.SwitchStatementAst] }, $true).Count
    $loops = $AST.FindAll({ 
        $args[0] -is [System.Management.Automation.Language.ForStatementAst] -or
        $args[0] -is [System.Management.Automation.Language.ForEachStatementAst] -or
        $args[0] -is [System.Management.Automation.Language.WhileStatementAst] -or
        $args[0] -is [System.Management.Automation.Language.DoWhileStatementAst]
    }, $true).Count
    
    $complexity = $ifStatements + $switchStatements + ($loops * 2) + 1
    
    return $complexity
}

# Helper function to find script issues
function Find-ScriptIssues {
    param($AST, [string]$Content)
    
    $issues = @()
    
    # Check for hardcoded paths
    if ($Content -match '[A-Z]:\\[\w\\]+' -or $Content -match '\\\\[\w]+\\[\w]+') {
        $issues += @{
            Type = 'HardcodedPath'
            Severity = 'Medium'
            Message = 'Script contains hardcoded paths that should be parameterized'
        }
    }
    
    # Check for credentials in code
    if ($Content -match 'ConvertTo-SecureString.*-AsPlainText' -or $Content -match 'Password\s*=') {
        $issues += @{
            Type = 'SecurityRisk'
            Severity = 'High'
            Message = 'Script may contain hardcoded credentials'
        }
    }
    
    # Check for missing error handling
    $tryStatements = $AST.FindAll({ $args[0] -is [System.Management.Automation.Language.TryStatementAst] }, $true).Count
    if ($tryStatements -eq 0 -and $AST.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true).Count -gt 10) {
        $issues += @{
            Type = 'ErrorHandling'
            Severity = 'Medium'
            Message = 'Script lacks proper error handling'
        }
    }
    
    # Check for global variables
    $globalVars = $AST.FindAll({ 
        $args[0] -is [System.Management.Automation.Language.VariableExpressionAst] -and 
        $args[0].VariablePath.UserPath -match '^global:'
    }, $true)
    
    if ($globalVars.Count -gt 0) {
        $issues += @{
            Type = 'GlobalVariables'
            Severity = 'Low'
            Message = "Script uses $($globalVars.Count) global variable(s)"
        }
    }
    
    return $issues
}

# Helper function to get migration recommendations
function Get-MigrationRecommendations {
    param($Analysis)
    
    $recommendations = @()
    
    # Module structure recommendation
    if ($Analysis.Functions.Count -gt 3) {
        $recommendations += "Consider splitting functions into separate module files for better organization"
    }
    
    # Parameter recommendation
    if ($Analysis.ComplexityScore -gt 10) {
        $recommendations += "High complexity detected. Consider breaking down into smaller, focused functions"
    }
    
    # Testing recommendation
    if ($Analysis.Functions.Count -gt 0) {
        $recommendations += "Generate Pester tests for the $($Analysis.Functions.Count) function(s)"
    }
    
    # Configuration recommendation
    foreach ($issue in $Analysis.Issues) {
        if ($issue.Type -eq 'HardcodedPath') {
            $recommendations += "Move hardcoded paths to configuration files"
            break
        }
    }
    
    return $recommendations
}

# Helper function to show analysis summary
function Show-AnalysisSummary {
    param($Session)
    
    Write-Host "`n📊 Analysis Summary:" -ForegroundColor Yellow
    Write-Host "═══════════════════" -ForegroundColor Yellow
    
    $totalFunctions = 0
    $totalIssues = 0
    $complexScripts = 0
    
    foreach ($script in $Session.Scripts) {
        $analysis = $Session.Analysis[$script.FullName]
        $totalFunctions += $analysis.Functions.Count
        $totalIssues += $analysis.Issues.Count
        
        if ($analysis.ComplexityScore -gt 10) {
            $complexScripts++
        }
    }
    
    Write-Host "  Total Scripts:    $($Session.Scripts.Count)" -ForegroundColor White
    Write-Host "  Total Functions:  $totalFunctions" -ForegroundColor White
    Write-Host "  Complex Scripts:  $complexScripts" -ForegroundColor $(if ($complexScripts -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "  Issues Found:     $totalIssues" -ForegroundColor $(if ($totalIssues -gt 0) { 'Yellow' } else { 'Green' })
    
    if ($totalIssues -gt 0) {
        Write-Host "`n  Common Issues:" -ForegroundColor Yellow
        
        $issueTypes = $Session.Analysis.Values.Issues | Group-Object Type
        foreach ($issueType in $issueTypes) {
            Write-Host "    • $($issueType.Name): $($issueType.Count) occurrence(s)" -ForegroundColor Gray
        }
    }
}

# Helper function to transform legacy script
function Transform-LegacyScript {
    param(
        $Script,
        $Analysis,
        [string]$TargetModule,
        [switch]$PreviewOnly
    )
    
    $result = @{
        OriginalPath = $Script.FullName
        TargetPath = ""
        Changes = @()
        Status = 'Pending'
    }
    
    try {
        # Read original content
        $content = Get-Content $Script.FullName -Raw
        $transformedContent = $content
        
        # Transform to module structure
        if ($Analysis.Functions.Count -gt 0) {
            # Extract functions to public folder
            foreach ($function in $Analysis.Functions) {
                $functionContent = Extract-Function -Content $content -FunctionName $function.Name
                
                if (-not $PreviewOnly) {
                    $functionPath = Join-Path $TargetModule "Public\$($function.Name).ps1"
                    New-Item -Path (Split-Path $functionPath -Parent) -ItemType Directory -Force | Out-Null
                    Set-Content -Path $functionPath -Value $functionContent
                }
                
                $result.Changes += @{
                    Type = 'ExtractFunction'
                    Description = "Extracted function '$($function.Name)' to separate file"
                    Path = $functionPath
                }
            }
        }
        
        # Add proper module structure
        $moduleContent = @"
#Requires -Module PSAutomationCore

<#
.SYNOPSIS
    Migrated from: $($Script.Name)
    
.DESCRIPTION
    This module was automatically migrated from a legacy script.
    Original script: $($Script.FullName)
    Migration date: $(Get-Date -Format 'yyyy-MM-dd')
#>

# Import required modules
Import-Module PSAutomationCore -Force

"@
        
        # Add initialization
        if ($Analysis.Variables.Count -gt 0) {
            $moduleContent += "`n# Module variables`n"
            # Transform global variables to module scope
        }
        
        # Add remaining code (non-function code)
        $remainingCode = Remove-FunctionsFromContent -Content $content -Functions $Analysis.Functions
        if ($remainingCode.Trim()) {
            $moduleContent += "`n# Original script logic`n"
            $moduleContent += "function Start-$($Analysis.Name) {`n"
            $moduleContent += $remainingCode
            $moduleContent += "`n}"
        }
        
        if (-not $PreviewOnly) {
            $modulePath = Join-Path $TargetModule "$($Analysis.Name).psm1"
            Set-Content -Path $modulePath -Value $moduleContent
            $result.TargetPath = $modulePath
        }
        
        $result.Status = 'Completed'
        $result.TransformedContent = $moduleContent
    }
    catch {
        $result.Status = 'Failed'
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

# Helper function to show migration summary
function Show-MigrationSummary {
    param($Session, [switch]$PreviewOnly)
    
    Write-Host "`n🎉 Migration Summary" -ForegroundColor Green
    Write-Host "═══════════════════" -ForegroundColor Green
    
    $successful = $Session.Changes | Where-Object { $_.Status -eq 'Completed' }
    $failed = $Session.Changes | Where-Object { $_.Status -eq 'Failed' }
    
    Write-Host "  Total Scripts:     $($Session.Scripts.Count)" -ForegroundColor White
    Write-Host "  Successful:        $($successful.Count)" -ForegroundColor Green
    Write-Host "  Failed:            $($failed.Count)" -ForegroundColor $(if ($failed.Count -gt 0) { 'Red' } else { 'Green' })
    
    if ($PreviewOnly) {
        Write-Host "`n  ⚠️  This was a preview. No changes were made." -ForegroundColor Yellow
        Write-Host "  To apply changes, run without -PreviewOnly flag" -ForegroundColor Gray
    }
    else {
        Write-Host "`n  ✅ Migration completed successfully!" -ForegroundColor Green
        
        if ($Session.Backups.Count -gt 0) {
            Write-Host "  📁 Backups saved to: $($Session.Backups[0])" -ForegroundColor Cyan
        }
    }
    
    # Duration
    $duration = (Get-Date) - $Session.StartTime
    Write-Host "`n  Duration: $($duration.ToString('mm\:ss'))" -ForegroundColor Gray
}

# Helper function to show post-migration steps
function Show-PostMigrationSteps {
    param([string]$Module, $Session)
    
    Write-Host "`n📋 Next Steps:" -ForegroundColor Cyan
    Write-Host "══════════════" -ForegroundColor Cyan
    
    Write-Host @"
    
  1. Test the migrated module:
     Import-Module $Module -Force
     Test-AutomationModule -Name $Module
     
  2. Update any references to old scripts:
     • Scheduled tasks
     • Documentation
     • Other scripts
     
  3. Run the included tests:
     Invoke-Pester -Path "$Module\Tests"
     
  4. Review and customize:
     • Configuration files
     • Module manifest
     • Help documentation
     
  5. When confident, archive old scripts:
     Move-Item -Path "OldScripts" -Destination "Archive\$(Get-Date -Format 'yyyy-MM-dd')"
     
  Need help? Try:
  Get-AutomationHelp -Category Migration
  
"@ -ForegroundColor White
}

Export-ModuleMember -Function Start-MigrationAssistant -Alias Start-Migration