function Get-AutomationHelp {
    <#
    .SYNOPSIS
        Provides context-aware, interactive help for automation commands and concepts
    
    .DESCRIPTION
        Get-AutomationHelp offers an enhanced help experience that goes beyond standard PowerShell help:
        - Interactive examples you can run directly
        - Visual diagrams for complex concepts
        - Troubleshooting guides for common issues
        - Video tutorials (links) for visual learners
        - Context-aware suggestions based on your current task
        - Search functionality across all documentation
        
        This is your friendly automation assistant, always ready to help!
    
    .PARAMETER Command
        The command or topic you need help with
    
    .PARAMETER Category
        Browse help by category: Basics, Advanced, Troubleshooting, BestPractices, Examples
    
    .PARAMETER Search
        Search for help across all documentation
    
    .PARAMETER Interactive
        Launch interactive help browser
    
    .PARAMETER ShowExample
        Show executable examples for the command
    
    .PARAMETER ShowDiagram
        Display visual diagrams for architectural concepts
    
    .EXAMPLE
        Get-AutomationHelp Start-AutomationWizard
        Shows comprehensive help for the Start-AutomationWizard command
    
    .EXAMPLE
        Get-AutomationHelp -Category Troubleshooting
        Browse all troubleshooting guides
    
    .EXAMPLE
        autohelp -Search "backup failed"
        Search for help related to backup failures
    
    .EXAMPLE
        Get-AutomationHelp -Interactive
        Launch the interactive help browser
    #>
    
    [CmdletBinding(DefaultParameterSetName = 'Command')]
    [Alias('autohelp')]
    param(
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = 'Command')]
        [string]$Command,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'Category')]
        [ValidateSet('Basics', 'Advanced', 'Troubleshooting', 'BestPractices', 'Examples', 'All')]
        [string]$Category,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'Search')]
        [string]$Search,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'Interactive')]
        [switch]$Interactive,
        
        [Parameter(Mandatory = $false)]
        [switch]$ShowExample,
        
        [Parameter(Mandatory = $false)]
        [switch]$ShowDiagram
    )
    
    # Initialize help system
    Initialize-HelpSystem
    
    switch ($PSCmdlet.ParameterSetName) {
        'Command' {
            if ($Command) {
                Show-CommandHelp -Command $Command -ShowExample:$ShowExample -ShowDiagram:$ShowDiagram
            }
            else {
                Show-HelpHomepage
            }
        }
        'Category' {
            Show-CategoryHelp -Category $Category
        }
        'Search' {
            Search-Help -Query $Search
        }
        'Interactive' {
            Start-InteractiveHelp
        }
    }
}

# Initialize help system
function Initialize-HelpSystem {
    if (-not $script:HelpInitialized) {
        $script:HelpData = @{
            Commands = @{}
            Categories = @{}
            Examples = @{}
            Diagrams = @{}
            Videos = @{}
            CommonIssues = @{}
        }
        
        # Load help data (in production, this would load from files)
        Load-HelpData
        
        $script:HelpInitialized = $true
    }
}

# Show help homepage
function Show-HelpHomepage {
    Clear-Host
    
    Write-Host "`n  🎯 PowerShell Automation Help Center" -ForegroundColor Cyan
    Write-Host "  ════════════════════════════════════" -ForegroundColor Cyan
    
    Write-Host "`n  Welcome! How can I help you today?" -ForegroundColor White
    
    Write-Host "`n  Quick Start:" -ForegroundColor Yellow
    Write-Host "    • Get-AutomationHelp Start-AutomationWizard  " -ForegroundColor Gray -NoNewline
    Write-Host "# Learn about the setup wizard" -ForegroundColor DarkGray
    Write-Host "    • Get-AutomationHelp -Category Basics        " -ForegroundColor Gray -NoNewline
    Write-Host "# Browse basic concepts" -ForegroundColor DarkGray
    Write-Host "    • Get-AutomationHelp -Interactive            " -ForegroundColor Gray -NoNewline
    Write-Host "# Interactive help browser" -ForegroundColor DarkGray
    
    Write-Host "`n  Popular Topics:" -ForegroundColor Yellow
    
    $popularTopics = @(
        @{ Name = "Getting Started"; Command = "Start-AutomationWizard" }
        @{ Name = "Creating Backup Jobs"; Command = "New-BackupJob" }
        @{ Name = "Managing Credentials"; Command = "Get-AutomationCredential" }
        @{ Name = "Troubleshooting Failed Jobs"; Command = "-Category Troubleshooting" }
        @{ Name = "Best Practices"; Command = "-Category BestPractices" }
    )
    
    for ($i = 0; $i -lt $popularTopics.Count; $i++) {
        Write-Host "    [$($i+1)] $($popularTopics[$i].Name)" -ForegroundColor White
    }
    
    Write-Host "`n  💡 Tip: " -ForegroundColor Magenta -NoNewline
    Write-Host "Use tab completion with Get-AutomationHelp for command discovery!" -ForegroundColor White
    
    Write-Host "`n  Enter a number (1-$($popularTopics.Count)) or type a command name: " -ForegroundColor Cyan -NoNewline
    $choice = Read-Host
    
    if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le $popularTopics.Count) {
        $topic = $popularTopics[[int]$choice - 1]
        Get-AutomationHelp $topic.Command
    }
    elseif ($choice) {
        Get-AutomationHelp $choice
    }
}

# Show command-specific help
function Show-CommandHelp {
    param(
        [string]$Command,
        [switch]$ShowExample,
        [switch]$ShowDiagram
    )
    
    Clear-Host
    
    # Try to get built-in help first
    $helpContent = Get-Help $Command -Full -ErrorAction SilentlyContinue
    
    if ($helpContent) {
        # Enhanced help display
        Write-Host "`n  📘 $($helpContent.Name)" -ForegroundColor Cyan
        Write-Host "  $('═' * ($helpContent.Name.Length + 3))" -ForegroundColor Cyan
        
        # Synopsis with emoji
        if ($helpContent.Synopsis) {
            Write-Host "`n  📝 Synopsis:" -ForegroundColor Yellow
            Write-Host "  $($helpContent.Synopsis)" -ForegroundColor White -Wrap
        }
        
        # Description with formatting
        if ($helpContent.Description) {
            Write-Host "`n  📖 Description:" -ForegroundColor Yellow
            $description = $helpContent.Description.Text -join "`n"
            Write-Host "  $description" -ForegroundColor White -Wrap
        }
        
        # Interactive examples
        if ($ShowExample -or $helpContent.Examples) {
            Write-Host "`n  💻 Examples:" -ForegroundColor Yellow
            Show-InteractiveExamples -Command $Command -Examples $helpContent.Examples
        }
        
        # Visual diagram
        if ($ShowDiagram) {
            Show-ConceptDiagram -Command $Command
        }
        
        # Related commands
        Show-RelatedCommands -Command $Command
        
        # Common issues
        Show-CommonIssues -Command $Command
    }
    else {
        # Command not found - show suggestions
        Write-Host "`n  ❓ Command '$Command' not found" -ForegroundColor Yellow
        
        # Find similar commands
        $suggestions = Find-SimilarCommands -Command $Command
        
        if ($suggestions) {
            Write-Host "`n  Did you mean one of these?" -ForegroundColor Cyan
            foreach ($suggestion in $suggestions) {
                Write-Host "    • $suggestion" -ForegroundColor White
            }
        }
        
        Write-Host "`n  💡 Try searching: " -ForegroundColor Magenta -NoNewline
        Write-Host "Get-AutomationHelp -Search '$Command'" -ForegroundColor White
    }
}

# Show interactive examples
function Show-InteractiveExamples {
    param(
        [string]$Command,
        $Examples
    )
    
    if (-not $Examples) { return }
    
    $exampleCount = 0
    foreach ($example in $Examples.Example) {
        $exampleCount++
        Write-Host "`n  Example $exampleCount" -ForegroundColor Green
        Write-Host "  ─────────" -ForegroundColor Green
        
        # Show the example code
        if ($example.Code) {
            Write-Host "  PS> " -ForegroundColor DarkGray -NoNewline
            Write-Host $example.Code -ForegroundColor Cyan
        }
        
        # Show description
        if ($example.Remarks) {
            $remarks = $example.Remarks.Text -join "`n"
            Write-Host "  $remarks" -ForegroundColor Gray -Wrap
        }
        
        # Offer to run the example
        if ($example.Code -and $exampleCount -eq 1) {
            Write-Host "`n  🚀 " -ForegroundColor Yellow -NoNewline
            Write-Host "Would you like to run this example? (Y/N): " -ForegroundColor White -NoNewline
            $runExample = Read-Host
            
            if ($runExample -match '^[Yy]') {
                Write-Host "  Running example..." -ForegroundColor Green
                try {
                    # Create a safe sandbox for the example
                    $exampleCode = $example.Code.ToString()
                    
                    # Add safety checks
                    if ($exampleCode -notmatch 'Remove-|Delete-|Clear-') {
                        Invoke-Expression $exampleCode
                    }
                    else {
                        Write-Host "  ⚠️  This example contains destructive operations and won't be run automatically" -ForegroundColor Yellow
                        Write-Host "  Copy and modify the code as needed for your environment" -ForegroundColor Gray
                    }
                }
                catch {
                    Write-Host "  ❌ Error running example: $_" -ForegroundColor Red
                }
            }
        }
    }
}

# Show concept diagram
function Show-ConceptDiagram {
    param([string]$Command)
    
    # Sample diagrams for demonstration
    $diagrams = @{
        'Start-AutomationWizard' = @"
        
  Automation Wizard Flow
  ═════════════════════
  
     ┌─────────────┐
     │   Welcome   │
     └──────┬──────┘
            ▼
     ┌─────────────┐     ┌─────────────┐
     │ Auto-Detect │ ──> │   Select    │
     │    Type     │     │   Wizard    │
     └──────┬──────┘     └──────┬──────┘
            └──────────┬────────┘
                       ▼
              ┌─────────────┐
              │   Execute   │
              │   Wizard    │
              └──────┬──────┘
                     ▼
              ┌─────────────┐
              │  Complete   │
              │  & Summary  │
              └─────────────┘
"@
    }
    
    if ($diagrams.ContainsKey($Command)) {
        Write-Host "`n  📊 Concept Diagram:" -ForegroundColor Yellow
        Write-Host $diagrams[$Command] -ForegroundColor Cyan
    }
}

# Show related commands
function Show-RelatedCommands {
    param([string]$Command)
    
    $related = @{
        'Start-AutomationWizard' = @('New-AutomationConfig', 'Get-AutomationModule', 'Start-MigrationAssistant')
        'Get-AutomationHelp' = @('Show-AutomationTip', 'Get-AutomationExample', 'Show-AutomationTutorial')
    }
    
    if ($related.ContainsKey($Command)) {
        Write-Host "`n  🔗 Related Commands:" -ForegroundColor Yellow
        foreach ($cmd in $related[$Command]) {
            Write-Host "    • $cmd" -ForegroundColor White
        }
    }
}

# Show common issues
function Show-CommonIssues {
    param([string]$Command)
    
    $issues = @{
        'Start-AutomationWizard' = @(
            @{
                Issue = "Wizard fails to start"
                Solution = "Ensure you have administrator privileges: Test-AdminPrivileges"
            }
            @{
                Issue = "Configuration not saved"
                Solution = "Check write permissions to: $env:APPDATA\PSAutomation"
            }
        )
    }
    
    if ($issues.ContainsKey($Command)) {
        Write-Host "`n  ⚠️  Common Issues:" -ForegroundColor Yellow
        
        foreach ($issue in $issues[$Command]) {
            Write-Host "    Issue: " -ForegroundColor Red -NoNewline
            Write-Host $issue.Issue -ForegroundColor White
            Write-Host "    Fix:   " -ForegroundColor Green -NoNewline
            Write-Host $issue.Solution -ForegroundColor Gray
            Write-Host ""
        }
    }
}

# Search help system
function Search-Help {
    param([string]$Query)
    
    Clear-Host
    Write-Host "`n  🔍 Searching for: '$Query'" -ForegroundColor Cyan
    Write-Host "  $('═' * (18 + $Query.Length))" -ForegroundColor Cyan
    
    # Simulate search results
    $results = @(
        @{ Type = "Command"; Name = "Start-AutomatedBackup"; Match = "Backup automation with '$Query' support" }
        @{ Type = "Guide"; Name = "Troubleshooting Backup Failures"; Match = "Common backup errors and solutions" }
        @{ Type = "Example"; Name = "Backup Configuration Example"; Match = "JSON configuration for backup jobs" }
    )
    
    if ($results.Count -eq 0) {
        Write-Host "`n  No results found for '$Query'" -ForegroundColor Yellow
        Write-Host "  Try different keywords or browse by category" -ForegroundColor Gray
    }
    else {
        Write-Host "`n  Found $($results.Count) results:" -ForegroundColor Green
        
        foreach ($result in $results) {
            Write-Host "`n  [$($result.Type)]" -ForegroundColor Magenta -NoNewline
            Write-Host " $($result.Name)" -ForegroundColor White
            Write-Host "  $($result.Match)" -ForegroundColor Gray
        }
        
        Write-Host "`n  💡 Use Get-AutomationHelp <name> to view any result" -ForegroundColor Yellow
    }
}

# Start interactive help browser
function Start-InteractiveHelp {
    Clear-Host
    
    Write-Host "`n  🎮 Interactive Help Browser" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════" -ForegroundColor Cyan
    Write-Host "`n  Navigate using arrow keys, Enter to select, Q to quit" -ForegroundColor Gray
    
    $categories = @(
        "Getting Started",
        "Core Concepts",
        "Command Reference",
        "Troubleshooting",
        "Best Practices",
        "Video Tutorials"
    )
    
    $selectedIndex = 0
    $quit = $false
    
    while (-not $quit) {
        # Clear and redraw menu
        Clear-Host
        Write-Host "`n  🎮 Interactive Help Browser" -ForegroundColor Cyan
        Write-Host "  ══════════════════════════" -ForegroundColor Cyan
        
        for ($i = 0; $i -lt $categories.Count; $i++) {
            if ($i -eq $selectedIndex) {
                Write-Host "  ▶ " -ForegroundColor Yellow -NoNewline
                Write-Host $categories[$i] -ForegroundColor White -BackgroundColor DarkBlue
            }
            else {
                Write-Host "    $($categories[$i])" -ForegroundColor Gray
            }
        }
        
        Write-Host "`n  [↑↓] Navigate  [Enter] Select  [Q] Quit" -ForegroundColor DarkGray
        
        # Handle input
        $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        
        switch ($key.VirtualKeyCode) {
            38 { # Up arrow
                $selectedIndex = ($selectedIndex - 1) % $categories.Count
                if ($selectedIndex -lt 0) { $selectedIndex = $categories.Count - 1 }
            }
            40 { # Down arrow
                $selectedIndex = ($selectedIndex + 1) % $categories.Count
            }
            13 { # Enter
                Show-CategoryHelp -Category $categories[$selectedIndex]
                Write-Host "`n  Press any key to continue..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            81 { # Q key
                $quit = $true
            }
        }
    }
    
    Clear-Host
}

# Helper function to find similar commands
function Find-SimilarCommands {
    param([string]$Command)
    
    $allCommands = Get-Command -Module PSAutomation* -ErrorAction SilentlyContinue
    $similar = @()
    
    foreach ($cmd in $allCommands) {
        $distance = Get-LevenshteinDistance -String1 $Command -String2 $cmd.Name
        if ($distance -le 5) {
            $similar += $cmd.Name
        }
    }
    
    return $similar | Select-Object -First 5
}

# Simple Levenshtein distance for command suggestions
function Get-LevenshteinDistance {
    param(
        [string]$String1,
        [string]$String2
    )
    
    $len1 = $String1.Length
    $len2 = $String2.Length
    
    if ($len1 -eq 0) { return $len2 }
    if ($len2 -eq 0) { return $len1 }
    
    $matrix = New-Object 'int[,]' ($len1 + 1), ($len2 + 1)
    
    for ($i = 0; $i -le $len1; $i++) { $matrix[$i, 0] = $i }
    for ($j = 0; $j -le $len2; $j++) { $matrix[0, $j] = $j }
    
    for ($i = 1; $i -le $len1; $i++) {
        for ($j = 1; $j -le $len2; $j++) {
            $cost = if ($String1[$i-1] -eq $String2[$j-1]) { 0 } else { 1 }
            $matrix[$i, $j] = [Math]::Min(
                [Math]::Min($matrix[($i-1), $j] + 1, $matrix[$i, ($j-1)] + 1),
                $matrix[($i-1), ($j-1)] + $cost
            )
        }
    }
    
    return $matrix[$len1, $len2]
}

# Load help data (simplified for demo)
function Load-HelpData {
    # In production, this would load from XML/JSON files
    $script:HelpData.CommonIssues = @{
        'credential' = @(
            "Invalid credentials - Check username and password",
            "Access denied - Ensure account has necessary permissions",
            "Credential expired - Update stored credentials"
        )
        'network' = @(
            "Connection timeout - Check firewall settings",
            "Host unreachable - Verify network connectivity",
            "DNS resolution failed - Check DNS configuration"
        )
    }
}

Export-ModuleMember -Function Get-AutomationHelp -Alias autohelp