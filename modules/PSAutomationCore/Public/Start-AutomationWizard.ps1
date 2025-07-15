function Start-AutomationWizard {
    <#
    .SYNOPSIS
        Launches an interactive wizard to help users configure and run automation tasks
    
    .DESCRIPTION
        The Start-AutomationWizard provides a friendly, guided experience for:
        - First-time setup and configuration
        - Creating new automation jobs
        - Troubleshooting existing configurations
        - Learning about available features
        
        The wizard adapts based on user expertise level and provides contextual help throughout.
    
    .PARAMETER WizardType
        The type of wizard to launch:
        - Setup: Initial platform configuration
        - NewJob: Create a new automation job
        - Migration: Migrate from legacy scripts
        - Troubleshoot: Diagnose and fix issues
        - Learn: Interactive tutorial mode
    
    .PARAMETER SkipIntro
        Skip the welcome screen and introduction
    
    .PARAMETER ExpertMode
        Use expert mode with fewer prompts and more advanced options
    
    .EXAMPLE
        Start-AutomationWizard
        Launches the wizard in interactive mode, detecting what the user needs
    
    .EXAMPLE
        Start-AutomationWizard -WizardType Setup
        Launches the setup wizard for first-time configuration
    
    .EXAMPLE
        autowiz -WizardType NewJob
        Uses the alias to quickly create a new automation job
    
    .NOTES
        This wizard is designed to make automation accessible to all skill levels
    #>
    
    [CmdletBinding()]
    [Alias('autowiz')]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('Setup', 'NewJob', 'Migration', 'Troubleshoot', 'Learn', 'Auto')]
        [string]$WizardType = 'Auto',
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipIntro,
        
        [Parameter(Mandatory = $false)]
        [switch]$ExpertMode
    )
    
    begin {
        # Initialize wizard state
        $wizardState = @{
            CurrentStep = 1
            TotalSteps = 0
            Responses = @{}
            WizardType = $WizardType
            ExpertMode = $ExpertMode.IsPresent
            StartTime = Get-Date
        }
        
        # Set up console for better interaction
        $originalTitle = $Host.UI.RawUI.WindowTitle
        $Host.UI.RawUI.WindowTitle = "PowerShell Automation Wizard"
    }
    
    process {
        try {
            # Show welcome screen
            if (-not $SkipIntro) {
                Show-WizardWelcome -WizardType $WizardType
            }
            
            # Auto-detect wizard type if needed
            if ($WizardType -eq 'Auto') {
                $WizardType = Get-RecommendedWizardType
                $wizardState.WizardType = $WizardType
            }
            
            # Show wizard overview
            Show-WizardOverview -WizardType $WizardType -ExpertMode $ExpertMode
            
            # Execute the appropriate wizard
            switch ($WizardType) {
                'Setup' {
                    $result = Start-SetupWizard -State $wizardState
                }
                'NewJob' {
                    $result = Start-NewJobWizard -State $wizardState
                }
                'Migration' {
                    $result = Start-MigrationWizard -State $wizardState
                }
                'Troubleshoot' {
                    $result = Start-TroubleshootWizard -State $wizardState
                }
                'Learn' {
                    $result = Start-LearningWizard -State $wizardState
                }
            }
            
            # Show completion summary
            Show-WizardCompletion -Result $result -State $wizardState
            
            # Offer next steps
            Show-NextSteps -WizardType $WizardType -Result $result
            
            return $result
        }
        catch {
            Show-WizardError -ErrorRecord $_ -State $wizardState
            throw
        }
    }
    
    end {
        # Restore console state
        $Host.UI.RawUI.WindowTitle = $originalTitle
        
        # Log wizard completion
        Write-AutomationLog -Message "Wizard completed: $WizardType" -Level Info -Metadata @{
            Duration = (Get-Date) - $wizardState.StartTime
            ExpertMode = $ExpertMode.IsPresent
        }
    }
}

# Helper function to show wizard welcome
function Show-WizardWelcome {
    param([string]$WizardType)
    
    Clear-Host
    
    Write-Host "`n" -NoNewline
    Write-Host "  ╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║                                                           ║" -ForegroundColor Cyan
    Write-Host "  ║      Welcome to PowerShell Automation Platform            ║" -ForegroundColor Cyan
    Write-Host "  ║                                                           ║" -ForegroundColor Cyan
    Write-Host "  ║         Making Enterprise Automation Delightful           ║" -ForegroundColor Cyan
    Write-Host "  ║                                                           ║" -ForegroundColor Cyan
    Write-Host "  ╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host "`n"
    
    # Show contextual welcome message
    $welcomeMessages = @{
        'Auto' = "I'll help you get started with the right wizard for your needs."
        'Setup' = "Let's set up your automation platform together!"
        'NewJob' = "Ready to create a new automation job? I'll guide you through it."
        'Migration' = "Moving from legacy scripts? I'll make it smooth and easy."
        'Troubleshoot' = "Having issues? Let's figure out what's wrong together."
        'Learn' = "Welcome to the interactive learning experience!"
    }
    
    Write-Host "  $($welcomeMessages[$WizardType])" -ForegroundColor White
    Write-Host "`n"
    
    if ($WizardType -eq 'Auto') {
        Write-Host "  Press any key to continue..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    else {
        Start-Sleep -Seconds 2
    }
}

# Helper function to detect recommended wizard type
function Get-RecommendedWizardType {
    Write-Host "`n  Let me help you choose the right wizard..." -ForegroundColor Cyan
    Write-Host "  Checking your environment..." -ForegroundColor Gray
    
    # Show progress animation
    $animation = @('⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏')
    $i = 0
    
    $checks = @(
        { Test-Path $script:AutomationConfig.ConfigPath }
        { Get-AutomationModule -ListAvailable | Where-Object { $_.Version -ge '2.0.0' } }
        { Test-Path (Join-Path $PSScriptRoot '..\..\scripts\*.ps1') }
    )
    
    foreach ($check in $checks) {
        Write-Host "`r  $($animation[$i % $animation.Count]) Analyzing..." -NoNewline -ForegroundColor Yellow
        Start-Sleep -Milliseconds 300
        $null = & $check
        $i++
    }
    
    Write-Host "`r  ✓ Analysis complete!                    " -ForegroundColor Green
    
    # Determine recommendation
    if (-not (Test-Path $script:AutomationConfig.ConfigPath)) {
        Write-Host "`n  Recommendation: First-time setup needed" -ForegroundColor Yellow
        return 'Setup'
    }
    elseif (Test-Path (Join-Path $PSScriptRoot '..\..\scripts\*.ps1')) {
        Write-Host "`n  Recommendation: Migrate existing scripts to modules" -ForegroundColor Yellow
        return 'Migration'
    }
    else {
        Write-Host "`n  What would you like to do?" -ForegroundColor Cyan
        
        $options = @(
            "Create a new automation job"
            "Troubleshoot an issue"
            "Learn about the platform"
            "Initial setup"
        )
        
        for ($i = 0; $i -lt $options.Count; $i++) {
            Write-Host "  [$($i+1)] $($options[$i])" -ForegroundColor White
        }
        
        do {
            Write-Host "`n  Enter your choice (1-$($options.Count)): " -NoNewline -ForegroundColor Cyan
            $choice = Read-Host
        } while ($choice -notmatch '^[1-4]$')
        
        return @('NewJob', 'Troubleshoot', 'Learn', 'Setup')[[int]$choice - 1]
    }
}

# Helper function to show wizard overview
function Show-WizardOverview {
    param(
        [string]$WizardType,
        [bool]$ExpertMode
    )
    
    Clear-Host
    
    $overviews = @{
        'Setup' = @{
            Title = "Initial Setup Wizard"
            Steps = @(
                "Environment verification"
                "Core module configuration"
                "Credential vault setup"
                "Plugin discovery"
                "First automation job"
            )
            Duration = "5-10 minutes"
        }
        'NewJob' = @{
            Title = "New Automation Job Wizard"
            Steps = @(
                "Job type selection"
                "Target configuration"
                "Schedule setup"
                "Notification preferences"
                "Testing and validation"
            )
            Duration = "3-5 minutes"
        }
        'Migration' = @{
            Title = "Script Migration Wizard"
            Steps = @(
                "Legacy script discovery"
                "Dependency analysis"
                "Module structure creation"
                "Code transformation"
                "Testing and validation"
            )
            Duration = "10-15 minutes per script"
        }
    }
    
    $overview = $overviews[$WizardType]
    
    Write-Host "`n  $($overview.Title)" -ForegroundColor Cyan
    Write-Host "  $('=' * $overview.Title.Length)" -ForegroundColor Cyan
    Write-Host "`n  This wizard will guide you through:" -ForegroundColor White
    
    for ($i = 0; $i -lt $overview.Steps.Count; $i++) {
        Write-Host "    $($i+1). $($overview.Steps[$i])" -ForegroundColor Gray
    }
    
    Write-Host "`n  Estimated time: $($overview.Duration)" -ForegroundColor Yellow
    
    if ($ExpertMode) {
        Write-Host "  Mode: Expert (fewer prompts)" -ForegroundColor Magenta
    }
    
    Write-Host "`n  Ready to begin? (Y/N): " -NoNewline -ForegroundColor Cyan
    $response = Read-Host
    
    if ($response -notmatch '^[Yy]') {
        Write-Host "`n  Wizard cancelled. Run 'Start-AutomationWizard' when you're ready!" -ForegroundColor Yellow
        return $false
    }
    
    return $true
}

# Export the function
Export-ModuleMember -Function Start-AutomationWizard -Alias autowiz