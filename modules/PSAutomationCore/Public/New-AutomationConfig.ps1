function New-AutomationConfig {
    <#
    .SYNOPSIS
        Creates a new automation configuration with an interactive, guided experience
    
    .DESCRIPTION
        New-AutomationConfig provides a delightful way to create configurations:
        - Interactive prompts with validation and suggestions
        - Template library for common scenarios
        - Real-time validation with helpful error messages
        - Preview mode to see configuration before saving
        - Import from existing configurations
        - Schema validation for correctness
        
        This function makes configuration creation easy and error-free!
    
    .PARAMETER Name
        Name for the configuration
    
    .PARAMETER Type
        Type of configuration: Job, Module, Environment, Credential, Global
    
    .PARAMETER Template
        Use a predefined template: BackupJob, ADSync, Monitoring, Security, Custom
    
    .PARAMETER Interactive
        Use interactive mode with prompts (default: true)
    
    .PARAMETER FromFile
        Import configuration from an existing file
    
    .PARAMETER Schema
        Path to JSON schema for validation
    
    .PARAMETER Preview
        Preview the configuration without saving
    
    .EXAMPLE
        New-AutomationConfig -Name "DailyBackup" -Type Job -Template BackupJob
        Creates a new backup job configuration using the template
    
    .EXAMPLE
        New-AutomationConfig -Interactive
        Launches interactive configuration creator
    
    .EXAMPLE
        New-AutomationConfig -FromFile "C:\old-config.json" -Name "UpdatedConfig"
        Creates new configuration based on existing file
    #>
    
    [CmdletBinding(DefaultParameterSetName = 'Interactive')]
    [Alias('autoconfig')]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$Name,
        
        [Parameter(Mandatory = $false, ParameterSetName = 'Direct')]
        [ValidateSet('Job', 'Module', 'Environment', 'Credential', 'Global')]
        [string]$Type = 'Job',
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('BackupJob', 'ADSync', 'Monitoring', 'Security', 'Custom')]
        [string]$Template = 'Custom',
        
        [Parameter(Mandatory = $false, ParameterSetName = 'Interactive')]
        [switch]$Interactive = $true,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'Import')]
        [string]$FromFile,
        
        [Parameter(Mandatory = $false)]
        [string]$Schema,
        
        [Parameter(Mandatory = $false)]
        [switch]$Preview
    )
    
    begin {
        $configData = @{
            Name = $Name
            Type = $Type
            CreatedDate = Get-Date
            CreatedBy = $env:USERNAME
            Version = '1.0.0'
            Settings = @{}
        }
    }
    
    process {
        try {
            # Import from file if specified
            if ($FromFile) {
                $configData = Import-Configuration -Path $FromFile -Name $Name
            }
            elseif ($Interactive -or -not $Name) {
                # Interactive configuration creation
                $configData = Start-ConfigurationWizard -InitialData $configData -Template $Template
            }
            else {
                # Template-based creation
                $configData = Apply-ConfigurationTemplate -Data $configData -Template $Template -Type $Type
            }
            
            # Validate configuration
            if ($Schema) {
                $validation = Test-ConfigurationSchema -Config $configData -Schema $Schema
                if (-not $validation.IsValid) {
                    Show-ValidationErrors -Errors $validation.Errors
                    throw "Configuration validation failed"
                }
            }
            
            # Preview mode
            if ($Preview) {
                Show-ConfigurationPreview -Config $configData
                
                Write-Host "`n  Save this configuration? (Y/N): " -ForegroundColor Cyan -NoNewline
                $save = Read-Host
                
                if ($save -notmatch '^[Yy]') {
                    Write-Host "  Configuration not saved." -ForegroundColor Yellow
                    return $null
                }
            }
            
            # Save configuration
            $savedPath = Save-Configuration -Config $configData
            
            # Show success message with next steps
            Show-ConfigurationSuccess -Config $configData -Path $savedPath
            
            return $configData
        }
        catch {
            Write-Error "Failed to create configuration: $_"
            throw
        }
    }
}

# Start configuration wizard
function Start-ConfigurationWizard {
    param(
        [hashtable]$InitialData,
        [string]$Template
    )
    
    Clear-Host
    
    Write-Host "`n  🔧 Configuration Wizard" -ForegroundColor Cyan
    Write-Host "  ═════════════════════" -ForegroundColor Cyan
    Write-Host "`n  Let's create your configuration step by step!" -ForegroundColor White
    
    # Step 1: Basic Information
    if (-not $InitialData.Name) {
        Write-Host "`n  Step 1: Basic Information" -ForegroundColor Yellow
        Write-Host "  ─────────────────────────" -ForegroundColor Yellow
        
        do {
            Write-Host "  Configuration name: " -ForegroundColor Cyan -NoNewline
            $name = Read-Host
        } while ([string]::IsNullOrWhiteSpace($name))
        
        $InitialData.Name = $name
    }
    
    # Step 2: Configuration Type
    Write-Host "`n  Step 2: Configuration Type" -ForegroundColor Yellow
    Write-Host "  ──────────────────────────" -ForegroundColor Yellow
    Write-Host "  What type of configuration is this?" -ForegroundColor White
    
    $types = @(
        @{ Name = "Job"; Description = "Automation job (backup, sync, etc.)" }
        @{ Name = "Module"; Description = "Module settings and preferences" }
        @{ Name = "Environment"; Description = "Environment-specific settings" }
        @{ Name = "Credential"; Description = "Credential and authentication" }
        @{ Name = "Global"; Description = "Platform-wide settings" }
    )
    
    for ($i = 0; $i -lt $types.Count; $i++) {
        Write-Host "  [$($i+1)] $($types[$i].Name) - " -ForegroundColor White -NoNewline
        Write-Host $types[$i].Description -ForegroundColor Gray
    }
    
    do {
        Write-Host "`n  Select type (1-$($types.Count)): " -ForegroundColor Cyan -NoNewline
        $typeChoice = Read-Host
    } while ($typeChoice -notmatch '^[1-5]$')
    
    $InitialData.Type = $types[[int]$typeChoice - 1].Name
    
    # Step 3: Template Selection
    if ($Template -eq 'Custom') {
        Write-Host "`n  Step 3: Template Selection" -ForegroundColor Yellow
        Write-Host "  ──────────────────────────" -ForegroundColor Yellow
        Write-Host "  Would you like to use a template?" -ForegroundColor White
        
        $templates = Get-AvailableTemplates -Type $InitialData.Type
        
        if ($templates.Count -gt 0) {
            Write-Host "  [0] Start from scratch" -ForegroundColor White
            
            for ($i = 0; $i -lt $templates.Count; $i++) {
                Write-Host "  [$($i+1)] $($templates[$i].Name) - " -ForegroundColor White -NoNewline
                Write-Host $templates[$i].Description -ForegroundColor Gray
            }
            
            Write-Host "`n  Select template (0-$($templates.Count)): " -ForegroundColor Cyan -NoNewline
            $templateChoice = Read-Host
            
            if ($templateChoice -ne '0') {
                $Template = $templates[[int]$templateChoice - 1].Name
            }
        }
    }
    
    # Step 4: Configuration Details
    Write-Host "`n  Step 4: Configuration Details" -ForegroundColor Yellow
    Write-Host "  ─────────────────────────────" -ForegroundColor Yellow
    
    # Apply template or gather custom settings
    if ($Template -ne 'Custom') {
        $InitialData = Apply-ConfigurationTemplate -Data $InitialData -Template $Template -Type $InitialData.Type
        
        Write-Host "  Template '$Template' applied! Let's customize it..." -ForegroundColor Green
        
        # Allow customization of template values
        $InitialData = Customize-TemplateValues -Config $InitialData
    }
    else {
        # Gather settings based on type
        $InitialData.Settings = Get-ConfigurationSettings -Type $InitialData.Type
    }
    
    # Step 5: Review and Confirm
    Write-Host "`n  Step 5: Review Configuration" -ForegroundColor Yellow
    Write-Host "  ────────────────────────────" -ForegroundColor Yellow
    
    Show-ConfigurationPreview -Config $InitialData
    
    Write-Host "`n  Is this correct? (Y/N): " -ForegroundColor Cyan -NoNewline
    $confirm = Read-Host
    
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "  Let's make changes..." -ForegroundColor Yellow
        $InitialData = Edit-Configuration -Config $InitialData
    }
    
    return $InitialData
}

# Apply configuration template
function Apply-ConfigurationTemplate {
    param(
        [hashtable]$Data,
        [string]$Template,
        [string]$Type
    )
    
    $templates = @{
        'BackupJob' = @{
            Settings = @{
                Schedule = @{
                    Type = 'Daily'
                    Time = '02:00:00'
                    DaysOfWeek = @('Monday','Tuesday','Wednesday','Thursday','Friday')
                }
                Source = @{
                    Paths = @('C:\Data', 'C:\Users\{username}\Documents')
                    ExcludePatterns = @('*.tmp', '*.log', '~*')
                }
                Destination = @{
                    Path = '\\backup-server\backups\{computername}'
                    CreateTimestampFolder = $true
                }
                Options = @{
                    Compression = $true
                    CompressionLevel = 'Optimal'
                    Encryption = $false
                    VerifyBackup = $true
                    RetentionDays = 30
                }
                Notifications = @{
                    OnSuccess = $true
                    OnFailure = $true
                    Recipients = @('{email}')
                }
            }
        }
        'ADSync' = @{
            Settings = @{
                Source = @{
                    Domain = '{domain}'
                    SearchBase = 'OU=Users,DC=company,DC=com'
                    Filter = '(&(objectCategory=person)(objectClass=user))'
                }
                Target = @{
                    System = 'AzureAD'
                    TenantId = '{tenantId}'
                }
                Mapping = @{
                    AttributeMap = @{
                        'sAMAccountName' = 'userPrincipalName'
                        'mail' = 'mail'
                        'displayName' = 'displayName'
                    }
                }
                Schedule = @{
                    Type = 'Interval'
                    IntervalMinutes = 30
                }
            }
        }
    }
    
    if ($templates.ContainsKey($Template)) {
        $Data.Settings = $templates[$Template].Settings
        $Data.Template = $Template
    }
    
    return $Data
}

# Get available templates
function Get-AvailableTemplates {
    param([string]$Type)
    
    $allTemplates = @(
        @{ Name = 'BackupJob'; Type = 'Job'; Description = 'File and folder backup configuration' }
        @{ Name = 'ADSync'; Type = 'Job'; Description = 'Active Directory synchronization' }
        @{ Name = 'Monitoring'; Type = 'Job'; Description = 'System monitoring and alerting' }
        @{ Name = 'Security'; Type = 'Global'; Description = 'Security and compliance settings' }
    )
    
    return $allTemplates | Where-Object { $_.Type -eq $Type -or $Type -eq 'Job' }
}

# Customize template values
function Customize-TemplateValues {
    param([hashtable]$Config)
    
    Write-Host "`n  The template contains placeholder values. Let's update them:" -ForegroundColor White
    
    # Find all placeholders in the configuration
    $placeholders = Find-Placeholders -Object $Config.Settings
    
    if ($placeholders.Count -gt 0) {
        Write-Host "  Found $($placeholders.Count) values to customize:" -ForegroundColor Gray
        
        foreach ($placeholder in $placeholders) {
            $currentValue = Get-NestedProperty -Object $Config.Settings -Path $placeholder.Path
            
            Write-Host "`n  $($placeholder.Path):" -ForegroundColor Yellow
            Write-Host "  Current: " -ForegroundColor Gray -NoNewline
            Write-Host $currentValue -ForegroundColor DarkYellow
            
            # Provide smart suggestions based on placeholder
            $suggestion = Get-PlaceholderSuggestion -Placeholder $currentValue
            if ($suggestion) {
                Write-Host "  Suggested: " -ForegroundColor Gray -NoNewline
                Write-Host $suggestion -ForegroundColor Green
            }
            
            Write-Host "  New value (Enter to keep current): " -ForegroundColor Cyan -NoNewline
            $newValue = Read-Host
            
            if (-not [string]::IsNullOrWhiteSpace($newValue)) {
                Set-NestedProperty -Object $Config.Settings -Path $placeholder.Path -Value $newValue
            }
            elseif ($suggestion -and $currentValue -match '^\{.+\}$') {
                # Auto-apply suggestion for placeholder values
                Set-NestedProperty -Object $Config.Settings -Path $placeholder.Path -Value $suggestion
                Write-Host "  ✓ Applied suggested value" -ForegroundColor Green
            }
        }
    }
    
    return $Config
}

# Find placeholders in configuration
function Find-Placeholders {
    param($Object, [string]$Path = '')
    
    $placeholders = @()
    
    if ($Object -is [hashtable] -or $Object -is [System.Collections.IDictionary]) {
        foreach ($key in $Object.Keys) {
            $newPath = if ($Path) { "$Path.$key" } else { $key }
            $placeholders += Find-Placeholders -Object $Object[$key] -Path $newPath
        }
    }
    elseif ($Object -is [array]) {
        for ($i = 0; $i -lt $Object.Count; $i++) {
            $newPath = "$Path[$i]"
            $placeholders += Find-Placeholders -Object $Object[$i] -Path $newPath
        }
    }
    elseif ($Object -is [string] -and $Object -match '\{.+\}') {
        $placeholders += @{ Path = $Path; Value = $Object }
    }
    
    return $placeholders
}

# Get smart suggestions for placeholders
function Get-PlaceholderSuggestion {
    param([string]$Placeholder)
    
    $suggestions = @{
        '{username}' = $env:USERNAME
        '{computername}' = $env:COMPUTERNAME
        '{email}' = "$($env:USERNAME)@$($env:USERDNSDOMAIN)"
        '{domain}' = $env:USERDNSDOMAIN
        '{date}' = (Get-Date -Format 'yyyy-MM-dd')
        '{time}' = (Get-Date -Format 'HH:mm:ss')
    }
    
    if ($suggestions.ContainsKey($Placeholder)) {
        return $suggestions[$Placeholder]
    }
    
    return $null
}

# Show configuration preview
function Show-ConfigurationPreview {
    param([hashtable]$Config)
    
    Write-Host "`n  📋 Configuration Preview" -ForegroundColor Cyan
    Write-Host "  ════════════════════════" -ForegroundColor Cyan
    
    Write-Host "`n  Name:    " -ForegroundColor Gray -NoNewline
    Write-Host $Config.Name -ForegroundColor White
    
    Write-Host "  Type:    " -ForegroundColor Gray -NoNewline
    Write-Host $Config.Type -ForegroundColor White
    
    Write-Host "  Version: " -ForegroundColor Gray -NoNewline
    Write-Host $Config.Version -ForegroundColor White
    
    if ($Config.Template) {
        Write-Host "  Template:" -ForegroundColor Gray -NoNewline
        Write-Host " $($Config.Template)" -ForegroundColor Magenta
    }
    
    Write-Host "`n  Settings:" -ForegroundColor Yellow
    Show-NestedObject -Object $Config.Settings -Indent 2
}

# Display nested object structure
function Show-NestedObject {
    param(
        $Object,
        [int]$Indent = 0
    )
    
    $prefix = "  " * $Indent
    
    if ($Object -is [hashtable] -or $Object -is [System.Collections.IDictionary]) {
        foreach ($key in $Object.Keys) {
            Write-Host "$prefix$key" -ForegroundColor White -NoNewline
            Write-Host ": " -ForegroundColor Gray -NoNewline
            
            if ($Object[$key] -is [hashtable] -or $Object[$key] -is [array]) {
                Write-Host ""
                Show-NestedObject -Object $Object[$key] -Indent ($Indent + 1)
            }
            else {
                Write-Host $Object[$key] -ForegroundColor Cyan
            }
        }
    }
    elseif ($Object -is [array]) {
        for ($i = 0; $i -lt $Object.Count; $i++) {
            Write-Host "$prefix- " -ForegroundColor Gray -NoNewline
            
            if ($Object[$i] -is [hashtable] -or $Object[$i] -is [array]) {
                Write-Host ""
                Show-NestedObject -Object $Object[$i] -Indent ($Indent + 1)
            }
            else {
                Write-Host $Object[$i] -ForegroundColor Cyan
            }
        }
    }
}

# Save configuration
function Save-Configuration {
    param([hashtable]$Config)
    
    $configDir = Join-Path $env:APPDATA 'PSAutomation\Configurations'
    
    if (-not (Test-Path $configDir)) {
        New-Item -Path $configDir -ItemType Directory -Force | Out-Null
    }
    
    $filename = "$($Config.Name)-$($Config.Type).json"
    $filepath = Join-Path $configDir $filename
    
    # Check if file exists
    if (Test-Path $filepath) {
        Write-Host "`n  ⚠️  Configuration '$($Config.Name)' already exists!" -ForegroundColor Yellow
        Write-Host "  Overwrite? (Y/N): " -ForegroundColor Cyan -NoNewline
        $overwrite = Read-Host
        
        if ($overwrite -notmatch '^[Yy]') {
            # Generate unique name
            $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
            $filename = "$($Config.Name)-$($Config.Type)-$timestamp.json"
            $filepath = Join-Path $configDir $filename
        }
    }
    
    # Convert to JSON with formatting
    $json = $Config | ConvertTo-Json -Depth 10 -Compress:$false
    
    # Save file
    Set-Content -Path $filepath -Value $json -Encoding UTF8
    
    return $filepath
}

# Show success message
function Show-ConfigurationSuccess {
    param(
        [hashtable]$Config,
        [string]$Path
    )
    
    Write-Host "`n  ✅ Configuration created successfully!" -ForegroundColor Green
    Write-Host "  ════════════════════════════════════" -ForegroundColor Green
    
    Write-Host "`n  📁 Saved to: " -ForegroundColor Gray -NoNewline
    Write-Host $Path -ForegroundColor Cyan
    
    Write-Host "`n  Next steps:" -ForegroundColor Yellow
    
    switch ($Config.Type) {
        'Job' {
            Write-Host "  1. Test your configuration: " -ForegroundColor Gray -NoNewline
            Write-Host "Test-AutomationConfig -Name '$($Config.Name)'" -ForegroundColor White
            
            Write-Host "  2. Run the job: " -ForegroundColor Gray -NoNewline
            Write-Host "Start-AutomationJob -ConfigName '$($Config.Name)'" -ForegroundColor White
            
            Write-Host "  3. Schedule it: " -ForegroundColor Gray -NoNewline
            Write-Host "New-AutomationSchedule -ConfigName '$($Config.Name)'" -ForegroundColor White
        }
        'Module' {
            Write-Host "  1. Apply configuration: " -ForegroundColor Gray -NoNewline
            Write-Host "Set-AutomationConfig -Name '$($Config.Name)'" -ForegroundColor White
            
            Write-Host "  2. Verify settings: " -ForegroundColor Gray -NoNewline
            Write-Host "Get-AutomationConfig -Name '$($Config.Name)'" -ForegroundColor White
        }
    }
    
    Write-Host "`n  💡 Tip: " -ForegroundColor Magenta -NoNewline
    Write-Host "Use 'Get-AutomationHelp $($Config.Type)' for more information!" -ForegroundColor White
}

# Helper functions for nested property access
function Get-NestedProperty {
    param($Object, [string]$Path)
    
    $parts = $Path -split '\.'
    $current = $Object
    
    foreach ($part in $parts) {
        if ($part -match '^\[(\d+)\]$') {
            $index = [int]$Matches[1]
            $current = $current[$index]
        }
        else {
            $current = $current[$part]
        }
    }
    
    return $current
}

function Set-NestedProperty {
    param($Object, [string]$Path, $Value)
    
    $parts = $Path -split '\.'
    $current = $Object
    
    for ($i = 0; $i -lt $parts.Count - 1; $i++) {
        $part = $parts[$i]
        
        if ($part -match '^\[(\d+)\]$') {
            $index = [int]$Matches[1]
            $current = $current[$index]
        }
        else {
            $current = $current[$part]
        }
    }
    
    $lastPart = $parts[-1]
    if ($lastPart -match '^\[(\d+)\]$') {
        $index = [int]$Matches[1]
        $current[$index] = $Value
    }
    else {
        $current[$lastPart] = $Value
    }
}

Export-ModuleMember -Function New-AutomationConfig -Alias autoconfig