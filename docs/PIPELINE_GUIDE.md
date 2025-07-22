# PowerShell CI/CD Pipeline Guide

## Overview

The PowerShell Automation Toolkit uses GitHub Actions for continuous integration (CI) to ensure code quality and consistency across all PowerShell modules and scripts. This guide provides comprehensive documentation for understanding, configuring, and troubleshooting the CI/CD pipeline.

## Table of Contents

- [Pipeline Architecture](#pipeline-architecture)
- [Workflow Configuration](#workflow-configuration)
- [PSScriptAnalyzer Integration](#psscriptanalyzer-integration)
- [Customization Options](#customization-options)
- [Troubleshooting](#troubleshooting)
- [Pipeline Examples](#pipeline-examples)
- [Best Practices](#best-practices)

## Pipeline Architecture

### Overview

The CI/CD pipeline is designed to automatically validate PowerShell code quality on every push to the main branch. It consists of:

1. **GitHub Actions Workflow** - Orchestrates the CI process
2. **PSScriptAnalyzer** - Performs static code analysis
3. **Pipeline Scripts** - Modular PowerShell scripts for specific tasks
4. **Notification System** - Alerts developers of failures via GitHub

### Components

```
.github/
└── workflows/
    ├── powershell-ci.yml      # Main CI workflow
    └── test-pipeline.yml      # Pipeline validation tests

scripts/
└── pipeline/
    ├── Install-PSScriptAnalyzer.ps1    # Installs analyzer
    ├── Invoke-CodeAnalysis.ps1         # Runs analysis
    └── Format-AnalysisReport.ps1       # Formats output
```

### Workflow Triggers

The pipeline automatically runs when:
- Code is pushed to the `main` or `master` branch
- Manually triggered via GitHub Actions UI
- Called by other workflows (future enhancement)

## Workflow Configuration

### Basic Configuration

The main workflow file (`.github/workflows/powershell-ci.yml`) defines:

```yaml
name: PowerShell CI Pipeline

on:
  push:
    branches:
      - main
      - master
  workflow_dispatch:  # Allow manual triggers

jobs:
  analyze:
    runs-on: ubuntu-latest
    timeout-minutes: 10
```

### Environment Setup

The pipeline uses:
- **Runner**: Ubuntu-latest (cost-effective and reliable)
- **PowerShell Version**: 7+ (cross-platform compatible)
- **PSScriptAnalyzer**: Latest version from PowerShell Gallery

### Job Steps

1. **Checkout Repository** - Fetches code from GitHub
2. **Setup PowerShell** - Ensures PowerShell 7+ is available
3. **Install Dependencies** - Installs PSScriptAnalyzer
4. **Run Analysis** - Scans all `.psm1` files
5. **Format Results** - Converts output to GitHub annotations
6. **Report Status** - Updates commit status and notifies

## PSScriptAnalyzer Integration

### Installation

PSScriptAnalyzer is installed using the `Install-PSScriptAnalyzer.ps1` script:

```powershell
# Example installation
Install-Module -Name PSScriptAnalyzer -Force -Scope CurrentUser
```

### Analysis Scope

The analyzer scans:
- All PowerShell module files (`*.psm1`)
- Recursively through all directories
- Excludes test directories and archived code

### Default Rules

The pipeline uses PSScriptAnalyzer's default ruleset, which includes:

| Rule Category | Description | Example |
|--------------|-------------|---------|
| **Code Quality** | Best practices and style | Use approved verbs |
| **Security** | Potential security issues | Avoid plain text passwords |
| **Performance** | Performance optimizations | Avoid `+=` in loops |
| **Compatibility** | Cross-platform issues | Use `/` not `\` for paths |

### Rule Severity Levels

- **Error** - Pipeline fails, must be fixed
- **Warning** - Displayed but doesn't fail pipeline
- **Information** - Suggestions for improvement

## Customization Options

### Configuring Analysis Rules

To customize PSScriptAnalyzer rules:

1. **Create Settings File**: Add `.psscriptanalyzer.psd1` to repository root
2. **Configure Rules**:
```powershell
@{
    ExcludeRules = @(
        'PSAvoidUsingWriteHost',
        'PSAvoidUsingCmdletAliases'
    )
    IncludeDefaultRules = $true
    Rules = @{
        PSAvoidUsingCmdletAliases = @{
            Enable = $false
        }
    }
}
```

### Modifying Workflow Behavior

Common customizations:

1. **Change Timeout**:
```yaml
timeout-minutes: 15  # Default is 10
```

2. **Add Path Filters**:
```yaml
on:
  push:
    paths:
      - 'scripts/**'
      - 'modules/**'
```

3. **Multiple OS Testing**:
```yaml
strategy:
  matrix:
    os: [ubuntu-latest, windows-latest, macos-latest]
```

### Environment Variables

Available for customization:

| Variable | Description | Default |
|----------|-------------|---------|
| `ANALYSIS_TIMEOUT` | Max time for analysis | 300 seconds |
| `FAIL_ON_WARNING` | Treat warnings as errors | false |
| `EXCLUDE_PATHS` | Paths to skip | tests/,archive/ |

## Troubleshooting

### Common Pipeline Failures

#### 1. PSScriptAnalyzer Installation Fails

**Error**: `Unable to install PSScriptAnalyzer module`

**Causes**:
- PowerShell Gallery connectivity issues
- Insufficient permissions
- Version conflicts

**Solutions**:
```powershell
# Clear module cache
Remove-Module PSScriptAnalyzer -Force -ErrorAction SilentlyContinue

# Install with specific version
Install-Module PSScriptAnalyzer -RequiredVersion 1.21.0 -Force

# Use alternative repository
Register-PSRepository -Name PSGallery -SourceLocation https://www.powershellgallery.com/api/v2
```

#### 2. Module Files Not Found

**Error**: `No PowerShell module files (*.psm1) found in repository`

**Causes**:
- No `.psm1` files in repository
- Incorrect file permissions
- Files in unexpected locations

**Solutions**:
- Verify module files exist: `Get-ChildItem -Recurse -Filter *.psm1`
- Check file extensions are correct (not `.ps1`)
- Ensure files are committed to repository

#### 3. Analysis Timeout

**Error**: `Analysis exceeded timeout limit`

**Causes**:
- Large codebase
- Complex module dependencies
- Performance issues

**Solutions**:
- Increase timeout in workflow: `timeout-minutes: 20`
- Split analysis into smaller jobs
- Optimize module structure

#### 4. GitHub Actions Permissions

**Error**: `Resource not accessible by integration`

**Causes**:
- Insufficient repository permissions
- Branch protection rules
- Token scope limitations

**Solutions**:
- Check workflow permissions in repository settings
- Ensure GITHUB_TOKEN has write access
- Review branch protection rules

### Debugging Pipeline Issues

1. **Enable Debug Logging**:
```yaml
env:
  ACTIONS_STEP_DEBUG: true
```

2. **Add Diagnostic Output**:
```powershell
Write-Host "##[debug]Current directory: $(Get-Location)"
Write-Host "##[debug]Module count: $(Get-ChildItem -Filter *.psm1 -Recurse).Count"
```

3. **Check Runner Environment**:
```yaml
- name: Diagnostic Information
  run: |
    $PSVersionTable
    Get-Module -ListAvailable
    Get-ChildItem -Path . -Recurse -Filter *.psm1
```

## Pipeline Examples

### Successful Pipeline Run

When the pipeline succeeds, you'll see:

```
✅ PowerShell CI Pipeline
   ├─ ✓ Checkout Repository (2s)
   ├─ ✓ Setup PowerShell (5s)
   ├─ ✓ Install PSScriptAnalyzer (12s)
   ├─ ✓ Run Code Analysis (18s)
   ├─ ✓ Format Results (1s)
   └─ ✓ Report Status (1s)

Total time: 39 seconds
Status: Success - All modules pass analysis
```

**Commit Status**: Green checkmark with "All checks have passed"

### Failed Pipeline Run

When analysis finds issues:

```
❌ PowerShell CI Pipeline
   ├─ ✓ Checkout Repository (2s)
   ├─ ✓ Setup PowerShell (5s)
   ├─ ✓ Install PSScriptAnalyzer (12s)
   ├─ ✗ Run Code Analysis (15s)
   │    └─ Found 3 errors, 7 warnings
   ├─ ✓ Format Results (1s)
   └─ ✓ Report Status (1s)

Total time: 36 seconds
Status: Failed - Code analysis found issues
```

**Example Violations**:

```powershell
# ERROR: PSAvoidUsingPlainTextForPassword
$password = "MyPassword123"  # Line 45 in Login-Module.psm1

# WARNING: PSUseSingularNouns
function Get-Users {  # Line 12 in User-Module.psm1
    # Should be Get-User
}

# ERROR: PSAvoidUsingInvokeExpression
Invoke-Expression $userInput  # Line 78 in Process-Module.psm1
```

**GitHub Annotations**: Issues appear inline in the Files Changed tab

### Manual Pipeline Trigger

To manually run the pipeline:

1. Navigate to Actions tab in GitHub
2. Select "PowerShell CI Pipeline"
3. Click "Run workflow"
4. Select branch and click "Run workflow"

## Best Practices

### For Module Development

1. **Run Analysis Locally** before pushing:
```powershell
Install-Module PSScriptAnalyzer -Force
Invoke-ScriptAnalyzer -Path . -Recurse
```

2. **Use Approved Verbs**:
```powershell
# Good
function Get-UserData { }

# Bad
function Fetch-UserData { }
```

3. **Document Functions**:
```powershell
function Get-UserReport {
<#
.SYNOPSIS
    Generates user activity report
.DESCRIPTION
    Creates detailed report of user activities in Active Directory
.PARAMETER StartDate
    Beginning date for report period
#>
    [CmdletBinding()]
    param(
        [DateTime]$StartDate
    )
    # Implementation
}
```

### For Pipeline Maintenance

1. **Version Lock Dependencies** when stable:
```yaml
- name: Install PSScriptAnalyzer
  run: Install-Module PSScriptAnalyzer -RequiredVersion 1.21.0
```

2. **Cache Dependencies** for performance:
```yaml
- uses: actions/cache@v3
  with:
    path: ~/.local/share/powershell/Modules
    key: ${{ runner.os }}-psmodules-${{ hashFiles('**/requirements.psd1') }}
```

3. **Parallel Analysis** for large codebases:
```yaml
strategy:
  matrix:
    module: [UserModule, GroupModule, SecurityModule]
```

### For Team Collaboration

1. **Document Exemptions** when suppressing rules:
```powershell
# Suppressed: Using Write-Host for user-facing CLI tool
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
```

2. **Create Team Standards** in `.psscriptanalyzer.psd1`
3. **Regular Reviews** of pipeline performance and rules

## Additional Resources

- [PSScriptAnalyzer Documentation](https://github.com/PowerShell/PSScriptAnalyzer)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [PowerShell Best Practices](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/strongly-encouraged-development-guidelines)

### Related Documentation

- [Pipeline Validation Checklist](./PIPELINE_VALIDATION_CHECKLIST.md) - Comprehensive validation checklist
- [Pipeline Test Results](./PIPELINE_TEST_RESULTS.md) - Detailed test execution results
- [Test Pipeline Workflow](../.github/workflows/test-pipeline.yml) - Automated test suite

## Support

For pipeline issues:
1. Check this troubleshooting guide
2. Review GitHub Actions logs
3. Consult team DevOps engineer
4. Open issue in repository with `pipeline` label

---

*Last updated: 2025-07-22*
*Pipeline version: 1.0.0*