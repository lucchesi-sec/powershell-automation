# PowerShell CI/CD Pipeline Documentation

## Overview

This directory contains the GitHub Actions workflows for the PowerShell Automation Toolkit project. The primary workflow (`powershell-ci.yml`) provides automated code quality checks using PSScriptAnalyzer for all PowerShell modules in the repository.

## Workflow: PowerShell CI Pipeline

### Trigger Events

The pipeline automatically runs on:
- **Push to main/master branch**: Every commit pushed to the default branch
- **Manual dispatch**: Can be triggered manually from the Actions tab in GitHub

### Pipeline Features

1. **Automated Code Analysis**: Runs PSScriptAnalyzer on all `.psm1` files
2. **GitHub Annotations**: Inline error/warning annotations in pull requests
3. **Status Badge**: Automatic README badge showing pipeline status
4. **Detailed Reporting**: Comprehensive analysis reports with actionable feedback
5. **Developer Notifications**: Automatic notifications to commit authors on failures

### Pipeline Steps

1. **Environment Setup**
   - Checks out repository code
   - Sets up PowerShell 7+ environment on Ubuntu
   - Displays environment information

2. **PSScriptAnalyzer Installation**
   - Uses project's installation script if available
   - Falls back to PowerShell Gallery installation
   - Verifies successful installation

3. **Module Discovery**
   - Recursively finds all `.psm1` files
   - Excludes test directories
   - Reports discovered modules

4. **Code Analysis**
   - Runs PSScriptAnalyzer on each module
   - Creates GitHub annotations for issues
   - Generates detailed console output

5. **Report Generation**
   - Creates markdown analysis report
   - Includes summary statistics
   - Provides actionable next steps

6. **Status Badge Update**
   - Automatically updates README.md
   - Shows real-time pipeline status

### Configuration

#### Timeout Settings
- Default timeout: 10 minutes per job
- Configurable in workflow file

#### Environment Variables
```yaml
POWERSHELL_TELEMETRY_OPTOUT: 1
DOTNET_CLI_TELEMETRY_OPTOUT: 1
```

### Local Testing

Use the provided `test-local.ps1` script to run the same checks locally:

```powershell
# Run full validation
./.github/workflows/test-local.ps1

# Skip module installation if already installed
./.github/workflows/test-local.ps1 -SkipInstall

# Show only errors (hide warnings)
./.github/workflows/test-local.ps1 -ShowOnlyErrors
```

## PSScriptAnalyzer Rules

The pipeline uses the default PSScriptAnalyzer ruleset, which includes:

### Error-Level Rules
- **PSAvoidUsingCmdletAliases**: Avoid aliases for better readability
- **PSAvoidUsingPositionalParameters**: Use named parameters
- **PSAvoidUsingInvokeExpression**: Security risk
- **PSAvoidUsingPlainTextForPassword**: Security risk
- **PSAvoidUsingConvertToSecureStringWithPlainText**: Security risk

### Warning-Level Rules
- **PSAvoidGlobalVars**: Avoid global variables
- **PSAvoidUsingWriteHost**: Use Write-Output for pipeline compatibility
- **PSUseShouldProcessForStateChangingFunctions**: Implement WhatIf/Confirm
- **PSUseDeclaredVarsMoreThanAssignments**: Avoid unused variables

### Information-Level Rules
- **PSProvideCommentHelp**: Include comment-based help
- **PSUseSingularNouns**: Follow PowerShell naming conventions

## Troubleshooting

### Common Issues

1. **PSScriptAnalyzer Installation Fails**
   - Check network connectivity
   - Verify PowerShell Gallery is accessible
   - Try manual installation: `Install-Module PSScriptAnalyzer`

2. **No Modules Found**
   - Ensure `.psm1` files exist in repository
   - Check file extensions (must be `.psm1`, not `.ps1`)
   - Verify files aren't in excluded directories

3. **Pipeline Timeout**
   - Large repositories may need increased timeout
   - Adjust in workflow file: `timeout-minutes: 20`

4. **Permission Issues**
   - Ensure GITHUB_TOKEN has write permissions
   - Check branch protection rules

### Getting Help

1. Check workflow run logs in GitHub Actions tab
2. Run local test script for debugging
3. Review PSScriptAnalyzer documentation
4. Open an issue in the repository

## Best Practices

1. **Run Local Tests First**: Use `test-local.ps1` before pushing
2. **Fix Errors Immediately**: Don't ignore pipeline failures
3. **Address Warnings**: Improve code quality over time
4. **Keep Modules Small**: Easier to analyze and maintain
5. **Use Suppression Sparingly**: Only suppress rules with good reason

## Future Enhancements

Potential improvements for future iterations:

1. **Pester Integration**: Add unit testing framework
2. **Code Coverage**: Measure test coverage
3. **Custom Rules**: Project-specific PSScriptAnalyzer rules
4. **Performance Metrics**: Module load time analysis
5. **Security Scanning**: Additional security-focused analysis
6. **Pull Request Analysis**: Run on PRs before merge
7. **Module Publishing**: Automated PowerShell Gallery publishing

## Contributing

To modify the CI/CD pipeline:

1. Edit `.github/workflows/powershell-ci.yml`
2. Test changes using act or push to a feature branch
3. Ensure changes maintain backward compatibility
4. Update this documentation
5. Submit pull request with clear description

## Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [PSScriptAnalyzer Documentation](https://github.com/PowerShell/PSScriptAnalyzer)
- [PowerShell Best Practices](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/strongly-encouraged-development-guidelines)