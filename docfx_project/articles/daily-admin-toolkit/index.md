# Daily Admin Toolkit

## Overview

The Daily Admin Toolkit is a comprehensive PowerShell module collection designed to streamline common system administration tasks. Built with a modular architecture, it provides sys admins with reliable, tested functions for the most frequent daily operations.

## Why Daily Admin Toolkit?

System administrators spend significant time on repetitive tasks. The Daily Admin Toolkit eliminates the need to write custom scripts by providing:

- **Pre-built, tested functions** for common admin tasks
- **Modular design** allowing independent module management
- **Pipeline-friendly** functions that integrate seamlessly
- **Production-ready** with proper error handling and security
- **Consistent interface** following PowerShell best practices

## Core Modules

### ActiveDirectory Module
Manage user accounts, passwords, and group memberships with production-grade security.

**Key Functions:**
- `Unlock-ADAccount` - Unlock user accounts quickly
- `Reset-ADUserPassword` - Secure password reset operations
- `Get-ADUserLastLogon` - Track user activity across domain controllers
- `Get-ADUserMembership` - Analyze group memberships efficiently

### ServerManagement Module
Monitor and maintain server infrastructure with comprehensive health checks.

**Key Functions:**
- `Get-ServerHealth` - Complete server health assessment
- `Test-ServerConnectivity` - Network connectivity validation
- `Get-ServiceStatus` - Service monitoring across multiple servers

### ServiceManagement Module
Manage Windows services and processes remotely with safety controls.

**Key Functions:**
- `Restart-RemoteService` - Safe service restart operations
- `Get-ProcessByName` - Process discovery and monitoring
- `Stop-ProcessRemotely` - Controlled process termination

## Getting Started

### Prerequisites

Before using the Daily Admin Toolkit, ensure you have:

1. **PowerShell 5.1 or later** (PowerShell 7.x recommended)
2. **RSAT Tools** (Remote Server Administration Tools)
3. **Appropriate permissions** for target systems
4. **Network connectivity** to managed servers

### Quick Installation

```powershell
# Import the Daily Admin Toolkit modules
Import-Module ProjectName.ActiveDirectory
Import-Module ProjectName.ServerManagement
Import-Module ProjectName.ServiceManagement

# Verify installation
Get-Module ProjectName.*
```

## Documentation Structure

This documentation follows a task-based "recipes" approach:

### 📚 Recipes
Step-by-step guides for common admin scenarios:
- [ActiveDirectory Recipes](recipes/activedirectory-recipes.md) - User and group management tasks
- [ServerManagement Recipes](recipes/servermanagement-recipes.md) - Health monitoring and maintenance
- [ServiceManagement Recipes](recipes/servicemanagement-recipes.md) - Service and process management

### ⚡ Quick Reference
Fast lookup guides for experienced admins:
- [Command Reference](quick-reference/command-reference.md) - All functions with syntax
- [Parameter Guide](quick-reference/parameter-guide.md) - Common parameters and usage
- [Error Codes](quick-reference/error-codes.md) - Troubleshooting reference

### 🔧 Setup & Configuration
- [Prerequisites](setup/prerequisites.md) - Installation requirements
- [Configuration](setup/configuration.md) - Initial setup and customization
- [Security](setup/security.md) - Security best practices

## Real-World Scenarios

The Daily Admin Toolkit addresses these common scenarios:

### Morning Health Checks
```powershell
# Quick server health assessment
Get-ServerHealth -ComputerName @('SERVER01', 'SERVER02', 'SERVER03') | 
    Where-Object { $_.Status -ne 'Healthy' } |
    Format-Table ComputerName, Status, Issues -AutoSize
```

### User Account Management
```powershell
# Unlock user account and check last logon
Unlock-ADAccount -Identity 'jdoe'
Get-ADUserLastLogon -Identity 'jdoe' -AllDomainControllers
```

### Service Monitoring
```powershell
# Check critical services across multiple servers
Get-ServiceStatus -ComputerName @('WEB01', 'WEB02') -ServiceName @('IIS', 'W3SVC') |
    Where-Object { $_.Status -ne 'Running' }
```

## Integration with Production Features

The Daily Admin Toolkit is designed as a gateway to production PowerShell adoption:

- **Logging Integration** - Works with existing logging frameworks
- **Monitoring Hooks** - Integrates with SCOM, Nagios, and other monitoring systems
- **Reporting** - Export functions for dashboard integration
- **Automation** - Ready for task scheduler and orchestration platforms

## Quality Assurance

Every function in the Daily Admin Toolkit includes:

- **Pester Testing** - Comprehensive unit and integration tests
- **Parameter Validation** - Input validation and type checking
- **Error Handling** - Graceful error handling with detailed messages
- **Security Review** - Secure credential handling and execution policies
- **Performance Testing** - Benchmarked for production environments

## Support and Community

- **Issue Tracking** - Report bugs and request features
- **Community Recipes** - Share your custom admin recipes
- **Training Resources** - Video tutorials and documentation
- **Professional Support** - Professional support options available

## Next Steps

1. **Review Prerequisites** - Ensure your environment is ready
2. **Explore Recipes** - Start with common scenarios in your environment
3. **Practice Safety** - Use `-WhatIf` parameters in production
4. **Customize** - Adapt functions to your organizational needs
5. **Contribute** - Share recipes and improvements with the community

---

> **Pro Tip**: Start with the [ActiveDirectory Recipes](recipes/activedirectory-recipes.md) if you're new to the toolkit. These are the most commonly used functions and provide a great introduction to the toolkit's capabilities.