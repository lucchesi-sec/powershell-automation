<div align="center">
  <img src="powershell-logo.svg" alt="PowerShell Logo" width="120" height="120">
  
  # PowerShell Automation Toolkit
  
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  [![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
  [![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)](https://www.microsoft.com/windows)
  [![GitHub Pages](https://img.shields.io/badge/docs-GitHub%20Pages-brightgreen.svg)](https://lucchesi-sec.github.io/powershell-automation/)
  [![PowerShell CI](https://github.com/lucchesi-sec/powershell-automation/actions/workflows/powershell-ci.yml/badge.svg)](https://github.com/lucchesi-sec/powershell-automation/actions/workflows/powershell-ci.yml)
  
  [![GitHub last commit](https://img.shields.io/github/last-commit/lucchesi-sec/powershell-automation.svg)](https://github.com/lucchesi-sec/powershell-automation/commits/main)
  [![GitHub issues](https://img.shields.io/github/issues/lucchesi-sec/powershell-automation.svg)](https://github.com/lucchesi-sec/powershell-automation/issues)
  [![GitHub forks](https://img.shields.io/github/forks/lucchesi-sec/powershell-automation.svg)](https://github.com/lucchesi-sec/powershell-automation/network)
  [![GitHub stars](https://img.shields.io/github/stars/lucchesi-sec/powershell-automation.svg)](https://github.com/lucchesi-sec/powershell-automation/stargazers)
  
  **A comprehensive collection of PowerShell modules and scripts for automation**
</div>

## Overview

This repository provides a suite of tools for automating common administrative and maintenance tasks in a Windows environment. The project is built around a core module, `PSAdminCore`, which provides essential functions for logging, notifications, reporting, and credential management.

## 🚀 Current Status

The PSAdminCore module has been fully implemented with comprehensive functionality including:
- ✅ Complete module structure with public/private function organization
- ✅ All core functions implemented (logging, privileges, notifications, etc.)
- ✅ Enhanced security features and credential management
- ✅ Pester unit tests for core functions, with ongoing expansion
- ✅ CI/CD pipeline integration with automated testing
- ✅ All scripts updated to use the new module system

## Features

-   **Core Module (`PSAdminCore`)**: A robust set of foundational functions including:
    - **Logging**: Structured logging with severity levels and automatic rotation
    - **Security**: Credential management, encryption, and compliance checking
    - **Notifications**: Email alerts and report generation
    - **Validation**: Parameter validation and connectivity testing
    - **Configuration**: Secure configuration management with encryption
-   **Administration Scripts**: Scripts for managing Active Directory, backups, and more.
-   **Maintenance Scripts**: Tools for system maintenance, such as disk cleanup and service monitoring.
-   **Security Features**: Built-in encryption, secure credential storage, and compliance validation.
-   **Extensible**: Designed to be easily extended with new scripts and modules.

## Getting Started

### Prerequisites

-   PowerShell 5.1 or later
-   Active Directory module (for AD-related scripts)

### Installation

1.  Clone the repository:
    ```sh
    git clone https://github.com/lucchesi-sec/powershell-automation.git
    ```
2.  Navigate to the repository directory:
    ```sh
    cd powershell-automation
    ```
3.  Import the core module:
    ```powershell
    Import-Module ./modules/PSAdminCore/PSAdminCore.psm1
    ```

## Usage

For detailed information on how to use the modules and scripts, please refer to our full documentation site.

## Documentation

-   **[Full Documentation](https://lucchesi-sec.github.io/powershell-automation/)** - Complete API reference and guides

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
