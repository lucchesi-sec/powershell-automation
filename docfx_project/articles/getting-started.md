---
uid: articles.getting-started
---
# Getting Started

This guide will walk you through the process of setting up the `powershell-automation` project on your local machine.

## Prerequisites

Before you begin, ensure you have the following installed:

-   **PowerShell 5.1 or later**: This is the minimum required version of PowerShell. You can check your version by running `$PSVersionTable.PSVersion`.
-   **Active Directory Module**: If you plan to use any of the Active Directory-related scripts, you will need the `ActiveDirectory` module for PowerShell. This is typically installed as part of the Remote Server Administration Tools (RSAT).

## Installation

1.  **Clone the Repository**

    Open a terminal and clone the repository to your local machine:

    ```sh
    git clone https://github.com/lucchesi-sec/powershell-automation.git
    ```

2.  **Navigate to the Project Directory**

    Change your current directory to the newly cloned repository:

    ```sh
    cd powershell-automation
    ```

3.  **Import the Core Module**

    The `PSAdminCore` module is the heart of this project. To use its functions, you need to import it into your PowerShell session. From the root of the project directory, run the following command:

    ```powershell
    Import-Module ./modules/PSAdminCore/PSAdminCore.psm1
    ```

    You can add the `-Verbose` flag to see the functions being imported.

## Running Scripts

Once the `PSAdminCore` module is imported, you can run any of the scripts located in the `scripts` directory.

For example, to run the `Clear-DiskSpace.ps1` script, you would navigate to the `scripts/maintenance` directory and execute it:

```powershell
cd scripts/maintenance
./Clear-DiskSpace.ps1 -WhatIf
```

> **Note**
> Many scripts require administrative privileges to run. Ensure you are running PowerShell as an administrator for full functionality. The `Test-AdminPrivileges` function is used in many scripts to enforce this.