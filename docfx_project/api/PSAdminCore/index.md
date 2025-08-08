---
uid: api.psadmincore
---
# PSAdminCore Module

The `PSAdminCore` module is the foundational component of the `powershell-automation` project. It provides a set of essential functions that are used by the operational scripts to perform common administrative tasks.

## Core Functions

The module exports the following functions:

-   **[Get-AdminConfig](xref:api.psadmincore.get-adminconfig)**: Retrieves configuration values from JSON files
-   **[Set-AdminConfig](xref:api.psadmincore.set-adminconfig)**: Sets configuration values in JSON files
-   **[Initialize-AdminEnvironment](xref:api.psadmincore.initialize-adminenvironment)**: Sets up the automation environment
-   **[Test-AdminConnectivity](xref:api.psadmincore.test-adminconnectivity)**: Tests connectivity to required services
-   **[Get-AdminCredential](xref:api.psadmincore.get-admincredential)**: Securely manages credentials
-   **[Test-AdminParameter](xref:api.psadmincore.test-adminparameter)**: Validates parameters using common patterns
-   **[Test-AdminPrivileges](xref:api.psadmincore.test-adminprivileges)**: Checks for administrative privileges
-   **[Write-AdminLog](xref:api.psadmincore.write-adminlog)**: Writes to a standardized log file
-   **[Send-AdminNotification](xref:api.psadmincore.send-adminnotification)**: Sends email notifications
-   **[New-AdminReport](xref:api.psadmincore.new-adminreport)**: Creates administrative reports

## Security Functions

Additional security and utility functions:
-   **SecretManagement**: Secure credential storage and retrieval
-   **Security**: Security-related utility functions

Use the navigation on the left to explore the detailed documentation for each function.