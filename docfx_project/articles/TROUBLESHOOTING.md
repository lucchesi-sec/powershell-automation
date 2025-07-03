# Troubleshooting & FAQ

This guide is designed to help you resolve common issues and answer frequently asked questions related to the PowerShell Enterprise Automation Platform.

## Table of Contents
- [Frequently Asked Questions (FAQ)](#frequently-asked-questions-faq)
- [Common Issues](#common-issues)
  - [Module Import Failures](#module-import-failures)
  - [Scheduled Task Failures](#scheduled-task-failures)
  - [Network Connectivity Issues](#network-connectivity-issues)
  - [Permission Errors](#permission-errors)

---

## Frequently Asked Questions (FAQ)

**Q: What PowerShell version is required?**
**A:** PowerShell 5.1 is the minimum requirement, but we strongly recommend using PowerShell 7.0+ for the best performance and cross-platform compatibility.

**Q: How are credentials managed securely?**
**A:** The platform is designed to integrate with the Windows Credential Manager for secure storage and retrieval of credentials. Avoid hardcoding credentials in scripts or configuration files. Refer to the `Get-AdminCredential` function in the `PSAdminCore` module.

**Q: Can I run this platform on Linux or macOS?**
**A:** While PowerShell 7+ is cross-platform, this automation platform is designed specifically for Windows environments due to its heavy reliance on Windows-specific features like Active Directory integration, Windows Task Scheduler, and Windows Credential Manager.

---

## Common Issues

### Module Import Failures

**Symptom:** You receive an error message like `The specified module 'PSAdminCore' was not loaded because no valid module file was found in any module directory.`

**Resolution:**
1.  **Check Module Path:** Ensure that the `modules` directory is in your `$env:PSModulePath`. You can check your module path by running:
    ```powershell
    $env:PSModulePath -split ';'
    ```
2.  **Correct Location:** Make sure you have copied the module folders (e.g., `PSAdminCore`, `PSActiveDirectory`) into one of the directories listed in your module path. A common location is `$env:USERPROFILE\Documents\PowerShell\Modules`.
3.  **Force Import:** Try importing the module with its full path to diagnose the issue:
    ```powershell
    Import-Module "C:\Path\To\Your\Project\modules\PSAdminCore\PSAdminCore.psm1" -Force -Verbose
    ```

### Scheduled Task Failures

**Symptom:** A scheduled task fails to run or completes with an error code.

**Resolution:**
1.  **Check Task History:** In the Windows Task Scheduler, right-click the task and select "Properties," then go to the "History" tab to see detailed execution logs.
2.  **Review Event Logs:** Check the Windows Event Viewer under `Application and Services Logs > Microsoft > Windows > TaskScheduler > Operational` for task-related events.
3.  **Execution Policy:** The service account running the task might be blocked by the PowerShell execution policy. Ensure the policy is set appropriately (e.g., `RemoteSigned`).
4.  **Test Manually:** Log in as the service account (or use `Run-As`) and try to execute the script manually from the command line to see more detailed error messages.

### Network Connectivity Issues

**Symptom:** Scripts fail when trying to connect to remote resources like a backup server, cloud storage, or an SMTP server.

**Resolution:**
1.  **Test Connection:** Use the `Test-NetConnection` cmdlet to verify connectivity to the target host and port.
    ```powershell
    # Test connection to a file share
    Test-NetConnection -ComputerName "backup-server" -Port 445

    # Test connection to an SMTP server
    Test-NetConnection -ComputerName "smtp.your-domain.com" -Port 587
    ```
2.  **Firewall Rules:** Ensure that outbound firewall rules exist on the automation server to allow traffic to the required destinations and ports (e.g., TCP 445 for SMB, TCP 587 for SMTP, TCP 443 for HTTPS).

### Permission Errors

**Symptom:** Scripts fail with "Access Denied" or other permission-related errors.

**Resolution:**
1.  **Run as Administrator:** Many automation tasks require elevated privileges. Ensure you are running your PowerShell session as an Administrator.
2.  **Service Account Permissions:** If a scheduled task is failing, verify that the service account running the task has the necessary permissions on the target resources (e.g., Full Control on backup directories, appropriate rights in Active Directory).
3.  **Least Privilege:** While troubleshooting, you might grant broad permissions. However, always follow the principle of least privilege in a production environment. Grant only the specific permissions required for the task.
