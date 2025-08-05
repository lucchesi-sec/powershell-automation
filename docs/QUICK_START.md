# Quick-Start: Your First Automation in 30 Minutes

Welcome to the PowerShell Automation Platform! This guide will walk you through a minimal, secure deployment to get your first automation running in under 30 minutes.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Step 1: Clone the Repository](#step-1-clone-the-repository)
- [Step 2: Configure Your Environment](#step-2-configure-your-environment)
- [Step 3: Run Your First Health Check](#step-3-run-your-first-health-check)
- [Next Steps](#next-steps)

## Prerequisites

Before you begin, ensure you have the following:
- **Windows Server 2019+** or **Windows 10/11 Pro+**
- **PowerShell 7.0+** recommended.
- **Git** installed.
- **Local Administrator** privileges on the machine.

## Step 1: Clone the Repository

Open a PowerShell terminal and clone the project repository from GitHub:

```powershell
git clone https://github.com/lucchesi-sec/powershell-automation.git
cd powershell-automation
```

You now have a local copy of the platform.

## Step 2: Configure Your Environment

For this quick-start, we will configure email notifications to send a report.

1.  **Navigate to the `config` directory:**
    ```powershell
    cd config
    ```

2.  **Create the Email Configuration:**
    Create a file named `email.json` and add the following content, replacing the placeholder values with your actual SMTP server details.

    ```json
    {
        "From": "automation@your-domain.com",
        "SmtpServer": "smtp.your-domain.com",
        "Port": 587,
        "UseSsl": true,
        "Credential": true,
        "Recipients": {
            "Administrators": ["your-email@your-domain.com"]
        }
    }
    ```
    *Note: For this quick-start, you will be prompted for credentials when the script runs.*

## Step 3: Run Your First Health Check

Now, let's run a simple script to monitor critical services and get a report.

1.  **Navigate to the `scripts/maintenance` directory:**
    ```powershell
    cd ../scripts/maintenance
    ```

2.  **Execute the `Monitor-CriticalServices.ps1` script:**
    This script will check for standard services like `WinRM` and `Spooler`.

    ```powershell
    ./Monitor-CriticalServices.ps1 -Services "WinRM", "Spooler" -SendEmail
    ```

3.  **Check Your Inbox:**
    You should receive an email report shortly with the status of the monitored services.

**Congratulations!** You have successfully deployed and run your first automation task with the platform.

## Next Steps

You are now ready to explore more advanced capabilities. Here are some suggestions:

-   Dive into the **[Deployment Guide](./DEPLOYMENT_GUIDE.md)** for a full production setup.
-   Explore the **[Module Guide](./MODULE_GUIDE.md)** to understand the available functions.
-   Try a more advanced script, like `scripts/administration/Get-ADUserActivityReport.ps1` if you are in a domain environment.
