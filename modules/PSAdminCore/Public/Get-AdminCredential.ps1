function Get-AdminCredential {
    <#
    .SYNOPSIS
        Retrieves stored credentials securely.
    .DESCRIPTION
        Retrieves credentials from Windows Credential Manager, PowerShell SecretManagement,
        or prompts for credentials if not found. Provides a secure way to handle credentials
        without hardcoding them in scripts.
    .PARAMETER Name
        The name/identifier of the credential to retrieve.
    .PARAMETER Target
        The target system or service for the credential (used for Credential Manager).
    .PARAMETER Force
        Forces a prompt for credentials even if stored credentials exist.
    .PARAMETER StoreCredential
        If specified, stores the entered credentials for future use.
    .PARAMETER Scope
        Scope for credential storage: CurrentUser or LocalMachine (requires admin).
    .EXAMPLE
        $cred = Get-AdminCredential -Name "ServiceAccount"
        Retrieves stored credentials for ServiceAccount.
    .EXAMPLE
        $cred = Get-AdminCredential -Name "SqlServer" -Force -StoreCredential
        Prompts for new credentials and stores them.
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCredential])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [string]$Target,

        [Parameter(Mandatory = $false)]
        [switch]$Force,

        [Parameter(Mandatory = $false)]
        [switch]$StoreCredential,

        [Parameter(Mandatory = $false)]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [string]$Scope = 'CurrentUser'
    )

    try {
        # Build credential identifier
        $credentialId = if ($Target) { "$Name@$Target" } else { $Name }
        
        Write-AdminLog -Message "Retrieving credential: $credentialId" -Level Debug

        # Try to retrieve existing credential unless Force is specified
        if (-not $Force) {
            # Method 1: Try PowerShell SecretManagement if available
            $secretModule = Get-Module -ListAvailable -Name Microsoft.PowerShell.SecretManagement
            if ($secretModule) {
                try {
                    Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction SilentlyContinue
                    $existingCred = Get-Secret -Name $credentialId -AsPlainText:$false -ErrorAction SilentlyContinue
                    if ($existingCred) {
                        Write-AdminLog -Message "Retrieved credential from SecretManagement vault" -Level Debug
                        return $existingCred
                    }
                }
                catch {
                    Write-AdminLog -Message "SecretManagement lookup failed: $_" -Level Debug
                }
            }

            # Method 2: Try Windows Credential Manager (Windows only)
            if ($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows) {
                try {
                    # Use CredentialManager module if available
                    $credManModule = Get-Module -ListAvailable -Name CredentialManager
                    if ($credManModule) {
                        Import-Module CredentialManager -ErrorAction SilentlyContinue
                        $storedCred = Get-StoredCredential -Target $credentialId -ErrorAction SilentlyContinue
                        if ($storedCred) {
                            Write-AdminLog -Message "Retrieved credential from Windows Credential Manager" -Level Debug
                            return $storedCred
                        }
                    }
                    
                    # Fallback to cmdkey check
                    $cmdkeyOutput = cmdkey /list 2>$null | Select-String $credentialId
                    if ($cmdkeyOutput) {
                        Write-AdminLog -Message "Credential exists in Windows Credential Manager but cannot retrieve automatically" -Level Warning
                    }
                }
                catch {
                    Write-AdminLog -Message "Credential Manager lookup failed: $_" -Level Debug
                }
            }

            # Method 3: Check for cached credential in module scope
            if ($script:CredentialCache -and $script:CredentialCache.ContainsKey($credentialId)) {
                $cachedCred = $script:CredentialCache[$credentialId]
                if ($cachedCred) {
                    Write-AdminLog -Message "Retrieved credential from session cache" -Level Debug
                    return $cachedCred
                }
            }
        }

        # Prompt for credentials
        $promptMessage = if ($Target) {
            "Enter credentials for $Name on $Target"
        } else {
            "Enter credentials for $Name"
        }

        $credential = Get-Credential -Message $promptMessage -UserName $Name

        if (-not $credential) {
            throw "No credentials provided"
        }

        # Store credential if requested
        if ($StoreCredential) {
            # Try to store using SecretManagement
            if ($secretModule) {
                try {
                    Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction SilentlyContinue
                    
                    # Check if a vault exists, create default if not
                    $vaults = Get-SecretVault -ErrorAction SilentlyContinue
                    if (-not $vaults) {
                        Register-SecretVault -Name 'PSAdminVault' -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
                    }
                    
                    Set-Secret -Name $credentialId -Secret $credential -ErrorAction Stop
                    Write-AdminLog -Message "Credential stored in SecretManagement vault" -Level Success
                }
                catch {
                    Write-AdminLog -Message "Failed to store in SecretManagement: $_" -Level Warning
                }
            }
            
            # For Windows, try to store in Credential Manager
            if (($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows) -and $credManModule) {
                try {
                    Import-Module CredentialManager -ErrorAction SilentlyContinue
                    New-StoredCredential -Target $credentialId -Credentials $credential -Persist $Scope -ErrorAction Stop
                    Write-AdminLog -Message "Credential stored in Windows Credential Manager" -Level Success
                }
                catch {
                    Write-AdminLog -Message "Failed to store in Credential Manager: $_" -Level Warning
                }
            }
        }

        # Cache credential in session
        if (-not $script:CredentialCache) {
            $script:CredentialCache = @{}
        }
        $script:CredentialCache[$credentialId] = $credential

        return $credential
    }
    catch {
        Write-AdminLog -Message "Failed to retrieve credential '$Name': $_" -Level Error
        throw
    }
}